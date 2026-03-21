use super::helpers::{generate_node_id, parse_canonical_name};
use super::Analyzer;
use crate::types::{
    GlobalEdge, GlobalLineage, GlobalNode, IssueCount, Node, NodeType, ResolvedColumnSchema,
    ResolvedSchemaMetadata, ResolvedSchemaTable, StatementRef, Summary,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
#[cfg(feature = "tracing")]
use tracing::debug;

impl<'a> Analyzer<'a> {
    pub(super) fn build_result(&self) -> crate::AnalyzeResult {
        // Apply CTE filtering if requested
        let hide_ctes = self
            .request
            .options
            .as_ref()
            .and_then(|o| o.hide_ctes)
            .unwrap_or(false);

        let statements = if hide_ctes {
            let mut filtered = self.statement_lineages.clone();
            for lineage in &mut filtered {
                super::transform::filter_cte_nodes(lineage);
            }
            filtered
        } else {
            self.statement_lineages.clone()
        };

        let global_lineage = self.build_global_lineage_from(&statements);
        let summary = self.build_summary(&global_lineage);
        let resolved_schema = self.build_resolved_schema();

        crate::AnalyzeResult {
            statements,
            global_lineage,
            issues: self.issues.clone(),
            summary,
            resolved_schema,
        }
    }

    fn build_resolved_schema(&self) -> Option<ResolvedSchemaMetadata> {
        if self.schema.is_empty() {
            return None;
        }

        let mut tables: Vec<ResolvedSchemaTable> = self
            .schema
            .all_entries()
            .map(|entry| {
                let columns: Vec<ResolvedColumnSchema> = entry
                    .table
                    .columns
                    .iter()
                    .map(|col| ResolvedColumnSchema {
                        name: col.name.clone(),
                        data_type: col.data_type.clone(),
                        origin: Some(entry.origin),
                        is_primary_key: col.is_primary_key,
                        foreign_key: col.foreign_key.clone(),
                    })
                    .collect();

                ResolvedSchemaTable {
                    catalog: entry.table.catalog.clone(),
                    schema: entry.table.schema.clone(),
                    name: entry.table.name.clone(),
                    columns,
                    origin: entry.origin,
                    source_statement_index: entry.source_statement_idx,
                    updated_at: entry.updated_at.to_rfc3339(),
                    temporary: if entry.temporary { Some(true) } else { None },
                    constraints: entry.constraints.clone(),
                }
            })
            .collect();

        // Sort by name for consistent output
        tables.sort_by(|a, b| a.name.cmp(&b.name));

        Some(ResolvedSchemaMetadata { tables })
    }

    fn build_global_lineage_from(
        &self,
        statements: &[crate::types::StatementLineage],
    ) -> GlobalLineage {
        let mut global_nodes: HashMap<Arc<str>, GlobalNode> = HashMap::new();
        let mut global_edges: Vec<GlobalEdge> = Vec::new();
        let mut local_to_global_id: HashMap<Arc<str>, Arc<str>> = HashMap::new();
        let mut seen_global_edges: HashSet<(Arc<str>, Arc<str>, &'static str)> = HashSet::new();

        // Collect all nodes from all statements.
        // For table-like nodes, merge by qualified_name (canonical) so that
        // self-join instances (same canonical, different node IDs) collapse
        // into a single global node.
        for lineage in statements {
            for node in &lineage.nodes {
                let canonical = node.qualified_name.clone().unwrap_or(node.label.clone());
                let canonical_name = parse_canonical_name(&canonical);

                let global_id = self.global_node_id(node, &canonical);
                local_to_global_id.insert(node.id.clone(), global_id.clone());

                global_nodes
                    .entry(global_id.clone())
                    .and_modify(|existing| {
                        existing.statement_refs.push(StatementRef {
                            statement_index: lineage.statement_index,
                            node_id: Some(node.id.clone()),
                        });
                    })
                    .or_insert_with(|| GlobalNode {
                        id: global_id,
                        node_type: node.node_type,
                        label: node.label.clone(),
                        canonical_name,
                        statement_refs: vec![StatementRef {
                            statement_index: lineage.statement_index,
                            node_id: Some(node.id.clone()),
                        }],
                        metadata: None,
                        resolution_source: node.resolution_source,
                    });
            }

            // Collect edges, remapping local node IDs to their global equivalents.
            // If a local ID is missing from the mapping (e.g., the node was pruned
            // during ambiguous column resolution, or belongs to a table function with
            // dialect-provided columns), the original local ID is used as fallback.
            // The post-build validation step below removes any resulting orphaned edges.
            for edge in &lineage.edges {
                let from = local_to_global_id
                    .get(&edge.from)
                    .cloned()
                    .unwrap_or_else(|| {
                        #[cfg(feature = "tracing")]
                        debug!(
                            edge_id = %edge.id,
                            node_id = %edge.from,
                            "global edge source not in local-to-global mapping, using local ID"
                        );
                        edge.from.clone()
                    });
                let to = local_to_global_id
                    .get(&edge.to)
                    .cloned()
                    .unwrap_or_else(|| {
                        #[cfg(feature = "tracing")]
                        debug!(
                            edge_id = %edge.id,
                            node_id = %edge.to,
                            "global edge target not in local-to-global mapping, using local ID"
                        );
                        edge.to.clone()
                    });

                if seen_global_edges.insert((
                    from.clone(),
                    to.clone(),
                    Self::global_edge_kind(edge.edge_type),
                )) {
                    global_edges.push(GlobalEdge {
                        id: edge.id.clone(),
                        from,
                        to,
                        edge_type: edge.edge_type,
                        producer_statement: Some(StatementRef {
                            statement_index: lineage.statement_index,
                            node_id: None,
                        }),
                        consumer_statement: None,
                        metadata: None,
                    });
                }
            }
        }

        // Detect cross-statement edges using the tracker
        global_edges.extend(self.tracker.build_cross_statement_edges());

        let nodes: Vec<GlobalNode> = global_nodes.into_values().collect();

        // Remove edges that reference nodes not present in the global graph.
        // This can happen when statement-level analysis removes a node (e.g.,
        // ambiguous column pruning) without cleaning up all referencing edges.
        let global_node_ids: HashSet<&Arc<str>> = nodes.iter().map(|n| &n.id).collect();

        #[cfg(feature = "tracing")]
        let edges_before = global_edges.len();

        global_edges.retain(|edge| {
            global_node_ids.contains(&edge.from) && global_node_ids.contains(&edge.to)
        });

        #[cfg(feature = "tracing")]
        if global_edges.len() < edges_before {
            debug!(
                removed = edges_before - global_edges.len(),
                "removed orphaned edges from global lineage"
            );
        }

        GlobalLineage {
            nodes,
            edges: global_edges,
        }
    }

    fn global_edge_kind(edge_type: crate::types::EdgeType) -> &'static str {
        match edge_type {
            crate::types::EdgeType::Ownership => "ownership",
            crate::types::EdgeType::DataFlow => "data_flow",
            crate::types::EdgeType::Derivation => "derivation",
            crate::types::EdgeType::JoinDependency => "join_dependency",
            crate::types::EdgeType::CrossStatement => "cross_statement",
        }
    }

    fn global_node_id(&self, node: &Node, canonical: &Arc<str>) -> Arc<str> {
        match node.node_type {
            NodeType::Table | NodeType::View => self.tracker.relation_identity(canonical).0,
            NodeType::Cte => {
                let definition_id = generate_node_id("cte", canonical);
                if node.id == definition_id {
                    definition_id
                } else {
                    node.id.clone()
                }
            }
            NodeType::Column if node.qualified_name.is_some() => {
                generate_node_id("column", canonical)
            }
            _ => node.id.clone(),
        }
    }

    pub(super) fn build_summary(&self, global_lineage: &GlobalLineage) -> Summary {
        let error_count = self
            .issues
            .iter()
            .filter(|i| i.severity == crate::Severity::Error)
            .count();
        let warning_count = self
            .issues
            .iter()
            .filter(|i| i.severity == crate::Severity::Warning)
            .count();
        let info_count = self
            .issues
            .iter()
            .filter(|i| i.severity == crate::Severity::Info)
            .count();

        let table_count = global_lineage
            .nodes
            .iter()
            .filter(|n| n.node_type.is_table_or_view())
            .count();

        let cte_count = global_lineage
            .nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Cte)
            .count();

        let column_count = global_lineage
            .nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Column)
            .count();

        // Aggregate join count from all statements
        let join_count: usize = self.statement_lineages.iter().map(|s| s.join_count).sum();

        // Calculate project-level complexity from global lineage
        // Uses table/CTE counts since GlobalNode doesn't track per-node join info
        let filter_count: usize = self
            .statement_lineages
            .iter()
            .flat_map(|s| s.nodes.iter())
            .map(|n| n.filters.len())
            .sum();

        let complexity_score =
            calculate_global_complexity(table_count, cte_count, join_count, filter_count);

        Summary {
            statement_count: self.statement_lineages.len(),
            table_count: table_count + cte_count, // Keep combined for backwards compat
            column_count,
            join_count,
            complexity_score,
            issue_count: IssueCount {
                errors: error_count,
                warnings: warning_count,
                infos: info_count,
            },
            has_errors: error_count > 0,
        }
    }
}

/// Calculate complexity score for project-level summary.
///
/// Returns a score from 1-100 based on structural complexity indicators.
/// The weights reflect typical query maintenance and comprehension burden:
/// - Tables (5): Base data sources add moderate complexity
/// - CTEs (8): Higher than tables since they introduce intermediate logic
/// - Joins (10): Highest weight as joins significantly increase query complexity
///   and are common sources of performance issues and logical errors
/// - Filters (2): Low weight since WHERE clauses are straightforward but add
///   some cognitive load when numerous
fn calculate_global_complexity(
    table_count: usize,
    cte_count: usize,
    join_count: usize,
    filter_count: usize,
) -> u8 {
    const TABLE_WEIGHT: usize = 5;
    const CTE_WEIGHT: usize = 8;
    const JOIN_WEIGHT: usize = 10;
    const FILTER_WEIGHT: usize = 2;

    let raw_score = table_count * TABLE_WEIGHT
        + cte_count * CTE_WEIGHT
        + join_count * JOIN_WEIGHT
        + filter_count * FILTER_WEIGHT;

    raw_score.clamp(1, 100) as u8
}
