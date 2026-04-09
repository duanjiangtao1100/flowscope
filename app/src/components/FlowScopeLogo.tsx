interface FlowScopeLogoProps {
  className?: string;
}

/**
 * DataLineageAnalysis water drop logo.
 */
export function FlowScopeLogo({ className }: FlowScopeLogoProps) {
  return (
    <img
      src="/logo.png"
      alt="DataLineageAnalysis logo"
      className={className}
      style={{ width: '32px', height: '32px', objectFit: 'contain' }}
    />
  );
}
