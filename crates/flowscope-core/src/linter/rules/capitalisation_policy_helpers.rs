use std::collections::HashSet;

use crate::linter::config::LintConfig;
use regex::{Regex, RegexBuilder};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapitalisationPolicy {
    Consistent,
    Upper,
    Lower,
    Capitalise,
    Pascal,
    Camel,
    Snake,
}

impl CapitalisationPolicy {
    pub fn from_rule_config(config: &LintConfig, code: &str, key: &str) -> Self {
        config
            .rule_option_str(code, key)
            .map(Self::from_raw_value)
            .unwrap_or(Self::Consistent)
    }

    pub fn from_raw_value(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "upper" | "uppercase" => Self::Upper,
            "lower" | "lowercase" => Self::Lower,
            "capitalise" | "capitalize" => Self::Capitalise,
            "pascal" | "pascalcase" => Self::Pascal,
            "camel" | "camelcase" => Self::Camel,
            "snake" | "snake_case" => Self::Snake,
            _ => Self::Consistent,
        }
    }
}

pub fn tokens_violate_policy(tokens: &[String], policy: CapitalisationPolicy) -> bool {
    match policy {
        CapitalisationPolicy::Consistent => !tokens_match_consistent_policy(tokens),
        _ => tokens
            .iter()
            .any(|token| !token_matches_policy(token, policy)),
    }
}

pub fn ignored_words_from_config(config: &LintConfig, code: &str) -> HashSet<String> {
    if let Some(words) = config.rule_option_string_list(code, "ignore_words") {
        return words
            .into_iter()
            .map(|word| word.trim().to_ascii_uppercase())
            .filter(|word| !word.is_empty())
            .collect();
    }

    if let Some(value) = config
        .rule_config_object(code)
        .and_then(|obj| obj.get("ignore_words"))
    {
        let scalar = match value {
            serde_json::Value::String(raw) => Some(raw.clone()),
            serde_json::Value::Bool(flag) => Some(if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        };

        if let Some(raw) = scalar {
            return raw
                .split(',')
                .map(str::trim)
                .filter(|word| !word.is_empty())
                .map(str::to_ascii_uppercase)
                .collect();
        }
    }

    config
        .rule_option_str(code, "ignore_words")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|word| !word.is_empty())
                .map(str::to_ascii_uppercase)
                .collect()
        })
        .unwrap_or_default()
}

pub fn ignored_words_regex_from_config(config: &LintConfig, code: &str) -> Option<Regex> {
    let raw = config.rule_option_str(code, "ignore_words_regex")?;
    let pattern = raw.trim();
    if pattern.is_empty() {
        return None;
    }

    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .ok()
}

pub fn token_is_ignored(
    token: &str,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> bool {
    if ignore_words.contains(&token.to_ascii_uppercase()) {
        return true;
    }

    ignore_words_regex
        .map(|regex| regex.is_match(token))
        .unwrap_or(false)
}

fn token_matches_policy(token: &str, policy: CapitalisationPolicy) -> bool {
    match policy {
        CapitalisationPolicy::Consistent => true,
        CapitalisationPolicy::Upper => token == token.to_ascii_uppercase(),
        CapitalisationPolicy::Lower => token == token.to_ascii_lowercase(),
        CapitalisationPolicy::Capitalise => {
            let mut seen_alpha = false;
            for ch in token.chars() {
                if !ch.is_ascii_alphabetic() {
                    continue;
                }
                if !seen_alpha {
                    if !ch.is_ascii_uppercase() {
                        return false;
                    }
                    seen_alpha = true;
                } else if !ch.is_ascii_lowercase() {
                    return false;
                }
            }
            seen_alpha
        }
        // For pascal, camel, and snake we match SQLFluff's "fix-based detection":
        // a token matches if applying the fix transformation would be a no-op.
        CapitalisationPolicy::Pascal => token == apply_pascal_transform(token),
        CapitalisationPolicy::Camel => token == apply_camel_transform(token),
        CapitalisationPolicy::Snake => token == apply_snake_transform(token),
    }
}

/// Pascal-case transform: uppercase the first letter of each word at non-alphanumeric boundaries.
pub fn apply_pascal_transform(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_word_start = true;
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() {
            out.push(ch);
            at_word_start = true;
        } else if at_word_start {
            out.push(ch.to_ascii_uppercase());
            at_word_start = false;
        } else {
            out.push(ch);
            at_word_start = false;
        }
    }
    out
}

/// Camel-case transform: lowercase the first letter of each word at non-alphanumeric boundaries.
pub fn apply_camel_transform(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_word_start = true;
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() {
            out.push(ch);
            at_word_start = true;
        } else if at_word_start {
            out.push(ch.to_ascii_lowercase());
            at_word_start = false;
        } else {
            out.push(ch);
            at_word_start = false;
        }
    }
    out
}

/// Snake-case transform: insert underscores at camelCase and letter/digit boundaries, lowercase.
pub fn apply_snake_transform(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    let chars: Vec<char> = value.chars().collect();
    let all_upper = chars
        .iter()
        .filter(|c| c.is_ascii_alphabetic())
        .all(|c| c.is_ascii_uppercase());
    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 {
            let prev = chars[i - 1];
            if !all_upper
                && ch.is_ascii_uppercase()
                && (prev.is_ascii_lowercase() || prev.is_ascii_digit())
            {
                out.push('_');
            }
            if ch.is_ascii_digit() && prev.is_ascii_alphabetic() {
                out.push('_');
            }
            if ch.is_ascii_alphabetic() && prev.is_ascii_digit() {
                out.push('_');
            }
        }
        out.push(ch);
    }
    out.to_ascii_lowercase()
}

fn tokens_match_consistent_policy(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return true;
    }

    const STYLE_UPPER: u8 = 0b001;
    const STYLE_LOWER: u8 = 0b010;
    const STYLE_CAPITALISE: u8 = 0b100;

    let mut possible_styles = STYLE_UPPER | STYLE_LOWER | STYLE_CAPITALISE;
    for token in tokens {
        let mut token_styles = 0u8;
        if token_matches_policy(token, CapitalisationPolicy::Upper) {
            token_styles |= STYLE_UPPER;
        }
        if token_matches_policy(token, CapitalisationPolicy::Lower) {
            token_styles |= STYLE_LOWER;
        }
        if token_matches_policy(token, CapitalisationPolicy::Capitalise) {
            token_styles |= STYLE_CAPITALISE;
        }

        if token_styles == 0 {
            return false;
        }

        possible_styles &= token_styles;
        if possible_styles == 0 {
            return false;
        }
    }

    true
}
