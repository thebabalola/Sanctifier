use crate::rules::{Rule, RuleViolation, Severity};
use syn::visit::Visit;
use syn::{parse_str, File};

pub struct DeprecatedHostFnRule;

impl DeprecatedHostFnRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DeprecatedHostFnRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DeprecatedHostFnRule {
    fn name(&self) -> &str {
        "deprecated_host_fns"
    }

    fn description(&self) -> &str {
        "Detects usage of deprecated Soroban host functions"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match parse_str::<File>(source) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        let mut visitor = DeprecatedVisitor {
            issues: Vec::new(),
        };
        visitor.visit_file(&file);

        visitor.issues
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct DeprecatedVisitor {
    issues: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for DeprecatedVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();
        let suggestion = match method_name.as_str() {
            "get_ledger_version" => Some("env.ledger().version()"),
            "get_ledger_sequence" => Some("env.ledger().sequence()"),
            "get_ledger_timestamp" => Some("env.ledger().timestamp()"),
            "get_current_contract_address" => Some("env.current_contract_address()"),
            _ => None,
        };

        if let Some(sug) = suggestion {
            let line = node.method.span().start().line;
            let message = format!(
                "Method '{}' is deprecated. Use '{}' instead.",
                method_name, sug
            );
            self.issues.push(
                RuleViolation::new(
                    "deprecated_host_fns",
                    Severity::Warning,
                    message,
                    format!("line {}", line),
                )
                .with_suggestion(sug.to_string()),
            );
        }

        // Continue visiting sub-expressions
        syn::visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprecated_ledger_calls() {
        let source = r#"
            #[contractimpl]
            impl MyContract {
                pub fn test_fn(env: Env) {
                    let version = env.get_ledger_version();
                    let seq = env.get_ledger_sequence();
                    let ts = env.get_ledger_timestamp();
                    let addr = env.get_current_contract_address();
                }
            }
        "#;

        let rule = DeprecatedHostFnRule::new();
        let issues = rule.check(source);

        assert_eq!(issues.len(), 4);
        assert!(issues[0].message.contains("get_ledger_version"));
        assert!(issues[1].message.contains("get_ledger_sequence"));
        assert!(issues[2].message.contains("get_ledger_timestamp"));
        assert!(issues[3].message.contains("get_current_contract_address"));
    }

    #[test]
    fn test_no_deprecated_calls() {
        let source = r#"
            #[contractimpl]
            impl MyContract {
                pub fn test_fn(env: Env) {
                    let version = env.ledger().version();
                    let seq = env.ledger().sequence();
                    let ts = env.ledger().timestamp();
                    let addr = env.current_contract_address();
                }
            }
        "#;

        let rule = DeprecatedHostFnRule::new();
        let issues = rule.check(source);

        assert_eq!(issues.len(), 0);
    }
}
