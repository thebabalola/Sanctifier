use syn::visit::{self, Visit};
use syn::{parse_str, Expr, ExprMethodCall, File};
use crate::rules::{Rule, RuleViolation, Severity};

pub struct DeprecatedHostFnRule;

impl DeprecatedHostFnRule {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for DeprecatedHostFnRule {
    fn name(&self) -> &str {
        "deprecated_host_fns"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match parse_str::<File>(source) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        let mut visitor = DeprecatedHostFnVisitor {
            violations: Vec::new(),
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct DeprecatedHostFnVisitor {
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for DeprecatedHostFnVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method_name = i.method.to_string();
        
        // List of deprecated Soroban host functions (v20+)
        let deprecated_methods = [
            ("get_ledger_version", "env.ledger().version()"),
            ("get_ledger_sequence", "env.ledger().sequence()"),
            ("get_ledger_timestamp", "env.ledger().timestamp()"),
            ("get_current_contract_address", "env.current_contract_address()"),
            ("get_invoking_contract_address", "env.invoker()"),
        ];

        for (deprecated, suggestion) in deprecated_methods {
            if method_name == deprecated {
                self.violations.push(RuleViolation {
                    rule_name: "deprecated_host_fns".to_string(),
                    severity: Severity::Warning,
                    message: format!(
                        "Usage of deprecated host function `{}`. Use `{}` instead.",
                        deprecated, suggestion
                    ),
                    location: format!("line:{}", i.method.span().start().line),
                });
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprecated_host_fn_detection() {
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
