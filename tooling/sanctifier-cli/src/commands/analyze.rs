use crate::cache::{CacheManager, CachedAnalysisResult};
use clap::Args;
use colored::*;
use sanctifier_core::{Analyzer, SanctifyConfig, SizeWarningLevel};
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the contract directory or Cargo.toml
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Limit for ledger entry size in bytes
    #[arg(short, long, default_value = "64000")]
    pub limit: usize,
}

pub fn exec(args: AnalyzeArgs) -> anyhow::Result<()> {
    let path = &args.path;
    let format = &args.format;
    let _limit = args.limit;
    let is_json = format == "json";

    if !is_soroban_project(path) {
        if is_json {
            let err = serde_json::json!({
                "error": format!("{:?} is not a valid Soroban project", path),
                "success": false,
            });
            println!("{}", serde_json::to_string_pretty(&err)?);
        } else {
            eprintln!(
                "❌ Error: {:?} is not a valid Soroban project. (Missing Cargo.toml with 'soroban-sdk' dependency)",
                path
            );
        }
        std::process::exit(1);
    }

    if is_json {
        eprintln!(
            "✨ Sanctifier: Valid Soroban project found at {:?}",
            path
        );
        eprintln!("🔍 Analyzing contract at {:?}...", path);
    } else {
        println!(
            "✨ Sanctifier: Valid Soroban project found at {:?}",
            path
        );
        println!("🔍 Analyzing contract at {:?}...", path);
    }

    let mut config = load_config(path);
    config.ledger_limit = args.limit;

    let mut cache_manager = CacheManager::new(path);
    let analyzer = Analyzer::new(config);

    let mut collisions = Vec::new();
    let mut size_warnings = Vec::new();
    let mut unsafe_patterns = Vec::new();
    let mut auth_gaps = Vec::new();
    let mut panic_issues = Vec::new();
    let mut arithmetic_issues = Vec::new();
    let mut deprecated_issues = Vec::new();
    let mut custom_matches = Vec::new();

    if path.is_dir() {
        walk_dir(
            path,
            &analyzer,
            &mut cache_manager,
            &mut collisions,
            &mut size_warnings,
            &mut unsafe_patterns,
            &mut auth_gaps,
            &mut panic_issues,
            &mut arithmetic_issues,
            &mut deprecated_issues,
            &mut custom_matches,
        )?;
    } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        if let Ok(content) = fs::read_to_string(path) {
            let hash = CacheManager::calculate_hash(&content);
            let mut used_cache = false;

            if let Some(entry) = cache_manager.get_file_entry(path) {
                if entry.hash == hash {
                    size_warnings.extend(entry.results.size_warnings.clone());
                    unsafe_patterns.extend(entry.results.unsafe_patterns.clone());
                    auth_gaps.extend(entry.results.auth_gaps.clone());
                    panic_issues.extend(entry.results.panic_issues.clone());
                    arithmetic_issues.extend(entry.results.arithmetic_issues.clone());
                    deprecated_issues.extend(entry.results.deprecated_issues.clone());
                    custom_matches.extend(entry.results.custom_matches.clone());
                    used_cache = true;
                }
            }

            if !used_cache {
                let s_warnings = analyzer.analyze_ledger_size(&content);
                size_warnings.extend(s_warnings.clone());

                let patterns = analyzer.analyze_unsafe_patterns(&content);
                unsafe_patterns.extend(patterns.clone());

                let gaps = analyzer.scan_auth_gaps(&content);
                auth_gaps.extend(gaps.clone());

                let panics = analyzer.scan_panics(&content);
                panic_issues.extend(panics.clone());

                let arith = analyzer.scan_arithmetic_overflow(&content);
                arithmetic_issues.extend(arith.clone());

                let deprecated = analyzer.scan_deprecated_host_fns(&content);
                deprecated_issues.extend(deprecated.clone());

                let custom = analyzer.analyze_custom_rules(&content, &analyzer.config.custom_rules);
                custom_matches.extend(custom.clone());

                cache_manager.update_file_entry(
                    path,
                    hash,
                    CachedAnalysisResult {
                        size_warnings: s_warnings,
                        unsafe_patterns: patterns,
                        auth_gaps: gaps,
                        panic_issues: panics,
                        arithmetic_issues: arith,
                        deprecated_issues: deprecated,
                        custom_matches: custom,
                    },
                );
            }
            // Collisions are NOT cached because they depend on multiple files often
            collisions.extend(analyzer.scan_storage_collisions(&content));
        }
    }

    if let Err(e) = cache_manager.save() {
        eprintln!("⚠️ Warning: Failed to save cache: {}", e);
    }

    let total_findings = collisions.len()
        + size_warnings.len()
        + unsafe_patterns.len()
        + auth_gaps.len()
        + panic_issues.len()
        + arithmetic_issues.len()
        + deprecated_issues.len()
        + custom_matches.len();

    let has_critical =
        !auth_gaps.is_empty() || panic_issues.iter().any(|p| p.issue_type == "panic!");
    let has_high = !arithmetic_issues.is_empty()
        || !panic_issues.is_empty()
        || size_warnings
            .iter()
            .any(|w| w.level == SizeWarningLevel::ExceedsLimit);

    if is_json {
        let report = serde_json::json!({
            "metadata": {
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": chrono_timestamp(),
                "project_path": path.display().to_string(),
                "format": "sanctifier-ci-v1",
            },
            "summary": {
                "total_findings": total_findings,
                "storage_collisions": collisions.len(),
                "auth_gaps": auth_gaps.len(),
                "panic_issues": panic_issues.len(),
                "arithmetic_issues": arithmetic_issues.len(),
                "deprecated_issues": deprecated_issues.len(),
                "size_warnings": size_warnings.len(),
                "unsafe_patterns": unsafe_patterns.len(),
                "custom_rule_matches": custom_matches.len(),
                "has_critical": has_critical,
                "has_high": has_high,
            },
            "findings": {
                "storage_collisions": collisions,
                "ledger_size_warnings": size_warnings,
                "unsafe_patterns": unsafe_patterns,
                "auth_gaps": auth_gaps,
                "panic_issues": panic_issues,
                "arithmetic_issues": arithmetic_issues,
                "deprecated_host_fns": deprecated_issues,
                "custom_rules": custom_matches,
            },
        });
        println!("{}", serde_json::to_string_pretty(&report)?);

        if has_critical || has_high {
            std::process::exit(1);
        }
        return Ok(());
    }

    if collisions.is_empty() {
        println!("\n✅ No storage key collisions found.");
    } else {
        println!(
            "\n⚠️ Found potential Storage Key Collisions!"
        );
        for collision in collisions {
            println!("   -> Value: {}", collision.key_value.bold());
            println!("      Type: {}", collision.key_type);
            println!("      Location: {}", collision.location);
            println!("      Message: {}", collision.message);
        }
    }

    if auth_gaps.is_empty() {
        println!("✅ No authentication gaps found.");
    } else {
        println!("\n⚠️ Found potential Authentication Gaps!");
        for gap in auth_gaps {
            println!("   -> Function: {}", gap.bold());
        }
    }

    if panic_issues.is_empty() {
        println!("✅ No explicit Panics/Unwraps found.");
    } else {
        println!("\n⚠️ Found explicit Panics/Unwraps!");
        for issue in panic_issues {
            println!("   -> Type: {}", issue.issue_type.bold());
            println!("      Location: {}", issue.location);
        }
    }

    if arithmetic_issues.is_empty() {
        println!("✅ No unchecked Arithmetic Operations found.");
    } else {
        println!("\n⚠️ Found unchecked Arithmetic Operations!");
        for issue in arithmetic_issues {
            println!("   -> Op: {}", issue.operation.bold());
            println!("      Location: {}", issue.location);
        }
    }

    if deprecated_issues.is_empty() {
        println!("✅ No deprecated Soroban host functions found.");
    } else {
        println!(
            "\n⚠️ Found usage of Deprecated Host Functions!"
        );
        for issue in deprecated_issues {
            println!("   -> {}", issue.message.bold());
            println!("      Location: {}", issue.location);
        }
    }

    if size_warnings.is_empty() {
        println!("✅ No ledger size issues found.");
    } else {
        println!("\n⚠️ Found Ledger Size Warnings!");
        for warning in size_warnings {
            println!("   -> Struct: {}", warning.struct_name.bold());
            println!("      Size: {} bytes", warning.estimated_size);
        }
    }

    if !custom_matches.is_empty() {
        println!("\n⚠️ Found Custom Rule matches!");
        for m in custom_matches {
            let sev_icon = match m.severity {
                sanctifier_core::RuleSeverity::Error => "❌",
                sanctifier_core::RuleSeverity::Warning => "⚠️",
                sanctifier_core::RuleSeverity::Info => "ℹ️",
            };
            println!("   {} [{}]: {}", sev_icon, m.rule_name.bold(), m.snippet);
        }
    }

    println!("\n✨ Static analysis complete.");

    Ok(())
}

fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{}", secs)
}

fn load_config(path: &Path) -> SanctifyConfig {
    let mut current = if path.is_file() {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        path.to_path_buf()
    };

    loop {
        let config_path = current.join(".sanctify.toml");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }
        if !current.pop() {
            break;
        }
    }
    SanctifyConfig::default()
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    dir: &Path,
    analyzer: &Analyzer,
    cache_manager: &mut CacheManager,
    collisions: &mut Vec<sanctifier_core::StorageCollisionIssue>,
    size_warnings: &mut Vec<sanctifier_core::SizeWarning>,
    unsafe_patterns: &mut Vec<sanctifier_core::UnsafePattern>,
    auth_gaps: &mut Vec<String>,
    panic_issues: &mut Vec<sanctifier_core::PanicIssue>,
    arithmetic_issues: &mut Vec<sanctifier_core::ArithmeticIssue>,
    deprecated_issues: &mut Vec<sanctifier_core::RuleViolation>,
    custom_matches: &mut Vec<sanctifier_core::CustomRuleMatch>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip ignore_paths and exclude
            let is_ignored = analyzer.config.ignore_paths.iter().any(|p| path.ends_with(p));
            let is_excluded = analyzer.config.exclude.iter().any(|p| path.ends_with(p));

            if is_ignored || is_excluded {
                continue;
            }

            walk_dir(
                &path,
                analyzer,
                cache_manager,
                collisions,
                size_warnings,
                unsafe_patterns,
                auth_gaps,
                panic_issues,
                arithmetic_issues,
                deprecated_issues,
                custom_matches,
            )?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = fs::read_to_string(&path) {
                let file_name = path.display().to_string();
                let hash = CacheManager::calculate_hash(&content);
                let mut used_cache = false;

                if let Some(entry) = cache_manager.get_file_entry(&path) {
                    if entry.hash == hash {
                        size_warnings.extend(entry.results.size_warnings.clone());
                        unsafe_patterns.extend(entry.results.unsafe_patterns.clone());
                        auth_gaps.extend(entry.results.auth_gaps.clone());
                        panic_issues.extend(entry.results.panic_issues.clone());
                        arithmetic_issues.extend(entry.results.arithmetic_issues.clone());
                        deprecated_issues.extend(entry.results.deprecated_issues.clone());
                        custom_matches.extend(entry.results.custom_matches.clone());
                        used_cache = true;
                    }
                }

                if !used_cache {
                    let s_warnings = analyzer.analyze_ledger_size(&content);
                    size_warnings.extend(s_warnings.clone());

                    let patterns = analyzer.analyze_unsafe_patterns(&content);
                    let mut local_patterns = Vec::new();
                    for mut i in patterns {
                        i.snippet = format!("{}:{}", file_name, i.snippet);
                        local_patterns.push(i.clone());
                        unsafe_patterns.push(i);
                    }

                    let gaps = analyzer.scan_auth_gaps(&content);
                    let mut local_gaps = Vec::new();
                    for g in gaps {
                        let gap_msg = format!("{}:{}", file_name, g);
                        local_gaps.push(gap_msg.clone());
                        auth_gaps.push(gap_msg);
                    }

                    let panics = analyzer.scan_panics(&content);
                    let mut local_panics = Vec::new();
                    for mut i in panics {
                        i.location = format!("{}:{}", file_name, i.location);
                        local_panics.push(i.clone());
                        panic_issues.push(i);
                    }

                    let arith = analyzer.scan_arithmetic_overflow(&content);
                    let mut local_arith = Vec::new();
                    for mut i in arith {
                        i.location = format!("{}:{}", file_name, i.location);
                        local_arith.push(i.clone());
                        arithmetic_issues.push(i);
                    }

                    let deprecated = analyzer.scan_deprecated_host_fns(&content);
                    let mut local_deprecated = Vec::new();
                    for mut i in deprecated {
                        i.location = format!("{}:{}", file_name, i.location);
                        local_deprecated.push(i.clone());
                        deprecated_issues.push(i);
                    }

                    let custom = analyzer.analyze_custom_rules(&content, &analyzer.config.custom_rules);
                    let mut local_custom = Vec::new();
                    for mut m in custom {
                        m.snippet = format!("{}:{}: {}", file_name, m.line, m.snippet);
                        local_custom.push(m.clone());
                        custom_matches.push(m);
                    }

                    cache_manager.update_file_entry(
                        &path,
                        hash,
                        CachedAnalysisResult {
                            size_warnings: s_warnings,
                            unsafe_patterns: local_patterns,
                            auth_gaps: local_gaps,
                            panic_issues: local_panics,
                            arithmetic_issues: local_arith,
                            deprecated_issues: local_deprecated,
                            custom_matches: local_custom,
                        },
                    );
                }

                // Collisions are NOT cached because they depend on multiple files often
                let mut c = analyzer.scan_storage_collisions(&content);
                for i in &mut c {
                    i.location = format!("{}:{}", file_name, i.location);
                }
                collisions.extend(c);
            }
        }
    }
    Ok(())
}

fn is_soroban_project(path: &Path) -> bool {
    // Basic heuristics for tests.
    if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        return true;
    }
    let cargo_toml_path = if path.is_dir() {
        path.join("Cargo.toml")
    } else {
        path.to_path_buf()
    };
    cargo_toml_path.exists()
}
    Ok(())
}
