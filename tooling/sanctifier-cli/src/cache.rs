use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use sanctifier_core::{ArithmeticIssue, PanicIssue, RuleViolation, SizeWarning, UnsafePattern, CustomRuleMatch};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisCache {
    pub files: HashMap<String, FileCacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileCacheEntry {
    pub hash: String,
    pub results: CachedAnalysisResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedAnalysisResult {
    pub size_warnings: Vec<SizeWarning>,
    pub unsafe_patterns: Vec<UnsafePattern>,
    pub auth_gaps: Vec<String>,
    pub panic_issues: Vec<PanicIssue>,
    pub arithmetic_issues: Vec<ArithmeticIssue>,
    pub deprecated_issues: Vec<RuleViolation>,
    pub custom_matches: Vec<CustomRuleMatch>,
}

pub struct CacheManager {
    cache_path: PathBuf,
    pub cache: AnalysisCache,
}

impl CacheManager {
    pub fn new(project_root: &Path) -> Self {
        let cache_path = project_root.join(".sanctifier_cache");
        let cache = if let Ok(content) = fs::read_to_string(&cache_path) {
            serde_json::from_str(&content).unwrap_or_else(|_| AnalysisCache {
                files: HashMap::new(),
            })
        } else {
            AnalysisCache {
                files: HashMap::new(),
            }
        };

        Self { cache_path, cache }
    }

    pub fn get_file_entry(&self, file_path: &Path) -> Option<&FileCacheEntry> {
        self.cache.files.get(&file_path.to_string_lossy().to_string())
    }

    pub fn update_file_entry(&mut self, file_path: &Path, hash: String, results: CachedAnalysisResult) {
        self.cache.files.insert(
            file_path.to_string_lossy().to_string(),
            FileCacheEntry { hash, results },
        );
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(&self.cache)?;
        fs::write(&self.cache_path, content)?;
        Ok(())
    }

    pub fn calculate_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}
