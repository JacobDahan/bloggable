use crate::git::commit::{CommitInfo, CommitSpec};
use crate::git::diff::Diff;
use crate::git::repository::Repository;
use futures;
use regex::Regex;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::sync::RwLock;

/// Alias for Result type used throughout the parser.
type ParseResult<T> = Result<T, ParseError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid commit format for commits {commits}: {reason}")]
    InvalidFormat { commits: String, reason: String },
    #[error("Commit(s) not found in repository: {}", .failed_commits.join(", "))]
    NotFound { failed_commits: Vec<String> },
    #[error("Unexpected error: {0}")]
    Internal(String),
}

static RANGE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s]+\.\.[^\s]+$").unwrap());
static MULTI_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^\s]+(\s+[^\s]+)+$").unwrap());
static SINGLE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s]+$").unwrap());

/// Parser for CLI-provided Git commit ranges
pub struct CommitParser {
    repository: Arc<RwLock<Repository>>,
}

impl CommitParser {
    pub fn new(repository: Arc<RwLock<Repository>>) -> Self {
        CommitParser { repository }
    }

    /// Parse a commit range string into a `CommitSpec` enum.
    ///
    /// The input can be a single commit, a range (e.g., `HEAD~5..HEAD`),
    /// or multiple commits (e.g., `abc123 def456`).
    ///
    /// Any valid Git commit-ish is supported (branch names, tags, etc.).
    ///
    /// # Examples
    ///
    /// Parsing a single commit reference:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, path::PathBuf};
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let _commit = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Initial commit",
    /// #         &tree,
    /// #         &[],
    /// #     ).unwrap();
    /// #
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let single_spec = parser.parse_commits("HEAD").await.unwrap();
    ///     assert!(matches!(single_spec, CommitSpec::Single(_)));
    /// # });
    /// ```
    ///
    /// Parsing multiple commit references:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, path::PathBuf};
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Initial commit",
    /// #         &tree,
    /// #         &[],
    /// #     ).unwrap();
    /// #     let second_commit = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Second commit",
    /// #         &tree,
    /// #         &[&git.find_commit(first_commit).unwrap()],
    /// #     ).unwrap();
    /// #
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let multi_commits = format!("{} {}", first_commit, second_commit);
    ///     let multi_spec = parser.parse_commits(&multi_commits).await.unwrap();
    ///     
    ///     if let CommitSpec::Multiple(commits) = multi_spec {
    ///         assert_eq!(commits.len(), 2);
    ///     } else {
    ///         panic!("Expected Multiple commit spec");
    ///     }
    /// # });
    /// ```
    ///
    /// Parsing a commit range:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, path::PathBuf};
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Initial commit",
    /// #         &tree,
    /// #         &[],
    /// #     ).unwrap();
    /// #     let second_commit = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Second commit",
    /// #         &tree,
    /// #         &[&git.find_commit(first_commit).unwrap()],
    /// #     ).unwrap();
    /// #
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let range_str = format!("{}..{}", first_commit, second_commit);
    ///     let range_spec = parser.parse_commits(&range_str).await.unwrap();
    ///     
    ///     if let CommitSpec::Range { from, to } = range_spec {
    ///         assert_eq!(from.id(), first_commit.to_string());
    ///         assert_eq!(to.id(), second_commit.to_string());
    ///     } else {
    ///         panic!("Expected Range commit spec");
    ///     }
    /// # });
    /// ```
    pub async fn parse_commits(&self, commits: &str) -> ParseResult<CommitSpec> {
        self.validate_commit_format(commits)?;

        match commits {
            _ if RANGE_REGEX.is_match(commits) => self.parse_range(commits).await,
            _ if MULTI_REGEX.is_match(commits) => self.parse_multi(commits).await,
            _ if SINGLE_REGEX.is_match(commits) => self.parse_single(commits).await,
            _ => {
                return Err(ParseError::InvalidFormat {
                    commits: commits.to_string(),
                    reason: "Unrecognized commit format".into(),
                });
            }
        }
    }

    /// Generate diffs for a CommitSpec.
    ///
    /// For Single and Multiple specs, returns individual diffs for each commit.
    /// For Range specs, walks the range to find all commits and returns their individual diffs.
    ///
    /// # Examples
    ///
    /// Generating a diff for a single commit:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, fs};
    /// #     use std::path::PathBuf;
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     
    /// #     // Create initial commit
    /// #     fs::write(dir.path().join("main.rs"), "fn main() { println!(\"Hello\"); }").unwrap();
    /// #     let mut index = git.index().unwrap();
    /// #     index.add_path(std::path::Path::new("main.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let _commit = git.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[]).unwrap();
    /// #     
    /// #     // Create second commit with changes
    /// #     fs::write(dir.path().join("main.rs"), "fn main() { println!(\"Hello, World!\"); }").unwrap();
    /// #     index.add_path(std::path::Path::new("main.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit = git.head().unwrap().peel_to_commit().unwrap();
    /// #     let _second_commit = git.commit(Some("HEAD"), &sig, &sig, "Update message", &tree, &[&first_commit]).unwrap();
    /// #
    ///     let repo = Repository::try_local(dir.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let spec = parser.parse_commits("HEAD").await.unwrap();
    ///     let diffs = parser.generate_diffs(spec).await.unwrap();
    ///     
    ///     assert_eq!(diffs.len(), 1);
    ///     assert!(!diffs[0].files().is_empty());
    ///     assert_eq!(diffs[0].files()[0].new_path().unwrap(), &PathBuf::from("main.rs"));
    /// # });
    /// ```
    ///
    /// Generating diffs for multiple commits:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, fs};
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     
    /// #     // Create first commit
    /// #     fs::write(dir.path().join("file1.rs"), "// File 1").unwrap();
    /// #     let mut index = git.index().unwrap();
    /// #     index.add_path(std::path::Path::new("file1.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit = git.commit(Some("HEAD"), &sig, &sig, "First commit", &tree, &[]).unwrap();
    /// #     
    /// #     // Create second commit
    /// #     fs::write(dir.path().join("file2.rs"), "// File 2").unwrap();
    /// #     index.add_path(std::path::Path::new("file2.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit_obj = git.find_commit(first_commit).unwrap();
    /// #     let second_commit = git.commit(Some("HEAD"), &sig, &sig, "Second commit", &tree, &[&first_commit_obj]).unwrap();
    /// #
    ///     let repo = Repository::try_local(dir.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let commits_str = format!("{} {}", first_commit, second_commit);
    ///     let spec = parser.parse_commits(&commits_str).await.unwrap();
    ///     let diffs = parser.generate_diffs(spec).await.unwrap();
    ///     
    ///     assert_eq!(diffs.len(), 2);
    ///     assert!(!diffs[0].files().is_empty());
    ///     assert!(!diffs[1].files().is_empty());
    /// # });
    /// ```
    ///
    /// Generating diffs for a commit range:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::parsing::CommitParser;
    /// #     use bloggable::git::repository::Repository;
    /// #     use bloggable::git::commit::CommitSpec;
    /// #     use std::{sync::Arc, fs};
    /// #     use std::path::PathBuf;
    /// #     use tokio::sync::RwLock;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     
    /// #     // Create first commit
    /// #     fs::write(dir.path().join("base.rs"), "// Base file").unwrap();
    /// #     let mut index = git.index().unwrap();
    /// #     index.add_path(std::path::Path::new("base.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit = git.commit(Some("HEAD"), &sig, &sig, "Base commit", &tree, &[]).unwrap();
    /// #     
    /// #     // Create second commit (this will be included in range)
    /// #     fs::write(dir.path().join("feature.rs"), "// Feature file").unwrap();
    /// #     index.add_path(std::path::Path::new("feature.rs")).unwrap();
    /// #     index.write().unwrap();
    /// #     let tree_id = index.write_tree().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let first_commit_obj = git.find_commit(first_commit).unwrap();
    /// #     let second_commit = git.commit(Some("HEAD"), &sig, &sig, "Feature commit", &tree, &[&first_commit_obj]).unwrap();
    /// #
    ///     let repo = Repository::try_local(dir.path().into()).await.unwrap();
    ///     let parser = CommitParser::new(Arc::new(RwLock::new(repo)));
    ///
    ///     let range_str = format!("{}..{}", first_commit, second_commit);
    ///     let spec = parser.parse_commits(&range_str).await.unwrap();
    ///     let diffs = parser.generate_diffs(spec).await.unwrap();
    ///     
    ///     // Range returns diffs for commits reachable from 'to' but not from 'from'
    ///     assert_eq!(diffs.len(), 1);
    ///     assert!(!diffs[0].files().is_empty());
    ///     assert_eq!(diffs[0].files()[0].new_path().unwrap(), &PathBuf::from("feature.rs"));
    /// # });
    /// ```
    pub async fn generate_diffs(&self, commit_spec: CommitSpec) -> ParseResult<Vec<Diff>> {
        let commit_infos = match commit_spec {
            CommitSpec::Single(commit_info) => vec![commit_info],
            CommitSpec::Multiple(mut commit_infos) => {
                // Sort commits chronologically (oldest first)
                commit_infos.sort();
                commit_infos
            }
            CommitSpec::Range { from, to } => {
                let repository = self.repository.read().await;
                repository.walk_range(&from, &to).await.map_err(|e| {
                    ParseError::Internal(format!("Failed to walk commit range: {}", e))
                })?
            }
        };

        let futures: Vec<_> = commit_infos
            .iter()
            .map(|commit_info| async move {
                let repository = self.repository.read().await;
                let diff = repository.generate_diff(commit_info).await;
                (commit_info.id(), diff)
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        let mut successes = Vec::new();
        let mut failures = Vec::new();

        // Separate successes from failures
        for (commit_ref, result) in results {
            match result {
                Ok(diff) => successes.push(diff),
                Err(_) => failures.push(commit_ref.to_string()),
            }
        }

        if failures.is_empty() {
            Ok(successes)
        } else {
            Err(ParseError::Internal(format!(
                "Failed to generate diffs for commits: {}",
                failures.join(", ")
            )))
        }
    }

    /// Parse a single commit-ish reference to a `CommitSpec::Single`.
    /// This will resolve the commit-ish to a commit info object,
    /// if a valid commit is found. Otherwise, an error is returned.
    /// The input can be any valid Git reference (branch name, tag, OID, etc.).
    async fn parse_single(&self, commit: &str) -> ParseResult<CommitSpec> {
        let mut resolved_commit_infos = self.resolve_commit_infos(vec![commit]).await?;

        let commit_info = resolved_commit_infos.pop().ok_or(ParseError::Internal(
            "This should never happen: resolved_commit_infos is empty after successful resolution"
                .into(),
        ))?;

        Ok(CommitSpec::Single(commit_info))
    }

    /// Parse a commit-ish range string to a `CommitSpec::Range`.
    /// The input range must be in the format `from..to`.
    /// This will resolve the commit-ish references to full commit objects,
    /// if valid commits are found. Otherwise, an error is returned.
    /// The input can be any valid Git references (branch names, tags, OIDs, etc.).
    async fn parse_range(&self, commits: &str) -> ParseResult<CommitSpec> {
        let parts: Vec<&str> = commits.split("..").collect();
        if parts.len() != 2 {
            return Err(ParseError::InvalidFormat {
                commits: commits.to_string(),
                reason: "Commit range must contain exactly two parts separated by '..'".into(),
            });
        }

        let resolved_commit_infos = self.resolve_commit_infos(parts).await?;

        let (from, to) = match resolved_commit_infos.len() {
            2 => (
                resolved_commit_infos[0].clone(),
                resolved_commit_infos[1].clone(),
            ),
            n => {
                return Err(ParseError::Internal(format!(
                    "This should never happen: expected 2 commits, got {}",
                    n
                )));
            }
        };

        // Validate that "from" is an ancestor of "to" using commit IDs
        let repository = self.repository.read().await;
        match repository.is_ancestor(&from, &to).await {
            Ok(true) => Ok(CommitSpec::Range { from, to }),
            Ok(false) => {
                return Err(ParseError::InvalidFormat {
                    commits: commits.to_string(),
                    reason: format!(
                        "Invalid commit range: '{}' is not an ancestor of '{}'",
                        from.id(),
                        to.id()
                    ),
                });
            }
            Err(e) => {
                return Err(ParseError::Internal(format!(
                    "Failed to verify commit ancestry: {}",
                    e
                )));
            }
        }
    }

    /// Parse multiple commit-ish references to a `CommitSpec::Multiple`.
    /// The input can be any number of valid Git references separated by whitespace.
    /// This will resolve the commit-ish references to commit info objects,
    /// if valid commits are found. Otherwise, an error is returned.
    /// The input can be any valid Git references (branch names, tags, OIDs, etc.).
    async fn parse_multi(&self, commits: &str) -> ParseResult<CommitSpec> {
        let commit_ids: Vec<&str> = commits.split_whitespace().collect();
        let resolved_commit_infos = self.resolve_commit_infos(commit_ids).await?;

        Ok(CommitSpec::Multiple(resolved_commit_infos))
    }

    // == Utility methods ==

    /// Validate the input format for commits.
    /// This is a basic validation to catch empty strings and obviously malformed inputs.
    /// More complex validation is done in the individual parsing methods.
    fn validate_commit_format(&self, commits: &str) -> Result<(), ParseError> {
        if commits.trim().is_empty() {
            return Err(ParseError::InvalidFormat {
                commits: commits.to_string(),
                reason: "Commit string is empty".into(),
            });
        }
        Ok(())
    }

    /// Resolve commit-ish references to commit info objects.
    /// This method will attempt to resolve all commits concurrently.
    /// If any commit cannot be resolved, an error will be returned indicating
    /// which specific commits failed to resolve.
    async fn resolve_commit_infos(&self, commits: Vec<&str>) -> ParseResult<Vec<CommitInfo>> {
        // Create futures for all commits with their original references
        let futures: Vec<_> = commits
            .iter()
            .map(|&commit_ref| async move {
                let repository = self.repository.read().await;
                let result = repository.resolve_commit(commit_ref).await;
                (commit_ref, result)
            })
            .collect();

        // Execute all futures concurrently
        let results = futures::future::join_all(futures).await;

        let mut successes = Vec::new();
        let mut failures = Vec::new();

        // Separate successes from failures
        for (commit_ref, result) in results {
            match result {
                Ok(commit_info) => successes.push(commit_info),
                Err(_) => failures.push(commit_ref.to_string()),
            }
        }

        if failures.is_empty() {
            Ok(successes)
        } else {
            Err(ParseError::NotFound {
                failed_commits: failures,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::tests::common::TestRepo;
    use std::{path::PathBuf, sync::Arc};
    use tokio::sync::RwLock;

    async fn setup_parser() -> (TestRepo, CommitParser) {
        let test_repo = TestRepo::new().await;
        let parser = CommitParser::new(Arc::new(RwLock::new(
            Repository::try_local(test_repo._temp_dir.path().into())
                .await
                .unwrap(),
        )));
        (test_repo, parser)
    }

    // == Single Commit Tests ==

    #[tokio::test]
    async fn test_parse_single_commit_by_hash() {
        let (test_repo, parser) = setup_parser().await;

        // Test full hash
        let commit_id = test_repo.first_commit_id();
        let spec = parser.parse_commits(&commit_id).await.unwrap();

        match spec {
            CommitSpec::Single(commit) => {
                assert_eq!(commit.id(), commit_id);
            }
            _ => panic!("Expected Single commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_single_commit_by_short_hash() {
        let (test_repo, parser) = setup_parser().await;

        // Test short hash (first 7 characters)
        let commit_id = test_repo.second_commit_id();
        let short_hash = &commit_id[..7];
        let spec = parser.parse_commits(short_hash).await.unwrap();

        match spec {
            CommitSpec::Single(commit) => {
                assert_eq!(commit.id(), commit_id);
            }
            _ => panic!("Expected Single commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_single_commit_by_head() {
        let (test_repo, parser) = setup_parser().await;

        let spec = parser.parse_commits("HEAD").await.unwrap();

        match spec {
            CommitSpec::Single(commit) => {
                // HEAD should resolve to the most recent commit
                assert_eq!(commit.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Single commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_single_commit_by_head_relative() {
        let (test_repo, parser) = setup_parser().await;

        let spec = parser.parse_commits("HEAD~1").await.unwrap();

        match spec {
            CommitSpec::Single(commit) => {
                // HEAD~1 should resolve to the first commit
                assert_eq!(commit.id(), test_repo.first_commit_id());
            }
            _ => panic!("Expected Single commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_single_commit_by_tag() {
        let (test_repo, parser) = setup_parser().await;

        let spec = parser.parse_commits("v2.0").await.unwrap();

        match spec {
            CommitSpec::Single(commit) => {
                // v2.0 tag should resolve to the second commit
                assert_eq!(commit.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Single commit spec"),
        }
    }

    // == Range Tests ==

    #[tokio::test]
    async fn test_parse_valid_range() {
        let (test_repo, parser) = setup_parser().await;

        let range = format!(
            "{}..{}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let spec = parser.parse_commits(&range).await.unwrap();

        match spec {
            CommitSpec::Range { from, to } => {
                assert_eq!(from.id(), test_repo.first_commit_id());
                assert_eq!(to.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Range commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_range_with_head_references() {
        let (test_repo, parser) = setup_parser().await;

        let spec = parser.parse_commits("HEAD~1..HEAD").await.unwrap();

        match spec {
            CommitSpec::Range { from, to } => {
                assert_eq!(from.id(), test_repo.first_commit_id());
                assert_eq!(to.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Range commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_range_with_short_hashes() {
        let (test_repo, parser) = setup_parser().await;

        let first_short = &test_repo.first_commit_id()[..7];
        let second_short = &test_repo.second_commit_id()[..7];
        let range = format!("{}..{}", first_short, second_short);

        let spec = parser.parse_commits(&range).await.unwrap();

        match spec {
            CommitSpec::Range { from, to } => {
                assert_eq!(from.id(), test_repo.first_commit_id());
                assert_eq!(to.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Range commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_range_with_mixed_references() {
        let (test_repo, parser) = setup_parser().await;

        let first_short = &test_repo.first_commit_id()[..7];
        let range = format!("{}..HEAD", first_short);

        let spec = parser.parse_commits(&range).await.unwrap();

        match spec {
            CommitSpec::Range { from, to } => {
                assert_eq!(from.id(), test_repo.first_commit_id());
                assert_eq!(to.id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Range commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_range_not_ancestor() {
        let (test_repo, parser) = setup_parser().await;

        // Reverse the range - second commit is not ancestor of first
        let range = format!(
            "{}..{}",
            test_repo.second_commit_id(),
            test_repo.first_commit_id()
        );
        let result = parser.parse_commits(&range).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::InvalidFormat { commits, reason } => {
                assert_eq!(commits, range);
                assert!(reason.contains("not an ancestor"));
            }
            _ => panic!("Expected InvalidFormat error about ancestry"),
        }
    }

    // == Multiple Commit Tests ==

    #[tokio::test]
    async fn test_parse_multiple_commits() {
        let (test_repo, parser) = setup_parser().await;

        let multi = format!(
            "{} {}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let spec = parser.parse_commits(&multi).await.unwrap();

        match spec {
            CommitSpec::Multiple(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].id(), test_repo.first_commit_id());
                assert_eq!(commits[1].id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Multiple commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_multiple_commits_with_head() {
        let (test_repo, parser) = setup_parser().await;

        let multi = format!("HEAD~1 HEAD {}", test_repo.first_commit_id());
        let spec = parser.parse_commits(&multi).await.unwrap();

        match spec {
            CommitSpec::Multiple(commits) => {
                assert_eq!(commits.len(), 3);
                assert_eq!(commits[0].id(), test_repo.first_commit_id()); // HEAD~1
                assert_eq!(commits[1].id(), test_repo.second_commit_id()); // HEAD
                assert_eq!(commits[2].id(), test_repo.first_commit_id()); // explicit hash
            }
            _ => panic!("Expected Multiple commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_multiple_commits_with_short_hashes() {
        let (test_repo, parser) = setup_parser().await;

        let first_short = &test_repo.first_commit_id()[..7];
        let second_short = &test_repo.second_commit_id()[..7];
        let multi = format!("{} {}", first_short, second_short);

        let spec = parser.parse_commits(&multi).await.unwrap();

        match spec {
            CommitSpec::Multiple(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].id(), test_repo.first_commit_id());
                assert_eq!(commits[1].id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Multiple commit spec"),
        }
    }

    #[tokio::test]
    async fn test_parse_multiple_commits_with_mixed_references() {
        let (test_repo, parser) = setup_parser().await;
        let first_short = &test_repo.first_commit_id()[..7];
        let multi = format!("{} {}", first_short, "v2.0");
        let spec = parser.parse_commits(&multi).await.unwrap();

        match spec {
            CommitSpec::Multiple(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].id(), test_repo.first_commit_id()); // explicit hash
                assert_eq!(commits[1].id(), test_repo.second_commit_id()); // v2.0
            }
            _ => panic!("Expected Multiple commit spec"),
        }
    }

    // == Error Cases ==

    #[tokio::test]
    async fn test_parse_empty_string() {
        let (_test_repo, parser) = setup_parser().await;

        let result = parser.parse_commits("").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ParseError::InvalidFormat { commits, reason } => {
                assert_eq!(commits, "");
                assert!(reason.contains("empty"));
            }
            _ => panic!("Expected InvalidFormat error for empty string"),
        }
    }

    #[tokio::test]
    async fn test_parse_whitespace_only() {
        let (_test_repo, parser) = setup_parser().await;

        let result = parser.parse_commits("   \t\n   ").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ParseError::InvalidFormat { reason, .. } => {
                assert!(reason.contains("empty"));
            }
            _ => panic!("Expected InvalidFormat error for whitespace-only string"),
        }
    }

    #[tokio::test]
    async fn test_parse_nonexistent_commit() {
        let (_test_repo, parser) = setup_parser().await;

        let result = parser.parse_commits("nonexistent123").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ParseError::NotFound { failed_commits } => {
                assert_eq!(failed_commits, vec!["nonexistent123"]);
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_parse_multiple_with_some_nonexistent() {
        let (test_repo, parser) = setup_parser().await;

        let multi = format!(
            "{} nonexistent456 {}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let result = parser.parse_commits(&multi).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::NotFound { failed_commits } => {
                assert_eq!(failed_commits, vec!["nonexistent456"]);
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_parse_range_with_nonexistent_commit() {
        let (test_repo, parser) = setup_parser().await;

        let range = format!("{}..nonexistent", test_repo.first_commit_id());
        let result = parser.parse_commits(&range).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::NotFound { failed_commits } => {
                assert_eq!(failed_commits, vec!["nonexistent"]);
            }
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_parse_malformed_range_extra_dots() {
        let (test_repo, parser) = setup_parser().await;

        let range = format!(
            "{}...{}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let result = parser.parse_commits(&range).await;

        // TODO: Improve commit parsing to more robustly reject malformed ranges
        // Currently, the regex will match "..." as it contains "..", but still
        // results in an invalid range during parsing. For now, we just assert that it fails.
        assert!(
            result.is_err(),
            "Three-dot range should be rejected as invalid"
        );
    }

    #[tokio::test]
    async fn test_parse_malformed_range_no_second_part() {
        let (test_repo, parser) = setup_parser().await;

        let range = format!("{}..", test_repo.first_commit_id());
        let result = parser.parse_commits(&range).await;

        // TODO: Improve commit parsing to more robustly reject malformed ranges
        // Currently, the regex will match "foo.." as a single commit, but still
        // results in an error during parsing. For now, we just assert that it fails.
        assert!(
            result.is_err(),
            "Missing second part of range should be rejected as invalid"
        );
    }

    // == Edge Cases ==

    #[tokio::test]
    async fn test_parse_commits_with_extra_whitespace() {
        let (test_repo, parser) = setup_parser().await;

        // Test multiple commits with irregular spacing (split_whitespace handles this)
        let multi = format!(
            "{}   {}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let spec = parser.parse_commits(&multi).await.unwrap();

        match spec {
            CommitSpec::Multiple(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].id(), test_repo.first_commit_id());
                assert_eq!(commits[1].id(), test_repo.second_commit_id());
            }
            _ => panic!("Expected Multiple commit spec"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_parsing() {
        let (test_repo, parser) = setup_parser().await;

        // Create bindings to avoid temporary value issues
        let first_commit_id = test_repo.first_commit_id();
        let range_spec = format!(
            "{}..{}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );

        // Test that concurrent parsing works correctly
        let futures = vec![
            parser.parse_commits(&first_commit_id),
            parser.parse_commits("HEAD"),
            parser.parse_commits("HEAD~1"),
            parser.parse_commits(&range_spec),
        ];

        let results = futures::future::join_all(futures).await;

        // All should succeed
        for result in results {
            assert!(result.is_ok(), "Concurrent parsing should succeed");
        }
    }

    #[tokio::test]
    async fn test_regex_patterns() {
        // Test the regex patterns directly
        assert!(SINGLE_REGEX.is_match("abc123"));
        assert!(SINGLE_REGEX.is_match("HEAD"));
        assert!(SINGLE_REGEX.is_match("HEAD~1"));
        assert!(!SINGLE_REGEX.is_match("abc def"));
        // Note: SINGLE_REGEX matches anything without spaces, so it will match "abc..def"
        // The parser logic handles determining if it's actually a range vs single commit

        assert!(RANGE_REGEX.is_match("abc..def"));
        assert!(RANGE_REGEX.is_match("HEAD~1..HEAD"));
        assert!(!RANGE_REGEX.is_match("abc"));
        assert!(!RANGE_REGEX.is_match("abc def"));
        // Note: RANGE_REGEX pattern ^[^\s]+\.\.[^\s]+$ actually matches "abc...def"
        // because "..." contains ".." but the parsing logic will handle this correctly
        assert!(RANGE_REGEX.is_match("abc...def"));

        assert!(MULTI_REGEX.is_match("abc def"));
        assert!(MULTI_REGEX.is_match("HEAD~1 HEAD abc123"));
        assert!(!MULTI_REGEX.is_match("abc"));
        assert!(!MULTI_REGEX.is_match("abc..def"));
    }

    #[tokio::test]
    async fn test_generate_diff_single_spec() {
        let (_test_repo, parser) = setup_parser().await;

        let spec = parser.parse_commits("HEAD").await.unwrap();
        let diffs = parser.generate_diffs(spec).await.unwrap();

        assert_eq!(diffs.len(), 1);
        assert!(!diffs[0].files().is_empty());

        // Verify the diff contains the expected files from the second commit
        let diff = &diffs[0];
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("main.rs")))
        );
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("new_feature.rs")))
        );
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("old_module.rs")))
        );
    }

    #[tokio::test]
    async fn test_generate_diff_multiple_spec() {
        let (test_repo, parser) = setup_parser().await;

        let first_commit = test_repo.first_commit_id();
        let second_commit = test_repo.second_commit_id();
        let commits_str = format!("{} {}", first_commit, second_commit);

        let spec = parser.parse_commits(&commits_str).await.unwrap();
        let diffs = parser.generate_diffs(spec).await.unwrap();

        assert_eq!(diffs.len(), 2);
        assert!(!diffs[0].files().is_empty());
        assert!(!diffs[1].files().is_empty());

        // First diff should contain initial files from first commit
        let first_diff = &diffs[0];
        assert!(
            first_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("main.rs")))
        );
        assert!(
            first_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("utils.rs")))
        );
        assert!(
            first_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("old_module.rs")))
        );

        // Second diff should contain changes from second commit
        let second_diff = &diffs[1];
        assert!(
            second_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("main.rs")))
        );
        assert!(
            second_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("new_feature.rs")))
        );
        assert!(
            second_diff
                .files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("old_module.rs")))
        );
    }

    #[tokio::test]
    async fn test_generate_diff_range_spec() {
        let (test_repo, parser) = setup_parser().await;

        let range = format!(
            "{}..{}",
            test_repo.first_commit_id(),
            test_repo.second_commit_id()
        );
        let spec = parser.parse_commits(&range).await.unwrap();
        let diffs = parser.generate_diffs(spec).await.unwrap();

        // For a two-commit range (first..second), we should get exactly 1 diff
        // (the diff for the second commit, since the range is "commits reachable from second but not from first")
        assert_eq!(diffs.len(), 1);
        assert!(!diffs[0].files().is_empty());

        // Should contain the changes from second commit
        let diff = &diffs[0];
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("main.rs")))
        );
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("new_feature.rs")))
        );
        assert!(
            diff.files()
                .iter()
                .any(|f| f.new_path() == Some(&PathBuf::from("old_module.rs")))
        );
    }

    #[tokio::test]
    async fn test_generate_diff_range_spec_multiple_commits() {
        let (test_repo, parser) = setup_parser().await;

        // Add a third commit to test a range with multiple commits
        let third_commit_id = test_repo.add_commit(
            "Third commit",
            "another_feature.rs",
            "// Another feature implementation\npub fn another_feature() {}\n",
        );

        let range = format!("{}..{}", test_repo.first_commit_id(), third_commit_id);
        let spec = parser.parse_commits(&range).await.unwrap();
        let diffs = parser.generate_diffs(spec).await.unwrap();

        // Should get 2 diffs: second commit and third commit
        assert_eq!(diffs.len(), 2);

        for diff in &diffs {
            assert!(!diff.files().is_empty());
        }

        // Verify files from both commits are present
        let all_files: Vec<&str> = diffs
            .iter()
            .flat_map(|d| {
                d.files()
                    .iter()
                    .map(|f| f.new_path().unwrap().to_str().unwrap())
            })
            .collect();

        assert!(all_files.contains(&"main.rs"));
        assert!(all_files.contains(&"new_feature.rs"));
        assert!(all_files.contains(&"old_module.rs"));
        assert!(all_files.contains(&"another_feature.rs"));
    }

    #[tokio::test]
    async fn test_generate_diff_concurrent_generation() {
        let (test_repo, parser) = setup_parser().await;

        // Test concurrent diff generation for different CommitSpec types
        let single_spec_future = async {
            let spec = parser.parse_commits("HEAD").await.unwrap();
            parser.generate_diffs(spec).await
        };

        let multi_spec_future = async {
            let commits_str = format!(
                "{} {}",
                test_repo.first_commit_id(),
                test_repo.second_commit_id()
            );
            let spec = parser.parse_commits(&commits_str).await.unwrap();
            parser.generate_diffs(spec).await
        };

        let range_spec_future = async {
            let range = format!(
                "{}..{}",
                test_repo.first_commit_id(),
                test_repo.second_commit_id()
            );
            let spec = parser.parse_commits(&range).await.unwrap();
            parser.generate_diffs(spec).await
        };

        let (single_result, multi_result, range_result) =
            futures::future::join3(single_spec_future, multi_spec_future, range_spec_future).await;

        // All should succeed
        assert!(single_result.is_ok());
        assert!(multi_result.is_ok());
        assert!(range_result.is_ok());

        let single_diffs = single_result.unwrap();
        let multi_diffs = multi_result.unwrap();
        let range_diffs = range_result.unwrap();

        assert_eq!(single_diffs.len(), 1);
        assert_eq!(multi_diffs.len(), 2);
        assert_eq!(range_diffs.len(), 1);
    }
}
