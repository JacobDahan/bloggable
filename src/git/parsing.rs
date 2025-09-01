use crate::git::commit::{Commit, CommitSpec};
use crate::git::repository::Repository;
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

    /// Parse a single commit-ish reference to a `CommitSpec::Single`.
    /// This will resolve the commit-ish to a full commit object,
    /// if a valid commit is found. Otherwise, an error is returned.
    /// The input can be any valid Git reference (branch name, tag, OID, etc.).
    async fn parse_single(&self, commit: &str) -> ParseResult<CommitSpec> {
        let mut resolved_commits = self.resolve_commits(vec![commit]).await?;

        let commit = resolved_commits.pop().ok_or(ParseError::Internal(
            "This should never happen: resolved_commits is empty after successful resolution"
                .into(),
        ))?;

        Ok(CommitSpec::Single(commit))
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

        let resolved_commits = self.resolve_commits(parts).await?;

        let (from, to) = match resolved_commits.len() {
            2 => (resolved_commits[0].clone(), resolved_commits[1].clone()),
            n => {
                return Err(ParseError::Internal(format!(
                    "This should never happen: expected 2 commits, got {}",
                    n
                )));
            }
        };

        let repository = self.repository.read().await;

        match repository.is_ancestor(&from, &to).await {
            Ok(is_ancestor) if is_ancestor => Ok(CommitSpec::Range { from, to }),
            Ok(_) => Err(ParseError::InvalidFormat {
                commits: commits.to_string(),
                reason: format!(
                    "Invalid commit range: '{}' is not an ancestor of '{}'",
                    from.info().id(),
                    to.info().id()
                ),
            }),
            Err(e) => {
                // At this point, we've already resolved both commits,
                // so any error here is unexpected.
                Err(ParseError::Internal(format!(
                    "Failed to verify commit ancestry: {}",
                    e
                )))
            }
        }
    }

    /// Parse multiple commit-ish references to a `CommitSpec::Multiple`.
    /// The input can be any number of valid Git references separated by whitespace.
    /// This will resolve the commit-ish references to full commit objects,
    /// if valid commits are found. Otherwise, an error is returned.
    /// The input can be any valid Git references (branch names, tags, OIDs, etc.).
    async fn parse_multi(&self, commits: &str) -> ParseResult<CommitSpec> {
        let commit_ids: Vec<&str> = commits.split_whitespace().collect();
        let resolved_commits = self.resolve_commits(commit_ids).await?;

        Ok(CommitSpec::Multiple(resolved_commits))
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

    /// Resolve a list of commit IDs to their full commit objects.
    /// This method will attempt to resolve all commits concurrently.
    /// If any commit cannot be resolved, an error will be returned indicating
    /// which specific commits failed to resolve.
    async fn resolve_commits(&self, commits: Vec<&str>) -> ParseResult<Vec<Commit>> {
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
                Ok(commit) => successes.push(commit),
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
    use std::sync::Arc;
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
}
