use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("Failed to convert git2::Commit to CommitInfo")]
    Git2ConversionError,
}

/// Metadata about a Git commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    id: String,
    message: String,
    timestamp: i64,
}

impl CommitInfo {
    /// Create a new CommitInfo instance.
    pub fn new(id: String, message: String, timestamp: i64) -> Self {
        CommitInfo { id, message, timestamp }
    }

    /// Get the commit ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the commit message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the commit timestamp (Unix timestamp in seconds).
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

impl PartialOrd for CommitInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CommitInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort by timestamp (chronological order)
        self.timestamp.cmp(&other.timestamp)
    }
}

/// Convert a git2::Commit to bloggable::git::CommitInfo
impl TryFrom<git2::Commit<'_>> for CommitInfo {
    type Error = CommitError;

    /// Attempt to convert a git2::Commit into a CommitInfo.
    /// Returns an error if the conversion fails.
    ///
    /// # Examples
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use std::path::PathBuf;
    /// #     use git2::Repository;
    /// #     use bloggable::git::commit::CommitInfo;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    ///     let commit_id = git.commit(
    ///         Some("HEAD"),
    ///         &sig,
    ///         &sig,
    ///         "Initial commit",
    ///         &tree,
    ///         &[],
    ///     ).unwrap();
    ///     let commit = git.find_commit(commit_id).unwrap();
    ///     let commit_info = CommitInfo::try_from(commit).unwrap();
    ///     assert_eq!(commit_info.id(), &commit_id.to_string());
    ///     assert_eq!(commit_info.message(), "Initial commit");
    /// # });
    /// ```
    fn try_from(commit: git2::Commit) -> Result<CommitInfo, Self::Error> {
        let id = commit.id().to_string();
        let message = commit
            .message()
            .ok_or(CommitError::Git2ConversionError)?
            .to_string();
        let timestamp = commit.time().seconds();

        Ok(CommitInfo { id, message, timestamp })
    }
}

/// Specification for commits to process.
///
/// This enum separates commit identification from diff generation,
/// allowing for proper range handling and lazy diff computation.
/// It supports single commits, multiple commits, and commit ranges.
#[derive(Debug)]
pub enum CommitSpec {
    /// A single commit identified by its metadata
    Single(CommitInfo),
    /// Multiple explicitly specified commits
    Multiple(Vec<CommitInfo>),
    /// A range of commits from one point to another (e.g., "A..B")
    /// The actual commits in the range are computed lazily during diff generation
    Range { from: CommitInfo, to: CommitInfo },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_info_chronological_ordering() {
        let older_commit = CommitInfo::new(
            "abc123".to_string(),
            "Older commit".to_string(),
            1000,
        );
        let newer_commit = CommitInfo::new(
            "def456".to_string(),
            "Newer commit".to_string(),
            2000,
        );

        // Test ordering
        assert!(older_commit < newer_commit);
        assert!(newer_commit > older_commit);

        // Test sorting
        let mut commits = vec![newer_commit.clone(), older_commit.clone()];
        commits.sort();
        assert_eq!(commits[0], older_commit);
        assert_eq!(commits[1], newer_commit);
    }
}
