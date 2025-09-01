use tracing::error;

use crate::git::diff::Diff;

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("Failed to convert git2::Commit to Commit")]
    Git2ConversionError,
}

/// Representation of a Git [commit][1].
///
/// The `Commit` struct may represent commits or references from different sources,
/// such as local repositories or remote services like GitHub.
///
/// The `Commit` struct encapsulates essential information about a Git commit,
/// including its ID, message, and diff.
///
/// The ID is a string that uniquely identifies the commit object.
///
/// [1]: http://git-scm.com/book/en/Git-Internals-Git-Objects
#[derive(Debug, Clone)]
pub struct Commit {
    info: CommitInfo,
    diff: Diff,
}

impl Commit {
    /// Create a new `Commit` instance.
    pub fn new(info: CommitInfo, diff: Diff) -> Self {
        Commit { info, diff }
    }

    /// Get the commit metadata.
    pub fn info(&self) -> &CommitInfo {
        &self.info
    }

    /// Get the structured diff of the commit.
    pub fn diff(&self) -> &Diff {
        &self.diff
    }

    /// Get the commit ID (convenience method).
    pub fn id(&self) -> &str {
        self.info.id()
    }
}

/// Metadata about a Git commit.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    id: String,
    message: String,
}

impl CommitInfo {
    /// Get the commit ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the commit message.
    pub fn message(&self) -> &str {
        &self.message
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

        Ok(CommitInfo { id, message })
    }
}

/// Specification of commits to process.
///
/// This enum represents different ways to specify commits,
/// including a single commit, multiple commits, or a range of commits.
#[derive(Debug)]
pub enum CommitSpec {
    Single(Commit),
    Multiple(Vec<Commit>),
    Range { from: Commit, to: Commit },
}
