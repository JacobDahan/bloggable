use std::path::PathBuf;

use tracing::debug;

use crate::git::commit::{Commit, CommitInfo};
use crate::git::diff::Diff;

/// Alias for Result type used throughout the repository module.
type RepositoryResult<T> = Result<T, RepositoryError>;

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Local repository not found at path: {path}")]
    LocalNotFound { path: String },
    #[error("Invalid commit-ish '{committish}': {reason}")]
    InvalidCommittish { committish: String, reason: String },
    #[error("Unexpected error: {0}")]
    Internal(String),
}

impl From<git2::Error> for RepositoryError {
    fn from(err: git2::Error) -> Self {
        RepositoryError::Internal(err.to_string())
    }
}

/// Representation of a code repository.
///
/// A strong invariant is that no `Repository` should exist
/// without a backing repository that has been validated to exist.
pub enum Repository {
    Local {
        path: PathBuf,
        repo: git2::Repository,
    },
    // TODO: Add support for remote repositories
    // GitHub { },
    // GitLab { },
}

impl Repository {
    /// Instantiate a local repository after validating its existence.
    /// Returns an error if the repository does not exist or is not a valid Git repository.
    ///
    /// # Examples
    ///
    /// Successfully loading an existing repository:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::repository::Repository;
    /// #     use std::path::PathBuf;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     assert!(matches!(repo, Repository::Local { .. }));
    /// # });
    /// ```
    ///
    /// Error when repository doesn't exist:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::repository::Repository;
    ///     let repo = Repository::try_local("/path/to/nonexistent/repo".into()).await;
    ///     assert!(repo.is_err());
    /// # });
    /// ```
    pub async fn try_local(path: PathBuf) -> RepositoryResult<Self> {
        // Validate the path is a Git repository
        // Note: We are intentionally generous here and allow discovery of parent directories
        //       that contain a .git folder, as this is common in Git workflows.
        //       In future implementations, we may want to enable stricter control over this behavior.
        let repo = match git2::Repository::discover(&path) {
            Ok(repo) => repo,
            Err(_) => {
                return Err(RepositoryError::LocalNotFound {
                    path: path.to_string_lossy().to_string(),
                });
            }
        };

        let repo_path = repo.path();
        debug!("Discovered Git repository at: {}", repo_path.display());

        // Make sure we store the discovered path, not the input path
        Ok(Repository::Local {
            path: repo_path.into(),
            repo,
        })
    }

    /// Resolve a commit-ish reference to a `Commit` object.
    /// The input can be any valid Git reference (branch names, tags, OIDs, etc.).
    /// If the commit is found, it is returned as a `Commit` object.
    /// Otherwise, an error is returned.
    /// The ID of the `Commit` object will be a string that uniquely identifies the commit-ish item,
    /// such as a OID hash for local commits or a SHA for GitHub commits.
    ///
    /// # Examples
    ///
    /// Resolving a commit by hash:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::repository::Repository;
    /// #     use std::path::PathBuf;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let commit_id = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Initial commit",
    /// #         &tree,
    /// #         &[],
    /// #     ).unwrap();
    /// #     
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     let commit = repo.resolve_commit(&commit_id.to_string()).await.unwrap();
    ///     assert_eq!(commit.id(), commit_id.to_string());
    /// # });
    /// ```
    ///
    /// Resolving HEAD reference:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::repository::Repository;
    /// #     use std::path::PathBuf;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// #     let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// #     let tree = git.find_tree(tree_id).unwrap();
    /// #     let commit_id = git.commit(
    /// #         Some("HEAD"),
    /// #         &sig,
    /// #         &sig,
    /// #         "Initial commit",
    /// #         &tree,
    /// #         &[],
    /// #     ).unwrap();
    /// #     
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     let head_commit = repo.resolve_commit("HEAD").await.unwrap();
    ///     assert_eq!(head_commit.id(), commit_id.to_string());
    /// # });
    /// ```
    ///
    /// Error when commit doesn't exist:
    /// ```
    /// # tokio_test::block_on(async {
    /// #     use bloggable::git::repository::Repository;
    /// #     use std::path::PathBuf;
    /// #     let dir = tempfile::tempdir().unwrap();
    /// #     let git = git2::Repository::init(dir.path()).unwrap();
    /// #     
    ///     let repo = Repository::try_local(git.path().into()).await.unwrap();
    ///     assert!(repo.resolve_commit("nonexistent").await.is_err());
    /// # });
    /// ```
    pub async fn resolve_commit(&self, commit: &str) -> RepositoryResult<Commit> {
        match self {
            Repository::Local { repo, .. } => {
                // First, resolve the commit-ish to an object
                // This handles branches, tags, and commit hashes
                let obj = repo.revparse_single(commit).map_err(|_| {
                    RepositoryError::InvalidCommittish {
                        committish: commit.into(),
                        reason: "No matching object found for commit-ish in repository".into(),
                    }
                })?;

                debug!("Resolved '{}' to object: {:?}", commit, obj);

                // Now, peel the object to a commit
                // This handles the "ish" case where the object is a tag or other reference
                let commit =
                    obj.peel_to_commit()
                        .map_err(|_| RepositoryError::InvalidCommittish {
                            committish: commit.into(),
                            reason: "Commit-ish cannot be resolved to a commit".into(),
                        })?;

                // Convert git2::Commit to our CommitInfo struct
                // This conversion should not fail as we've already validated the commit exists
                let commit_info = CommitInfo::try_from(commit).map_err(|e| {
                    RepositoryError::Internal(format!("Commit conversion error: {}", e))
                })?;

                // Generate a diff for the commit
                let diff = self.generate_diff(&commit_info).map_err(|e| {
                    RepositoryError::Internal(format!("Diff generation error: {}", e))
                })?;

                debug!("Generated diff for commit '{}'", commit_info.id());

                Ok(Commit::new(commit_info, diff))
            }
        }
    }

    /// Check if one commit is an ancestor of another.
    /// If either commit is not found, an error is returned.
    ///
    /// # Examples
    ///
    /// Checking ancestor relationship (true case):
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::{Commit, CommitInfo};
    /// # use bloggable::git::diff::Diff;
    /// # use std::path::PathBuf;
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let git = git2::Repository::init(dir.path()).unwrap();
    /// # let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// # let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// # let tree = git.find_tree(tree_id).unwrap();
    /// # let first_commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Initial commit",
    /// #     &tree,
    /// #     &[],
    /// # ).unwrap();
    /// # let second_commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Second commit",
    /// #     &tree,
    /// #     &[&git.find_commit(first_commit).unwrap()],
    /// # ).unwrap();
    /// #
    /// let repo = Repository::try_local(git.path().into()).await.unwrap();
    /// let ancestor = Commit::new(
    ///     CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap(),
    ///     Diff::default(),
    /// );
    /// let descendant = Commit::new(
    ///     CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap(),
    ///     Diff::default(),
    /// );
    ///
    /// let is_ancestor = repo.is_ancestor(&ancestor, &descendant).await.unwrap();
    /// assert!(is_ancestor); // first_commit is ancestor of second_commit
    /// # });
    /// ```
    ///
    /// Checking ancestor relationship (false case):
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::{Commit, CommitInfo};
    /// # use bloggable::git::diff::Diff;
    /// # use std::path::PathBuf;
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let git = git2::Repository::init(dir.path()).unwrap();
    /// # let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// # let tree_id = git.treebuilder(None).unwrap().write().unwrap();
    /// # let tree = git.find_tree(tree_id).unwrap();
    /// # let first_commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Initial commit",
    /// #     &tree,
    /// #     &[],
    /// # ).unwrap();
    /// # let second_commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Second commit",
    /// #     &tree,
    /// #     &[&git.find_commit(first_commit).unwrap()],
    /// # ).unwrap();
    /// #
    /// let repo = Repository::try_local(git.path().into()).await.unwrap();
    /// let ancestor = Commit::new(
    ///     CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap(),
    ///     Diff::default(),
    /// );
    /// let descendant = Commit::new(
    ///     CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap(),
    ///     Diff::default(),
    /// );
    ///
    /// // Reverse check: descendant is NOT ancestor of ancestor
    /// let is_reverse = repo.is_ancestor(&descendant, &ancestor).await.unwrap();
    /// assert!(!is_reverse);
    /// # });
    /// ```
    pub async fn is_ancestor(
        &self,
        ancestor: &Commit,
        descendant: &Commit,
    ) -> RepositoryResult<bool> {
        match self {
            Repository::Local { repo, .. } => {
                let ancestor_oid = git2::Oid::from_str(ancestor.info().id()).map_err(|_| {
                    RepositoryError::InvalidCommittish {
                        committish: ancestor.info().id().into(),
                        reason: "Invalid commit-ish format".into(),
                    }
                })?;

                let descendant_oid = git2::Oid::from_str(descendant.info().id()).map_err(|_| {
                    RepositoryError::InvalidCommittish {
                        committish: descendant.info().id().into(),
                        reason: "Invalid commit-ish format".into(),
                    }
                })?;

                Ok(repo.graph_descendant_of(descendant_oid, ancestor_oid)?)
            }
        }
    }

    /// Generate a diff for a given commit.
    /// If the commit has no parents (e.g., initial commit), the diff is against an empty tree.
    fn generate_diff(&self, commit: &CommitInfo) -> RepositoryResult<Diff> {
        match self {
            Repository::Local { repo, .. } => {
                // Re-fetch the commit and get trees
                let oid = git2::Oid::from_str(commit.id())?;
                let commit = repo.find_commit(oid)?;
                let commit_tree = commit.tree()?;

                // Get parent tree if it exists
                let parent_tree = if commit.parent_count() > 0 {
                    Some(commit.parent(0)?.tree()?)
                } else {
                    None
                };

                // Generate git2 diff
                let git_diff =
                    repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&commit_tree), None)?;

                // Convert to our structured Diff type
                let diff = Diff::try_from(git_diff).map_err(|e| {
                    RepositoryError::Internal(format!(
                        "Failed to parse diff for commit '{}': {}",
                        commit.id(),
                        e
                    ))
                })?;

                Ok(diff)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::tests::common::TestRepo;

    #[tokio::test]
    async fn test_resolve_commit_by_hash() {
        let test_repo = TestRepo::new().await;

        // Test resolving by full commit hash
        let commit_id = test_repo.first_commit_id();
        let commit = test_repo.repo.resolve_commit(&commit_id).await.unwrap();
        assert_eq!(commit.id(), commit_id);

        // Test resolving by short hash (first 7 characters)
        let short_hash = &commit_id[..7];
        let commit = test_repo.repo.resolve_commit(short_hash).await.unwrap();
        assert_eq!(commit.id(), commit_id);
    }

    #[tokio::test]
    async fn test_resolve_commit_by_head() {
        let test_repo = TestRepo::new().await;

        // HEAD should resolve to the second commit (most recent)
        let commit = test_repo.repo.resolve_commit("HEAD").await.unwrap();
        assert_eq!(commit.id(), test_repo.second_commit_id());

        // HEAD~1 should resolve to the first commit
        let commit = test_repo.repo.resolve_commit("HEAD~1").await.unwrap();
        assert_eq!(commit.id(), test_repo.first_commit_id());
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_commit() {
        let test_repo = TestRepo::new().await;

        let result = test_repo.repo.resolve_commit("nonexistent").await;
        assert!(result.is_err());

        match result.unwrap_err() {
            RepositoryError::InvalidCommittish { committish, .. } => {
                assert_eq!(committish, "nonexistent");
            }
            _ => panic!("Expected InvalidCommittish error"),
        }
    }

    #[tokio::test]
    async fn test_is_ancestor() {
        let test_repo = TestRepo::new().await;

        let first_commit = test_repo
            .repo
            .resolve_commit(&test_repo.first_commit_id())
            .await
            .unwrap();
        let second_commit = test_repo
            .repo
            .resolve_commit(&test_repo.second_commit_id())
            .await
            .unwrap();

        // First commit should be ancestor of second commit
        let is_ancestor = test_repo
            .repo
            .is_ancestor(&first_commit, &second_commit)
            .await
            .unwrap();
        assert!(is_ancestor);

        // Second commit should NOT be ancestor of first commit
        let is_not_ancestor = test_repo
            .repo
            .is_ancestor(&second_commit, &first_commit)
            .await
            .unwrap();
        assert!(!is_not_ancestor);

        // A commit should NOT be considered an ancestor of itself in git2
        // (This follows git's behavior where `git merge-base --is-ancestor A A` returns false)
        let self_ancestor = test_repo
            .repo
            .is_ancestor(&first_commit, &first_commit)
            .await
            .unwrap();
        assert!(!self_ancestor);
    }

    #[tokio::test]
    async fn test_commit_includes_diff() {
        let test_repo = TestRepo::new().await;

        // Resolve the second commit and verify it includes the expected diff
        let commit = test_repo
            .repo
            .resolve_commit(&test_repo.second_commit_id())
            .await
            .unwrap();
        let diff = commit.diff();

        // Should have the expected file changes
        assert_eq!(diff.stats.files_changed, 3); // main.rs, old_module.rs, new_feature.rs
        assert!(diff.stats.insertions > 0);
        assert!(diff.stats.deletions > 0);

        // Check specific file changes
        let added_files: Vec<_> = diff.added_files().collect();
        assert_eq!(added_files.len(), 1);
        assert_eq!(added_files[0].new_path.as_ref().unwrap(), "new_feature.rs");

        let deleted_files: Vec<_> = diff.deleted_files().collect();
        assert_eq!(deleted_files.len(), 1);
        assert_eq!(deleted_files[0].old_path.as_ref().unwrap(), "old_module.rs");

        let modified_files: Vec<_> = diff.modified_files().collect();
        assert_eq!(modified_files.len(), 1);
        assert_eq!(modified_files[0].new_path.as_ref().unwrap(), "main.rs");
    }

    #[tokio::test]
    async fn test_initial_commit_diff() {
        let test_repo = TestRepo::new().await;

        // The first commit should have a diff against empty tree
        let commit = test_repo
            .repo
            .resolve_commit(&test_repo.first_commit_id())
            .await
            .unwrap();
        let diff = commit.diff();

        // All files in initial commit should appear as additions
        assert_eq!(diff.stats.files_changed, 3); // main.rs, utils.rs, old_module.rs
        assert_eq!(diff.stats.deletions, 0); // No deletions in initial commit
        assert!(diff.stats.insertions > 0);

        let added_files: Vec<_> = diff.added_files().collect();
        assert_eq!(added_files.len(), 3);

        let file_names: Vec<_> = added_files
            .iter()
            .map(|f| f.new_path.as_ref().unwrap().as_str())
            .collect();
        assert!(file_names.contains(&"main.rs"));
        assert!(file_names.contains(&"utils.rs"));
        assert!(file_names.contains(&"old_module.rs"));
    }
}
