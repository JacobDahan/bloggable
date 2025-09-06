use std::path::PathBuf;

use tracing::debug;

use crate::git::commit::CommitInfo;
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

    /// Resolve a commit-ish reference to a `CommitInfo` object.
    /// The input can be any valid Git reference (branch names, tags, OIDs, etc.).
    /// If the commit is found, it is returned as a `CommitInfo` object.
    /// Otherwise, an error is returned.
    ///
    /// The ID of the `CommitInfo` object will be a string that uniquely identifies the
    /// commit-ish item, such as a commit hash, tag name, or branch name.
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
    pub async fn resolve_commit(&self, commit: &str) -> RepositoryResult<CommitInfo> {
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

                Ok(commit_info)
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
    /// # use bloggable::git::commit::CommitInfo;
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
    /// let ancestor = CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap();
    /// let descendant = CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap();
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
    /// # use bloggable::git::commit::CommitInfo;
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
    /// let ancestor = CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap();
    /// let descendant = CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap();
    ///
    /// // Reverse check: descendant is NOT ancestor of ancestor
    /// let is_ancestor = repo.is_ancestor(&descendant, &ancestor).await.unwrap();
    /// assert!(!is_ancestor);
    /// # });
    /// ```
    pub async fn is_ancestor(
        &self,
        ancestor: &CommitInfo,
        descendant: &CommitInfo,
    ) -> RepositoryResult<bool> {
        match self {
            Repository::Local { repo, .. } => {
                let ancestor_oid = git2::Oid::from_str(ancestor.id()).map_err(|_| {
                    RepositoryError::InvalidCommittish {
                        committish: ancestor.id().into(),
                        reason: "Invalid commit-ish format".into(),
                    }
                })?;

                let descendant_oid = git2::Oid::from_str(descendant.id()).map_err(|_| {
                    RepositoryError::InvalidCommittish {
                        committish: descendant.id().into(),
                        reason: "Invalid commit-ish format".into(),
                    }
                })?;

                Ok(repo.graph_descendant_of(descendant_oid, ancestor_oid)?)
            }
        }
    }

    /// Walk the commit history from `from` to `to`, returning all commits in between.
    /// The direction of the walk is from `from` to `to`, meaning that `from` should be an ancestor of `to`.
    /// The `from` commit will not be included in the returned list.
    /// If a commit is not found, an internal error will be returned.
    ///
    /// # Examples
    ///
    /// Walking commits in a range A..C where A --> B --> C:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::CommitInfo;
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
    /// # let third_commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Third commit",
    /// #     &tree,
    /// #     &[&git.find_commit(second_commit).unwrap()],
    /// # ).unwrap();
    /// let repo = Repository::try_local(git.path().into()).await.unwrap();
    /// let from = CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap();
    /// let to = CommitInfo::try_from(git.find_commit(third_commit).unwrap()).unwrap();
    /// let commits = repo.walk_range(&from, &to).await.unwrap();
    /// assert_eq!(commits.len(), 2);
    /// assert_eq!(commits[0].id(), second_commit.to_string());
    /// assert_eq!(commits[1].id(), third_commit.to_string());
    /// # });
    /// ```
    ///
    /// Walking commits in a range A..C where A --> C:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::CommitInfo;
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
    /// let repo = Repository::try_local(git.path().into()).await.unwrap();
    /// let from = CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap();
    /// let to = CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap();
    /// let commits = repo.walk_range(&from, &to).await.unwrap();
    /// assert_eq!(commits.len(), 1);
    /// assert_eq!(commits[0].id(), second_commit.to_string());
    /// # });
    /// ```
    ///
    /// Walking commits in a range C..A where A --> C:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::CommitInfo;
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
    /// let repo = Repository::try_local(git.path().into()).await.unwrap();
    /// let from = CommitInfo::try_from(git.find_commit(second_commit).unwrap()).unwrap();
    /// let to = CommitInfo::try_from(git.find_commit(first_commit).unwrap()).unwrap();
    /// let commits = repo.walk_range(&from, &to).await.unwrap();
    /// assert_eq!(commits.len(), 0);
    /// # });
    /// ```
    pub async fn walk_range(
        &self,
        from: &CommitInfo,
        to: &CommitInfo,
    ) -> RepositoryResult<Vec<CommitInfo>> {
        match self {
            Repository::Local { repo, .. } => {
                let mut revwalk = repo.revwalk()?;
                let from_oid = git2::Oid::from_str(from.id())?;

                let to_oid = git2::Oid::from_str(to.id())?;

                // Mark the 'to' commit as the start of the walk
                revwalk.push(to_oid)?;

                // Mark the 'from' commit as hidden, or the end of the walk
                revwalk.hide(from_oid)?;

                // Set the revwalk order to walk from 'from' to 'to'
                revwalk.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)?;

                let mut commits = Vec::new();
                for oid_result in revwalk {
                    let oid = oid_result?;
                    let commit = repo.find_commit(oid)?;
                    let commit_info = CommitInfo::try_from(commit).map_err(|e| {
                        RepositoryError::Internal(format!("Commit conversion error: {}", e))
                    })?;
                    commits.push(commit_info);
                }

                Ok(commits)
            }
        }
    }

    /// Generate a diff for a given commit.
    /// If the commit has no parents (e.g., initial commit), the diff is against an empty tree.
    ///
    /// # Examples
    /// ```
    /// # tokio_test::block_on(async {
    /// # use bloggable::git::repository::Repository;
    /// # use bloggable::git::commit::CommitInfo;
    /// # use bloggable::git::diff::Diff;
    /// # use std::path::PathBuf;
    /// # use std::fs;
    /// # let dir = tempfile::tempdir().unwrap();
    /// # let git = git2::Repository::init(dir.path()).unwrap();
    /// # let sig = git2::Signature::now("Test", "test@example.com").unwrap();
    /// # fs::write(dir.path().join("new_file.txt"), "Hello\nWorld\n").unwrap();
    /// # let mut index = git.index().unwrap();
    /// # index.add_path(std::path::Path::new("new_file.txt")).unwrap();
    /// # index.write().unwrap();
    /// # let tree_id = index.write_tree().unwrap();
    /// # let tree = git.find_tree(tree_id).unwrap();
    /// # let commit = git.commit(
    /// #     Some("HEAD"),
    /// #     &sig,
    /// #     &sig,
    /// #     "Initial commit",
    /// #     &tree,
    /// #     &[],
    /// # ).unwrap();
    /// let commit = CommitInfo::try_from(git.find_commit(commit).unwrap()).unwrap();
    /// let repo = Repository::try_local(dir.path().into()).await.unwrap();
    /// let diff = repo.generate_diff(&commit).await;
    /// assert!(diff.is_ok());
    /// assert!(diff.unwrap().added_files().next().is_some_and(|f| f.new_path() == Some(&"new_file.txt".into())));
    /// # })
    /// ```
    pub async fn generate_diff(&self, commit: &CommitInfo) -> RepositoryResult<Diff> {
        match self {
            Repository::Local { repo, .. } => {
                // Re-fetch the commit and get trees
                let oid = git2::Oid::from_str(commit.id())?;
                let git_commit = repo.find_commit(oid)?;
                let commit_tree = git_commit.tree()?;

                // TODO: Consider handling multi-parent commits more gracefully.
                // For now, we'll just use the first parent.
                let parent_tree = if git_commit.parent_count() > 0 {
                    Some(git_commit.parent(0)?.tree()?)
                } else {
                    None
                };

                // Generate git2 diff
                let git_diff =
                    repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&commit_tree), None)?;

                // Convert to our structured Diff type
                let diff = Diff::from_git_diff(commit.clone(), git_diff).map_err(|e| {
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
    async fn test_open_local_repository() {
        let test_repo = TestRepo::new().await;
        let repo_path = test_repo._temp_dir.path().to_path_buf();
        let repo = Repository::try_local(repo_path).await;
        assert!(repo.is_ok());
    }

    #[tokio::test]
    async fn test_open_nonexistent_repository() {
        let repo = Repository::try_local(PathBuf::from("/path/to/nonexistent/repo")).await;
        assert!(repo.is_err());
    }

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
    async fn test_resolve_commit_by_tag() {
        let test_repo = TestRepo::new().await;

        // v1.0 should resolve to the first commit
        let commit = test_repo.repo.resolve_commit("v1.0").await.unwrap();
        assert_eq!(commit.id(), test_repo.first_commit_id());

        // v2.0 should resolve to the second commit
        let commit = test_repo.repo.resolve_commit("v2.0").await.unwrap();
        assert_eq!(commit.id(), test_repo.second_commit_id());
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
    async fn test_walk_range_distant_commits() {
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

        let third_commit_id = test_repo.add_commit(
            "Third Commit",
            "sweet_was_the_walk.txt",
            "Sweet was the walk along the narrow lane",
        );

        let third_commit = test_repo
            .repo
            .resolve_commit(&third_commit_id.to_string())
            .await
            .unwrap();

        let commits = test_repo
            .repo
            .walk_range(&first_commit, &third_commit)
            .await
            .unwrap();

        // The `from` commit should not be included, leaving
        // us with the second and third commits.
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].id(), second_commit.id());
        assert_eq!(commits[1].id(), third_commit.id());
    }

    #[tokio::test]
    async fn test_walk_range_adjacent_commits() {
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

        let commits = test_repo
            .repo
            .walk_range(&first_commit, &second_commit)
            .await
            .unwrap();

        // Again, the `from` commit should not be included
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].id(), second_commit.id());
    }

    #[tokio::test]
    async fn test_walk_range_misordered() {
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

        let commits = test_repo
            .repo
            .walk_range(&second_commit, &first_commit)
            .await
            .unwrap();

        // Range A..B means "all commits reachable from B but not from A."
        // If B is a child of A, then no commits should match this definition.
        assert_eq!(commits.len(), 0);
    }

    #[tokio::test]
    async fn test_walk_range_same_commit() {
        let test_repo = TestRepo::new().await;

        let first_commit = test_repo
            .repo
            .resolve_commit(&test_repo.first_commit_id())
            .await
            .unwrap();

        let commits = test_repo
            .repo
            .walk_range(&first_commit, &first_commit)
            .await
            .unwrap();

        // A commit should not be considered in the range to itself
        assert_eq!(commits.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_diff_between_commits() {
        let test_repo = TestRepo::new().await;

        let second_commit = CommitInfo::new(
            test_repo.second_commit_id(),
            "Second commit with changes".to_string(),
        );

        // Generate the diff of the second commit
        let diff = test_repo.repo.generate_diff(&second_commit).await.unwrap();

        // Should have the expected file changes
        assert_eq!(diff.stats().files_changed(), 3); // main.rs, old_module.rs, new_feature.rs
        assert!(diff.stats().insertions() > 0);
        assert!(diff.stats().deletions() > 0);

        // Check specific file changes
        let added_files: Vec<_> = diff.added_files().collect();
        assert_eq!(added_files.len(), 1);
        assert_eq!(
            added_files[0].new_path().unwrap(),
            &PathBuf::from("new_feature.rs")
        );

        let deleted_files: Vec<_> = diff.deleted_files().collect();
        assert_eq!(deleted_files.len(), 1);
        assert_eq!(
            deleted_files[0].old_path().unwrap(),
            &PathBuf::from("old_module.rs")
        );

        let modified_files: Vec<_> = diff.modified_files().collect();
        assert_eq!(modified_files.len(), 1);
        assert_eq!(
            modified_files[0].new_path().unwrap(),
            &PathBuf::from("main.rs")
        );
    }

    #[tokio::test]
    async fn test_generate_diff_initial_commit() {
        let test_repo = TestRepo::new().await;

        let first_commit =
            CommitInfo::new(test_repo.first_commit_id(), "Initial commit".to_string());

        // The first commit should have a diff against empty tree
        let diff = test_repo.repo.generate_diff(&first_commit).await.unwrap();

        // All files in initial commit should appear as additions
        assert_eq!(diff.stats().files_changed(), 3); // main.rs, utils.rs, old_module.rs
        assert_eq!(diff.stats().deletions(), 0); // No deletions in initial commit
        assert!(diff.stats().insertions() > 0);

        let added_files: Vec<_> = diff.added_files().collect();
        assert_eq!(added_files.len(), 3);

        let file_names: Vec<_> = added_files
            .iter()
            .map(|f| f.new_path().unwrap().to_str())
            .collect();
        assert!(file_names.contains(&Some("main.rs")));
        assert!(file_names.contains(&Some("utils.rs")));
        assert!(file_names.contains(&Some("old_module.rs")));
    }
}
