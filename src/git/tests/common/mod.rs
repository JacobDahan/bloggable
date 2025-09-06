use std::fs;
use tempfile::TempDir;

use crate::git::commit::CommitInfo;
use crate::git::diff::Diff;
use crate::git::repository::Repository;

pub struct TestRepo {
    pub _temp_dir: TempDir,
    pub git_repo: git2::Repository,
    pub repo: Repository,
    pub first_commit_id: git2::Oid,
    pub second_commit_id: git2::Oid,
}

impl TestRepo {
    /// Creates a test repository with realistic Rust files and two commits.
    ///
    /// First commit contains:
    /// - main.rs (v1)
    /// - utils.rs  
    /// - old_module.rs
    ///
    /// Second commit contains:
    /// - main.rs (v2, modified)
    /// - utils.rs (unchanged)
    /// - new_feature.rs (added)
    /// - old_module.rs (deleted)
    ///
    /// This setup provides comprehensive test scenarios for:
    /// - Modified files
    /// - Added files  
    /// - Deleted files
    /// - Unchanged files
    /// - Multiple hunks with Rust context
    pub async fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let git_repo = git2::Repository::init(temp_dir.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // Get the path to test data files (src/git/tests/data/)
        let test_data_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("git")
            .join("tests")
            .join("data");

        // Read test files
        let main_v1 = fs::read_to_string(test_data_dir.join("main_v1.rs"))
            .expect("Failed to read main_v1.rs");
        let main_v2 = fs::read_to_string(test_data_dir.join("main_v2.rs"))
            .expect("Failed to read main_v2.rs");
        let utils_content =
            fs::read_to_string(test_data_dir.join("utils.rs")).expect("Failed to read utils.rs");
        let old_module_content = fs::read_to_string(test_data_dir.join("old_module.rs"))
            .expect("Failed to read old_module.rs");
        let new_feature_content = fs::read_to_string(test_data_dir.join("new_feature.rs"))
            .expect("Failed to read new_feature.rs");

        // Create initial commit with multiple Rust files
        fs::write(temp_dir.path().join("main.rs"), &main_v1).unwrap();
        fs::write(temp_dir.path().join("utils.rs"), &utils_content).unwrap();
        fs::write(temp_dir.path().join("old_module.rs"), &old_module_content).unwrap();

        let mut index = git_repo.index().unwrap();
        index.add_path(std::path::Path::new("main.rs")).unwrap();
        index.add_path(std::path::Path::new("utils.rs")).unwrap();
        index
            .add_path(std::path::Path::new("old_module.rs"))
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let first_commit_id = {
            let tree = git_repo.find_tree(tree_id).unwrap();
            git_repo
                .commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
                .unwrap()
        };
        {
            let first_commit_obj = git_repo.find_commit(first_commit_id).unwrap();
            // Tag the first commit as v1.0
            git_repo
                .tag(
                    "v1.0",
                    &first_commit_obj.as_object(),
                    &sig,
                    "Version 1.0",
                    false,
                )
                .unwrap();
        }

        // Create second commit with modifications
        // 1. Modify main.rs
        fs::write(temp_dir.path().join("main.rs"), &main_v2).unwrap();
        // 2. Delete old_module.rs
        fs::remove_file(temp_dir.path().join("old_module.rs")).unwrap();
        // 3. Add new_feature.rs
        fs::write(temp_dir.path().join("new_feature.rs"), &new_feature_content).unwrap();

        index.add_path(std::path::Path::new("main.rs")).unwrap();
        index
            .add_path(std::path::Path::new("new_feature.rs"))
            .unwrap();
        index
            .remove_path(std::path::Path::new("old_module.rs"))
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let second_commit_id = {
            let tree = git_repo.find_tree(tree_id).unwrap();
            let first_commit_obj = git_repo.find_commit(first_commit_id).unwrap();
            git_repo
                .commit(
                    Some("HEAD"),
                    &sig,
                    &sig,
                    "Second commit with changes",
                    &tree,
                    &[&first_commit_obj],
                )
                .unwrap()
        };
        {
            let second_commit_obj = git_repo.find_commit(second_commit_id).unwrap();
            // Tag the second commit as v2.0
            git_repo
                .tag(
                    "v2.0",
                    &second_commit_obj.as_object(),
                    &sig,
                    "Version 2.0",
                    false,
                )
                .unwrap();
        }

        // Create our Repository wrapper
        let repo = Repository::try_local(temp_dir.path().into()).await.unwrap();

        Self {
            _temp_dir: temp_dir,
            git_repo,
            repo,
            first_commit_id,
            second_commit_id,
        }
    }

    /// Create a diff between the first and second commit
    pub fn create_diff(&self) -> Diff {
        let commit1 = self.git_repo.find_commit(self.first_commit_id).unwrap();
        let commit2 = self.git_repo.find_commit(self.second_commit_id).unwrap();
        let tree1 = commit1.tree().unwrap();
        let tree2 = commit2.tree().unwrap();

        let git_diff = self
            .git_repo
            .diff_tree_to_tree(Some(&tree1), Some(&tree2), None)
            .expect("Failed to create git diff");

        // Create CommitInfo for the second commit (the one we're diffing to)
        let commit_info = CommitInfo::new(
            self.second_commit_id.to_string(),
            commit2.message().unwrap_or("").to_string(),
        );

        Diff::from_git_diff(commit_info, git_diff).expect("Failed to convert git2::Diff to Diff")
    }

    /// Get the first commit ID as a string
    pub fn first_commit_id(&self) -> String {
        self.first_commit_id.to_string()
    }

    /// Get the second commit ID as a string  
    pub fn second_commit_id(&self) -> String {
        self.second_commit_id.to_string()
    }

    /// Helper to add a simple commit for additional test scenarios
    pub fn add_commit(&self, message: &str, file_name: &str, content: &str) -> git2::Oid {
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        fs::write(self._temp_dir.path().join(file_name), content).unwrap();

        let mut index = self.git_repo.index().unwrap();
        index.add_path(std::path::Path::new(file_name)).unwrap();
        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = self.git_repo.find_tree(tree_id).unwrap();

        let head = self.git_repo.head().unwrap();
        let head_commit = head.peel_to_commit().unwrap();

        self.git_repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &[&head_commit])
            .unwrap()
    }
}
