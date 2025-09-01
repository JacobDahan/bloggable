use std::sync::LazyLock;
use tracing::warn;

static HUNK_HEADER_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"@@ -\d+,\d+ \+\d+,\d+ @@(.*)").unwrap());

#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("Failed to parse diff: {0}")]
    ParseError(String),
    #[error("Invalid UTF-8 in diff content: {0}")]
    Utf8Error(String),
}

/// Represents the type of change in a diff line
#[derive(Debug, Clone, PartialEq)]
pub enum LineType {
    /// Line was added (starts with '+')
    Addition,
    /// Line was removed (starts with '-')  
    Deletion,
    /// Line is context (starts with ' ')
    Context,
    /// Line is a header or other non-content line
    Other,
}

/// A single line within a diff hunk
#[derive(Debug, Clone)]
pub struct DiffLine {
    pub line_type: LineType,
    pub content: String,
    pub old_line_number: Option<u32>,
    pub new_line_number: Option<u32>,
}

/// A contiguous block of changes within a file
#[derive(Debug, Clone)]
pub struct DiffHunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub header: String,
    pub lines: Vec<DiffLine>,
}

/// Changes to a single file in the diff
#[derive(Debug, Clone)]
pub struct FileDiff {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub status: FileStatus,
    pub hunks: Vec<DiffHunk>,
}

/// The type of change applied to a file
#[derive(Debug, Clone, PartialEq)]
pub enum FileStatus {
    /// File was added
    Added,
    /// File was deleted
    Deleted,
    /// File was modified
    Modified,
    /// File was renamed
    Renamed,
    /// File was copied
    Copied,
}

/// A structured representation of a Git diff
#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub files: Vec<FileDiff>,
    pub stats: DiffStats,
}

/// Statistics about the changes in a diff
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
}

impl Diff {
    /// Get files that were added
    ///
    /// # Examples
    ///
    /// ```
    /// use bloggable::git::diff::{Diff, FileDiff, FileStatus, DiffStats};
    ///
    /// let diff = Diff {
    ///     files: vec![
    ///         FileDiff {
    ///             old_path: None,
    ///             new_path: Some("new_file.txt".to_string()),
    ///             status: FileStatus::Added,
    ///             hunks: vec![],
    ///         },
    ///         FileDiff {
    ///             old_path: Some("old_file.txt".to_string()),
    ///             new_path: Some("old_file.txt".to_string()),
    ///             status: FileStatus::Modified,
    ///             hunks: vec![],
    ///         },
    ///     ],
    ///     stats: DiffStats {
    ///         files_changed: 2,
    ///         insertions: 5,
    ///         deletions: 2,
    ///     },
    /// };
    ///
    /// let added_files: Vec<_> = diff.added_files().collect();
    /// assert_eq!(added_files.len(), 1);
    /// assert_eq!(added_files[0].new_path.as_ref().unwrap(), "new_file.txt");
    /// ```
    pub fn added_files(&self) -> impl Iterator<Item = &FileDiff> {
        self.files.iter().filter(|f| f.status == FileStatus::Added)
    }

    /// Get files that were deleted
    ///
    /// # Examples
    ///
    /// ```
    /// use bloggable::git::diff::{Diff, FileDiff, FileStatus, DiffStats};
    ///
    /// let diff = Diff {
    ///     files: vec![
    ///         FileDiff {
    ///             old_path: Some("deleted_file.txt".to_string()),
    ///             new_path: None,
    ///             status: FileStatus::Deleted,
    ///             hunks: vec![],
    ///         },
    ///         FileDiff {
    ///             old_path: Some("modified_file.txt".to_string()),
    ///             new_path: Some("modified_file.txt".to_string()),
    ///             status: FileStatus::Modified,
    ///             hunks: vec![],
    ///         },
    ///     ],
    ///     stats: DiffStats {
    ///         files_changed: 2,
    ///         insertions: 0,
    ///         deletions: 10,
    ///     },
    /// };
    ///
    /// let deleted_files: Vec<_> = diff.deleted_files().collect();
    /// assert_eq!(deleted_files.len(), 1);
    /// assert_eq!(deleted_files[0].old_path.as_ref().unwrap(), "deleted_file.txt");
    /// ```
    pub fn deleted_files(&self) -> impl Iterator<Item = &FileDiff> {
        self.files
            .iter()
            .filter(|f| f.status == FileStatus::Deleted)
    }

    /// Get files that were modified
    ///
    /// # Examples
    ///
    /// ```
    /// use bloggable::git::diff::{Diff, FileDiff, FileStatus, DiffStats};
    ///
    /// let diff = Diff {
    ///     files: vec![
    ///         FileDiff {
    ///             old_path: Some("file1.txt".to_string()),
    ///             new_path: Some("file1.txt".to_string()),
    ///             status: FileStatus::Modified,
    ///             hunks: vec![],
    ///         },
    ///         FileDiff {
    ///             old_path: None,
    ///             new_path: Some("file2.txt".to_string()),
    ///             status: FileStatus::Added,
    ///             hunks: vec![],
    ///         },
    ///         FileDiff {
    ///             old_path: Some("file3.txt".to_string()),
    ///             new_path: Some("file3.txt".to_string()),
    ///             status: FileStatus::Modified,
    ///             hunks: vec![],
    ///         },
    ///     ],
    ///     stats: DiffStats {
    ///         files_changed: 3,
    ///         insertions: 15,
    ///         deletions: 8,
    ///     },
    /// };
    ///
    /// let modified_files: Vec<_> = diff.modified_files().collect();
    /// assert_eq!(modified_files.len(), 2);
    /// assert_eq!(modified_files[0].new_path.as_ref().unwrap(), "file1.txt");
    /// assert_eq!(modified_files[1].new_path.as_ref().unwrap(), "file3.txt");
    /// ```
    pub fn modified_files(&self) -> impl Iterator<Item = &FileDiff> {
        self.files
            .iter()
            .filter(|f| f.status == FileStatus::Modified)
    }
}

/// Convert from git2::Diff to our structured Diff
///
/// # Examples
///
/// ```
/// use bloggable::git::diff::Diff;
/// use std::convert::TryFrom;
/// use std::fs;
///
/// # let dir = tempfile::tempdir().unwrap();
/// # let repo = git2::Repository::init(dir.path()).unwrap();
/// # let sig = git2::Signature::now("Test", "test@example.com").unwrap();
/// #
/// # // Create initial commit with a file
/// # fs::write(dir.path().join("file.txt"), "Hello\nWorld\n").unwrap();
/// # let mut index = repo.index().unwrap();
/// # index.add_path(std::path::Path::new("file.txt")).unwrap();
/// # index.write().unwrap();
/// # let tree_id = index.write_tree().unwrap();
/// # let tree = repo.find_tree(tree_id).unwrap();
/// # let first_commit = repo.commit(
/// #     Some("HEAD"),
/// #     &sig,
/// #     &sig,
/// #     "Initial commit",
/// #     &tree,
/// #     &[],
/// # ).unwrap();
/// #
/// # // Modify the file and create a second commit
/// # fs::write(dir.path().join("file.txt"), "Hello\nWorld\nFoo\n").unwrap();
/// # index.add_path(std::path::Path::new("file.txt")).unwrap();
/// # index.write().unwrap();
/// # let tree_id = index.write_tree().unwrap();
/// # let tree = repo.find_tree(tree_id).unwrap();
/// # let first_commit_obj = repo.find_commit(first_commit).unwrap();
/// # let second_commit = repo.commit(
/// #     Some("HEAD"),
/// #     &sig,
/// #     &sig,
/// #     "Add foo",
/// #     &tree,
/// #     &[&first_commit_obj],
/// # ).unwrap();
///
/// // Create a diff between the two commits
/// let commit1 = repo.find_commit(first_commit).unwrap();
/// let commit2 = repo.find_commit(second_commit).unwrap();
/// let tree1 = commit1.tree().unwrap();
/// let tree2 = commit2.tree().unwrap();
///
/// let git_diff = repo.diff_tree_to_tree(Some(&tree1), Some(&tree2), None)
///     .expect("Failed to create diff");
///
/// let diff = Diff::try_from(git_diff).expect("Failed to parse diff");
/// assert_eq!(diff.stats.files_changed, 1);
/// assert_eq!(diff.stats.insertions, 1);
/// assert_eq!(diff.stats.deletions, 0);
///
/// let modified_files: Vec<_> = diff.modified_files().collect();
/// assert_eq!(modified_files.len(), 1);
/// assert_eq!(modified_files[0].new_path.as_ref().unwrap(), "file.txt");
/// ```
impl<'a> TryFrom<git2::Diff<'a>> for Diff {
    type Error = DiffError;

    fn try_from(git_diff: git2::Diff<'a>) -> Result<Self, Self::Error> {
        let mut files: Vec<FileDiff> = Vec::new();
        // Since git iterates the diff via patches, we need to merge individual patches
        // by file to create our structured representation. Therefore, we need to keep
        // track of the current file being processed as well as its hunks.
        let mut current_file: Option<FileDiff> = None;
        let mut current_hunk: Option<DiffHunk> = None;

        git_diff
            .print(git2::DiffFormat::Patch, |delta, hunk, line| {
                // Early exit if we don't have a hunk (file headers, binary indicators, etc.)
                let Some(hunk) = hunk else {
                    return true;
                };

                let new_file_path = delta
                    .new_file()
                    .path()
                    .and_then(|p| p.to_str())
                    .map(String::from);
                let old_file_path = delta
                    .old_file()
                    .path()
                    .and_then(|p| p.to_str())
                    .map(String::from);

                // If we have moved on to a new file, save the previous one
                if let Some(ref mut cf) = current_file {
                    if cf.new_path != new_file_path || cf.old_path != old_file_path {
                        // First, save any current hunk as it belongs to the previous file
                        if let Some(hunk) = current_hunk.take() {
                            cf.hunks.push(hunk);
                        }

                        // Now, save the processed file diff
                        files.push(current_file.take().unwrap());
                    }
                }

                // Determine the file status
                let status = match delta.status() {
                    git2::Delta::Added => FileStatus::Added,
                    git2::Delta::Deleted => FileStatus::Deleted,
                    git2::Delta::Modified => FileStatus::Modified,
                    git2::Delta::Renamed => FileStatus::Renamed,
                    git2::Delta::Copied => FileStatus::Copied,
                    git2::Delta::Unmodified
                    | git2::Delta::Ignored
                    | git2::Delta::Untracked
                    | git2::Delta::Typechange
                    | git2::Delta::Unreadable
                    | git2::Delta::Conflicted => return true,
                };

                // If we have a current file but the status differs, return an error
                if let Some(file_diff) = &current_file {
                    if file_diff.status != status {
                        return false; // Inconsistent status for the same file
                    }
                }

                // If we don't have a current file, create one
                if current_file.is_none() {
                    current_file = Some(FileDiff {
                        old_path: old_file_path,
                        new_path: new_file_path,
                        status,
                        hunks: Vec::new(),
                    });
                }

                let current_file = current_file.as_mut().unwrap();

                // If we have moved on to a new hunk, save the previous one
                if let Some(ref mut ch) = current_hunk {
                    if ch.old_start != hunk.old_start()
                        || ch.new_start != hunk.new_start()
                        || ch.old_lines != hunk.old_lines()
                        || ch.new_lines != hunk.new_lines()
                    {
                        // Save the previous hunk to the current file
                        current_file.hunks.push(current_hunk.take().unwrap());
                    }
                }

                // If we don't have a current hunk, create one
                if current_hunk.is_none() {
                    let raw_header = match String::from_utf8(hunk.header().to_vec())
                        .map_err(|e| DiffError::Utf8Error(e.to_string()))
                    {
                        Ok(header) => header,
                        Err(e) => {
                            warn!("Failed to parse hunk header as UTF-8. Error: {}", e);
                            return false; // Failed to parse hunk header
                        }
                    };

                    // Extract just the context part (function/struct name) from the hunk header
                    // TODO: Consider making this more strict once we understand all edge cases
                    let header = if let Some(captures) = HUNK_HEADER_REGEX.captures(&raw_header) {
                        if let Some(matched) = captures.get(1) {
                            matched.as_str().trim().to_string()
                        } else {
                            // Empty context is valid (e.g., @@ -1,3 +1,3 @@)
                            String::new()
                        }
                    } else {
                        // Handle cases where header format doesn't match expected pattern
                        warn!(
                            "Hunk header format unexpected, using empty context: {}",
                            raw_header
                        );
                        String::new()
                    };

                    current_hunk = Some(DiffHunk {
                        old_start: hunk.old_start(),
                        old_lines: hunk.old_lines(),
                        new_start: hunk.new_start(),
                        new_lines: hunk.new_lines(),
                        header,
                        lines: Vec::new(),
                    });
                }

                // Finally, process the line...
                let line_content = match std::str::from_utf8(line.content()) {
                    Ok(content) => content.to_string(),
                    Err(e) => {
                        warn!("Failed to parse line content as UTF-8. Error: {}", e);
                        return false; // Failed to parse line content
                    }
                };

                let (line_type, old_line_number, new_line_number) =
                    match LineType::try_from(line.origin() as char) {
                        Ok(LineType::Addition) => (
                            LineType::Addition,
                            None,
                            Some(line.new_lineno().unwrap_or(0)),
                        ),
                        Ok(LineType::Deletion) => (
                            LineType::Deletion,
                            Some(line.old_lineno().unwrap_or(0)),
                            None,
                        ),
                        Ok(LineType::Context) => {
                            (LineType::Context, line.old_lineno(), line.new_lineno())
                        }
                        Ok(LineType::Other) => {
                            // Ignore other line types (including hunk headers)
                            return true;
                        }
                        Err(e) => {
                            warn!("Failed to parse line type. Error: {}", e);
                            return false; // Invalid line type character
                        }
                    };

                current_hunk.as_mut().unwrap().lines.push(DiffLine {
                    line_type,
                    content: line_content,
                    old_line_number,
                    new_line_number,
                });

                true
            })
            .map_err(|e| DiffError::ParseError(e.to_string()))?;

        // Save any remaining current hunk and file
        if let Some(ref mut cf) = current_file {
            if let Some(hunk) = current_hunk.take() {
                cf.hunks.push(hunk);
            }

            files.push(current_file.take().unwrap());
        }

        let stats = git_diff
            .stats()
            .map_err(|e| DiffError::ParseError(e.to_string()))
            .map(|stats| DiffStats {
                files_changed: stats.files_changed() as usize,
                insertions: stats.insertions() as usize,
                deletions: stats.deletions() as usize,
            })?;

        Ok(Diff { files, stats })
    }
}

/// Convert a character to a LineType
///
/// # Examples
///
/// ```
/// use bloggable::git::diff::LineType;
/// use std::convert::TryFrom;
///
/// assert_eq!(LineType::try_from('+').unwrap(), LineType::Addition);
/// assert_eq!(LineType::try_from('-').unwrap(), LineType::Deletion);
/// assert_eq!(LineType::try_from(' ').unwrap(), LineType::Context);
/// assert_eq!(LineType::try_from('=').unwrap(), LineType::Other);
///
/// assert!(LineType::try_from('x').is_err());
/// ```
impl<'a> TryFrom<char> for LineType {
    type Error = DiffError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        match c {
            '+' => Ok(LineType::Addition),
            '-' => Ok(LineType::Deletion),
            ' ' => Ok(LineType::Context),
            // These line types are not relevant for our purposes
            // and will be ignored in the diff processing.
            '>' | '<' | '=' | 'B' | 'F' | 'H' => Ok(LineType::Other),
            _ => Err(DiffError::ParseError(format!(
                "Invalid line type character: {}",
                c
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::tests::common::TestRepo;
    use std::convert::TryFrom;
    use std::fs;

    #[tokio::test]
    async fn test_diff_statistics() {
        let test_repo = TestRepo::new().await;
        let diff = test_repo.create_diff();

        // Test that statistics are correctly calculated
        assert_eq!(diff.stats.files_changed, 3); // main.rs, old_module.rs, new_feature.rs
        assert!(diff.stats.insertions > 0, "Should have insertions");
        assert!(diff.stats.deletions > 0, "Should have deletions");
    }

    #[tokio::test]
    async fn test_added_files() {
        let test_repo = TestRepo::new().await;
        let diff = test_repo.create_diff();

        let added_files: Vec<_> = diff.added_files().collect();
        assert_eq!(added_files.len(), 1);
        assert_eq!(added_files[0].new_path.as_ref().unwrap(), "new_feature.rs");
        assert_eq!(added_files[0].status, FileStatus::Added);

        // Verify the added file has proper content
        let added_file = &added_files[0];
        assert!(!added_file.hunks.is_empty(), "Added file should have hunks");

        // Check that we have addition lines in the hunk
        let hunk = &added_file.hunks[0];
        let additions: Vec<_> = hunk
            .lines
            .iter()
            .filter(|l| l.line_type == LineType::Addition)
            .collect();
        assert!(!additions.is_empty(), "Should have addition lines");

        // Check that we have no deletion lines in the hunk
        let deletions: Vec<_> = hunk
            .lines
            .iter()
            .filter(|l| l.line_type == LineType::Deletion)
            .collect();
        assert!(deletions.is_empty(), "Should have no deletion lines");

        // Check for specific content we expect in new_feature.rs
        let has_feature_manager = additions
            .iter()
            .any(|line| line.content.contains("pub struct FeatureManager"));
        assert!(
            has_feature_manager,
            "Should contain FeatureManager struct definition"
        );
    }

    #[tokio::test]
    async fn test_deleted_files() {
        let test_repo = TestRepo::new().await;
        let diff = test_repo.create_diff();

        let deleted_files: Vec<_> = diff.deleted_files().collect();
        assert_eq!(deleted_files.len(), 1);
        assert_eq!(deleted_files[0].old_path.as_ref().unwrap(), "old_module.rs");
        assert_eq!(deleted_files[0].status, FileStatus::Deleted);

        // Verify the deleted file has proper content
        let deleted_file = &deleted_files[0];
        assert!(
            !deleted_file.hunks.is_empty(),
            "Deleted file should have hunks"
        );

        // Check that we have deletion lines in the hunk
        let hunk = &deleted_file.hunks[0];
        let deletions: Vec<_> = hunk
            .lines
            .iter()
            .filter(|l| l.line_type == LineType::Deletion)
            .collect();
        assert!(!deletions.is_empty(), "Should have deletion lines");

        // Check that we have no addition lines in the hunk
        let additions: Vec<_> = hunk
            .lines
            .iter()
            .filter(|l| l.line_type == LineType::Addition)
            .collect();
        assert!(additions.is_empty(), "Should have no addition lines");

        // Check for specific content we expect from old_module.rs
        let has_old_struct = deletions
            .iter()
            .any(|line| line.content.contains("pub struct OldStruct"));
        assert!(
            has_old_struct,
            "Should contain OldStruct definition from deleted file"
        );
    }

    #[tokio::test]
    async fn test_modified_files() {
        let test_repo = TestRepo::new().await;
        let diff = test_repo.create_diff();

        let modified_files: Vec<_> = diff.modified_files().collect();
        assert_eq!(modified_files.len(), 1);
        assert_eq!(modified_files[0].new_path.as_ref().unwrap(), "main.rs");
        assert_eq!(modified_files[0].old_path.as_ref().unwrap(), "main.rs");
        assert_eq!(modified_files[0].status, FileStatus::Modified);

        // Test that hunks are properly parsed
        let modified_file = &modified_files[0];
        assert!(
            !modified_file.hunks.is_empty(),
            "Modified file should have hunks"
        );

        // Collect all lines across all hunks to verify we have the expected changes
        let all_additions: Vec<_> = modified_file
            .hunks
            .iter()
            .flat_map(|h| &h.lines)
            .filter(|l| l.line_type == LineType::Addition)
            .collect();
        let all_deletions: Vec<_> = modified_file
            .hunks
            .iter()
            .flat_map(|h| &h.lines)
            .filter(|l| l.line_type == LineType::Deletion)
            .collect();
        let all_context: Vec<_> = modified_file
            .hunks
            .iter()
            .flat_map(|h| &h.lines)
            .filter(|l| l.line_type == LineType::Context)
            .collect();

        assert!(
            !all_additions.is_empty(),
            "Should have addition lines across all hunks"
        );
        assert!(
            !all_deletions.is_empty(),
            "Should have deletion lines across all hunks"
        );
        assert!(
            !all_context.is_empty(),
            "Should have context lines across all hunks"
        );

        // Verify line numbers are correctly assigned across all hunks
        for hunk in &modified_file.hunks {
            for line in &hunk.lines {
                match line.line_type {
                    LineType::Addition => {
                        assert!(line.new_line_number.is_some());
                        assert!(line.old_line_number.is_none());
                    }
                    LineType::Deletion => {
                        assert!(line.old_line_number.is_some());
                        assert!(line.new_line_number.is_none());
                    }
                    LineType::Context => {
                        assert!(line.old_line_number.is_some());
                        assert!(line.new_line_number.is_some());
                    }
                    LineType::Other => {}
                }
            }
        }

        // Test specific changes we expect between main_v1.rs and main_v2.rs
        let has_stats_addition = all_additions
            .iter()
            .any(|line| line.content.contains("stats: ProcessingStats"));
        assert!(
            has_stats_addition,
            "Should add stats field to DataProcessor"
        );

        let has_case_change = all_deletions
            .iter()
            .any(|line| line.content.contains("to_uppercase"))
            && all_additions
                .iter()
                .any(|line| line.content.contains("to_lowercase"));
        assert!(
            has_case_change,
            "Should change from to_uppercase to to_lowercase"
        );
    }

    #[tokio::test]
    async fn test_hunk_headers_with_rust_context() {
        let test_repo = TestRepo::new().await;
        let diff = test_repo.create_diff();

        // Find the modified file (main.rs)
        let modified_files: Vec<_> = diff.modified_files().collect();
        assert_eq!(modified_files.len(), 1);
        let modified_file = &modified_files[0];

        // Check that hunks have meaningful headers from Rust context
        // The first hunk may not have context if it starts at the top of the file
        modified_file.hunks.iter().skip(1).for_each(|hunk| {
            assert!(
                hunk.header.contains("fn")
                    || hunk.header.contains("impl")
                    || hunk.header.contains("struct"),
                "Hunk header should contain Rust context like function or struct names: {}",
                hunk.header
            )
        });
    }

    #[test]
    fn test_try_from_empty_git2_diff() {
        // Test the try_from logic with an empty diff
        let dir = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(dir.path()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();

        // Create a single commit
        fs::write(dir.path().join("file.txt"), "content\n").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(std::path::Path::new("file.txt")).unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let _commit = repo
            .commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        // Create diff from tree to itself (should be empty)
        let git_diff = repo
            .diff_tree_to_tree(Some(&tree), Some(&tree), None)
            .unwrap();
        let diff = Diff::try_from(git_diff).expect("Should handle empty diff");

        assert_eq!(diff.files.len(), 0);
        assert_eq!(diff.stats.files_changed, 0);
        assert_eq!(diff.stats.insertions, 0);
        assert_eq!(diff.stats.deletions, 0);

        assert_eq!(diff.added_files().count(), 0);
        assert_eq!(diff.deleted_files().count(), 0);
        assert_eq!(diff.modified_files().count(), 0);
    }

    #[test]
    fn test_line_type_try_from_char() {
        assert_eq!(LineType::try_from('+').unwrap(), LineType::Addition);
        assert_eq!(LineType::try_from('-').unwrap(), LineType::Deletion);
        assert_eq!(LineType::try_from(' ').unwrap(), LineType::Context);
        assert_eq!(LineType::try_from('>').unwrap(), LineType::Other);
        assert_eq!(LineType::try_from('<').unwrap(), LineType::Other);
        assert_eq!(LineType::try_from('=').unwrap(), LineType::Other);
        assert_eq!(LineType::try_from('B').unwrap(), LineType::Other);
        assert_eq!(LineType::try_from('F').unwrap(), LineType::Other);
        assert_eq!(LineType::try_from('H').unwrap(), LineType::Other);

        assert!(LineType::try_from('x').is_err());
        assert!(LineType::try_from('1').is_err());
        assert!(LineType::try_from('@').is_err());
    }

    #[test]
    fn test_hunk_header_regex() {
        // Test the regex pattern used in try_from implementation
        let valid_header = "@@ -1,3 +1,4 @@ fn test_function()";
        let captures = HUNK_HEADER_REGEX.captures(valid_header).unwrap();
        assert_eq!(
            captures.get(1).unwrap().as_str().trim(),
            "fn test_function()"
        );

        let header_no_context = "@@ -1,3 +1,4 @@";
        let captures = HUNK_HEADER_REGEX.captures(header_no_context).unwrap();
        assert_eq!(captures.get(1).map(|m| m.as_str().trim()).unwrap_or(""), "");

        let header_with_spaces = "@@ -10,5 +12,7 @@   struct MyStruct   ";
        let captures = HUNK_HEADER_REGEX.captures(header_with_spaces).unwrap();
        assert_eq!(captures.get(1).unwrap().as_str().trim(), "struct MyStruct");
    }
}
