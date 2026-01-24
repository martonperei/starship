#[cfg(not(target_os = "windows"))]
use super::utils::directory_nix as directory_utils;
#[cfg(target_os = "windows")]
use super::utils::directory_win as directory_utils;
use super::utils::path::PathExt as SPathExt;
use indexmap::IndexMap;
use path_slash::{PathBufExt, PathExt};
use std::borrow::Cow;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use unicode_segmentation::UnicodeSegmentation;

use super::{Context, Module};

use super::utils::directory::truncate;
use crate::config::ModuleConfig;
use crate::configs::directory::DirectoryConfig;
use crate::formatter::StringFormatter;

/// Creates a module with the current logical or physical directory
///
/// Will perform path contraction, substitution, and truncation.
///
/// **Contraction**
/// - Paths beginning with the home directory or with a git repo right inside
///   the home directory will be contracted to `~`, or the set `HOME_SYMBOL`
/// - Paths containing a git repo will contract to begin at the repo root
///
/// **Substitution**
/// Paths will undergo user-provided substitutions of substrings
///
/// **Truncation**
/// Paths will be limited in length to `3` path components by default.
pub fn module<'a>(context: &'a Context) -> Option<Module<'a>> {
    let mut module = context.new_module("directory");
    let config: DirectoryConfig = DirectoryConfig::try_load(module.config);

    let home_dir = context
        .get_home()
        .expect("Unable to determine HOME_DIR for user");
    let physical_dir = &context.current_dir;
    let display_dir = if config.use_logical_path {
        &context.logical_dir
    } else {
        &context.current_dir
    };

    log::debug!("Home dir: {:?}", &home_dir);
    log::debug!("Physical dir: {:?}", &physical_dir);
    log::debug!("Display dir: {:?}", &display_dir);

    // Contract home directory in the display path (used for fish-style prefix)
    let full_path_with_home = contract_path(display_dir, &home_dir, config.home_symbol);

    // Get contracted repo path and repo name if in a repo
    // Uses lightweight git workdir lookup (no gix overhead)
    let repo_contract = if config.truncate_to_repo || config.repo_root_style.is_some() {
        context
            .get_git_workdir()
            .filter(|&root| root != &home_dir)
            .and_then(|root| contract_repo_path(display_dir, root))
    } else {
        None
    };

    let dir_string = if config.truncate_to_repo {
        repo_contract.clone()
    } else {
        None
    };

    let mut is_truncated = dir_string.is_some();

    // If no repo path contraction occurred, use the home-contracted path
    let full_dir_string = dir_string.unwrap_or_else(|| full_path_with_home.to_string());

    #[cfg(windows)]
    let full_dir_string = remove_extended_path_prefix(full_dir_string);

    // Apply path substitutions
    let full_dir_string = substitute_path(full_dir_string, &config.substitutions);

    // Truncate the dir string to the maximum number of path components
    let dir_string = if let Some(truncated) = truncate(&full_dir_string, config.truncation_length as usize) {
        is_truncated = true;
        truncated
    } else {
        full_dir_string.clone()
    };

    // Compute fish-style prefix if needed
    let fish_style_len = config.fish_style_pwd_dir_length as usize;
    let use_fish_style = fish_style_len > 0 && config.substitutions.is_empty();

    let prefix = if is_truncated {
        if use_fish_style {
            // When truncate_to_repo is active, fish-style the path BEFORE the repo
            if config.truncate_to_repo {
                if let Some(ref contracted) = repo_contract {
                    let repo_name = contracted.split('/').next().unwrap_or("");
                    let before_repo = before_root_dir(&full_path_with_home, repo_name);
                    to_fish_style(fish_style_len, before_repo, "")
                } else {
                    to_fish_style(fish_style_len, &full_dir_string, &dir_string)
                }
            } else {
                to_fish_style(fish_style_len, &full_dir_string, &dir_string)
            }
        } else {
            String::from(config.truncation_symbol)
        }
    } else {
        String::new()
    };

    let path_vec = match repo_contract {
        Some(ref contracted_path) if config.repo_root_style.is_some() => {
            let repo_name = contracted_path.split('/').next().unwrap_or("");
            let after_repo_root = contracted_path.replacen(repo_name, "", 1);
            let num_segments_after_root = after_repo_root.split('/').count();

            if use_fish_style {
                let before_repo = before_root_dir(&full_path_with_home, repo_name);
                let before_fish = to_fish_style(fish_style_len, before_repo, "");

                if let Some(truncated) = truncate(&after_repo_root, config.truncation_length as usize) {
                    let after_fish = to_fish_style(fish_style_len, &after_repo_root, &truncated);
                    [before_fish, repo_name.to_string(), after_fish, truncated]
                } else {
                    [before_fish, repo_name.to_string(), String::new(), after_repo_root]
                }
            } else if config.truncation_length == 0
                || ((num_segments_after_root - 1) as i64) < config.truncation_length
            {
                let before = before_root_dir(&dir_string, repo_name);
                [prefix + before, repo_name.to_string(), String::new(), after_repo_root]
            } else {
                [String::new(), String::new(), String::new(), prefix + dir_string.as_str()]
            }
        }
        _ => [String::new(), String::new(), String::new(), prefix + dir_string.as_str()],
    };

    let path_vec = if config.use_os_path_sep {
        path_vec.map(|i| convert_path_sep(&i))
    } else {
        path_vec
    };

    let display_format = if path_vec[0].is_empty() && path_vec[1].is_empty() {
        config.format
    } else {
        config.repo_root_format
    };
    let repo_root_style = config.repo_root_style.unwrap_or(config.style);
    let before_repo_root_style = config.before_repo_root_style.unwrap_or(config.style);

    let parsed = StringFormatter::new(display_format).and_then(|formatter| {
        formatter
            .map_style(|variable| match variable {
                "style" => Some(Ok(config.style)),
                "read_only_style" => Some(Ok(config.read_only_style)),
                "repo_root_style" => Some(Ok(repo_root_style)),
                "before_repo_root_style" => Some(Ok(before_repo_root_style)),
                _ => None,
            })
            .map(|variable| match variable {
                "path" => Some(Ok(path_vec[3].as_str())),
                "before_root_path" => Some(Ok(path_vec[0].as_str())),
                "repo_root" => Some(Ok(path_vec[1].as_str())),
                "after_root_path" => Some(Ok(path_vec[2].as_str())),
                "read_only" => {
                    if is_readonly_dir(physical_dir) {
                        Some(Ok(config.read_only))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .parse(None, Some(context))
    });

    module.set_segments(match parsed {
        Ok(segments) => segments,
        Err(error) => {
            log::warn!("Error in module `directory`:\n{error}");
            return None;
        }
    });

    Some(module)
}

#[cfg(windows)]
fn remove_extended_path_prefix(path: String) -> String {
    fn try_trim_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if !s.starts_with(prefix) {
            return None;
        }
        Some(&s[prefix.len()..])
    }
    // Trim any Windows extended-path prefix from the display path
    if let Some(unc) = try_trim_prefix(&path, r"\\?\UNC\") {
        return format!(r"\\{unc}");
    }
    if let Some(p) = try_trim_prefix(&path, r"\\?\") {
        return p.to_string();
    }
    path
}

fn is_readonly_dir(path: &Path) -> bool {
    match directory_utils::is_write_allowed(path) {
        Ok(res) => !res,
        Err(e) => {
            log::debug!("Failed to determine read only status of directory '{path:?}': {e}");
            false
        }
    }
}

/// Contract the root component of a path
///
/// Replaces the `top_level_path` in a given `full_path` with the provided
/// `top_level_replacement`.
fn contract_path<'a>(
    full_path: &'a Path,
    top_level_path: &'a Path,
    top_level_replacement: &'a str,
) -> Cow<'a, str> {
    if !full_path.normalised_starts_with(top_level_path) {
        return full_path.to_slash_lossy();
    }

    if full_path.normalised_equals(top_level_path) {
        return Cow::from(top_level_replacement);
    }

    // Because we've done a normalised path comparison above
    // we can safely ignore the Prefix components when doing this
    // strip_prefix operation.
    let sub_path = full_path
        .without_prefix()
        .strip_prefix(top_level_path.without_prefix())
        .unwrap_or(full_path);

    Cow::from(format!(
        "{replacement}{separator}{path}",
        replacement = top_level_replacement,
        separator = "/",
        path = sub_path.to_slash_lossy()
    ))
}

/// Contract the root component of a path based on the real path
///
/// Replaces the `top_level_path` in a given `full_path` with the provided
/// `top_level_replacement` by walking ancestors and comparing its real path.
fn contract_repo_path(full_path: &Path, top_level_path: &Path) -> Option<String> {
    // Fast path: try direct prefix matching first (no syscalls)
    // This works when there are no symlinks involved
    if let Some(result) = contract_repo_path_fast(full_path, top_level_path) {
        return Some(result);
    }

    // Slow path: resolve symlinks and compare real paths
    let top_level_real_path = real_path(top_level_path);
    for (i, ancestor) in full_path.ancestors().enumerate() {
        let ancestor_real_path = real_path(ancestor);
        if ancestor_real_path != top_level_real_path {
            continue;
        }

        let components: Vec<_> = full_path.components().collect();
        let repo_name = components[components.len() - i - 1]
            .as_os_str()
            .to_string_lossy();

        if i == 0 {
            return Some(repo_name.to_string());
        }

        let path = PathBuf::from_iter(&components[components.len() - i..]);
        return Some(format!(
            "{repo_name}{separator}{path}",
            repo_name = repo_name,
            separator = "/",
            path = path.to_slash_lossy()
        ));
    }
    None
}

/// Fast path for contract_repo_path: simple prefix matching without syscalls
fn contract_repo_path_fast(full_path: &Path, top_level_path: &Path) -> Option<String> {
    // Check if full_path starts with top_level_path using normalized comparison
    if !full_path.normalised_starts_with(top_level_path) {
        return None;
    }

    // Get the repo directory name
    let repo_name = top_level_path.file_name()?.to_string_lossy();

    // Get the path after the repo root
    let after_repo = full_path
        .without_prefix()
        .strip_prefix(top_level_path.without_prefix())
        .ok()?;

    if after_repo.as_os_str().is_empty() {
        Some(repo_name.to_string())
    } else {
        Some(format!(
            "{repo_name}/{path}",
            repo_name = repo_name,
            path = after_repo.to_slash_lossy()
        ))
    }
}

/// Resolves symlinks in a path while preserving the logical structure
///
/// This function manually resolves symlinks component-by-component, then attempts
/// to canonicalize the result. This approach preserves logical paths better than
/// using canonicalize alone, which would return only the physical path.
///
/// # Arguments
/// * `path` - The path to resolve
///
/// # Returns
/// The resolved path, or the original path if canonicalization fails
fn real_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    let mut buf = PathBuf::new();
    
    // Manually resolve symlinks component by component
    for component in path.components() {
        let next = buf.join(component);
        if let Ok(realpath) = next.read_link() {
            if realpath.is_absolute() {
                buf = realpath;
            } else {
                buf.push(realpath);
            }
        } else {
            buf = next;
        }
    }
    
    // Attempt to canonicalize, falling back to the original path on failure
    buf.canonicalize().unwrap_or_else(|_| path.into())
}

/// Perform a list of string substitutions on the path
///
/// Given a list of (from, to) pairs, this will perform the string
/// substitutions, in order, on the path. Any non-pair of strings is ignored.
fn substitute_path(dir_string: String, substitutions: &IndexMap<String, &str>) -> String {
    let mut substituted_dir = dir_string;
    for substitution_pair in substitutions {
        substituted_dir = substituted_dir.replace(substitution_pair.0, substitution_pair.1);
    }
    substituted_dir
}

/// Takes part before contracted path and replaces it with fish style path
///
/// Will take the first `pwd_dir_length` graphemes of each directory before the 
/// contracted path and use that in the path instead. See the following example.
///
/// Absolute Path: `/Users/Bob/Projects/work/a_repo`
/// Contracted Path: `a_repo`
/// With Fish Style: `~/P/w/a_repo`
///
/// Absolute Path: `/some/Path/not/in_a/repo/but_nested`
/// Contracted Path: `in_a/repo/but_nested`
/// With Fish Style: `/s/P/n/in_a/repo/but_nested`
///
/// # Arguments
/// * `pwd_dir_length` - Number of graphemes to keep from each directory name
/// * `dir_string` - The full directory path
/// * `truncated_dir_string` - The part to be removed from the end (must be a suffix of dir_string)
///
/// # Note
/// For dot-prefixed directories (e.g., `.config`), includes the dot plus `pwd_dir_length` 
/// characters (e.g., with `pwd_dir_length=1`, `.config` becomes `.c`).
fn to_fish_style(pwd_dir_length: usize, dir_string: &str, truncated_dir_string: &str) -> String {
    debug_assert!(
        dir_string.ends_with(truncated_dir_string),
        "truncated_dir_string must be a suffix of dir_string"
    );

    let replaced_dir_string = dir_string.trim_end_matches(truncated_dir_string);
    
    // Quick exit to avoid allocation for empty string
    if replaced_dir_string.is_empty() {
        return String::new();
    }

    let components = replaced_dir_string.split('/');
    let mut result = String::with_capacity(replaced_dir_string.len());

    for (idx, word) in components.enumerate() {
        if idx > 0 {
            result.push('/');
        }

        if word.is_empty() {
            continue;
        }

        let mut graphemes = word.graphemes(true);
        
        // Peek at the first grapheme to check for dotfiles
        if let Some(first) = graphemes.next() {
            let is_dot = first == ".";
            let take_count = if is_dot { pwd_dir_length + 1 } else { pwd_dir_length };
            
            // We need to know if the word is short enough to fit fully.
            // We count the remaining graphemes (we already took 1).
            let remaining_count = graphemes.clone().count();
            let total_count = remaining_count + 1;

            if total_count <= pwd_dir_length {
                // Word is short: append the whole thing
                result.push_str(word);
            } else {
                // Word is long: append the first char (already popped)
                result.push_str(first);
                // Append the rest of the limit
                // Note: take() uses usize, if take_count is 1 we need 0 more items
                for g in graphemes.take(take_count - 1) {
                    result.push_str(g);
                }
            }
        }
    }
    
    result
}

/// Convert the path separators in `path` to the OS specific path separators.
fn convert_path_sep(path: &str) -> String {
    PathBuf::from_slash(path).to_string_lossy().into_owned()
}

/// Extracts the path portion before a repository root directory
///
/// Finds the rightmost occurrence of the repository name in the path and returns
/// everything before it. This is useful for separating the path into "before repo"
/// and "repo + after" sections.
///
/// # Arguments
/// * `path` - The full path string
/// * `repo_name` - The repository directory name to search for
///
/// # Returns
/// The portion of the path before the repository name, or the full path if not found
///
/// # Examples
/// ```text
/// before_root_dir("~/user/gitrepo/gitrepo", "gitrepo") => "~/user/gitrepo/"
/// before_root_dir("~/projects/myrepo/src", "myrepo") => "~/projects/"
/// before_root_dir("~/projects/src", "notfound") => "~/projects/src"
/// ```
fn before_root_dir<'a>(path: &'a str, repo_name: &'a str) -> &'a str {
    match path.rsplit_once(repo_name) {
        Some((before, _)) => before,
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::ModuleRenderer;
    use crate::utils::create_command;
    use crate::utils::home_dir;
    use nu_ansi_term::Color;
    #[cfg(not(target_os = "windows"))]
    use std::os::unix::fs::symlink;
    #[cfg(target_os = "windows")]
    use std::os::windows::fs::symlink_dir as symlink;
    use std::path::Path;
    use std::{fs, io};
    use tempfile::TempDir;

    #[test]
    fn contract_home_directory() {
        let full_path = Path::new("/Users/astronaut/schematics/rocket");
        let home = Path::new("/Users/astronaut");

        let output = contract_path(full_path, home, "~");
        assert_eq!(output, "~/schematics/rocket");
    }

    #[test]
    fn contract_repo_directory() -> io::Result<()> {
        let tmp_dir = TempDir::new_in(home_dir().unwrap().as_path())?;
        let repo_dir = tmp_dir.path().join("dev").join("rocket-controls");
        let src_dir = repo_dir.join("src");
        fs::create_dir_all(&src_dir)?;
        init_repo(&repo_dir)?;

        let src_variations = [src_dir.clone(), dunce::canonicalize(src_dir).unwrap()];
        let repo_variations = [repo_dir.clone(), dunce::canonicalize(repo_dir).unwrap()];
        for src_dir in &src_variations {
            for repo_dir in &repo_variations {
                let output = contract_repo_path(src_dir, repo_dir);
                assert_eq!(output, Some("rocket-controls/src".to_string()));
            }
        }

        tmp_dir.close()
    }

    #[test]
    #[cfg(windows)]
    fn contract_windows_style_home_directory() {
        let path_variations = [
            r"\\?\C:\Users\astronaut\schematics\rocket",
            r"C:\Users\astronaut\schematics\rocket",
        ];
        let home_path_variations = [r"\\?\C:\Users\astronaut", r"C:\Users\astronaut"];
        for path in &path_variations {
            for home_path in &home_path_variations {
                let path = Path::new(path);
                let home_path = Path::new(home_path);

                let output = contract_path(path, home_path, "~");
                assert_eq!(output, "~/schematics/rocket");
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn contract_windows_style_repo_directory() {
        let full_path = Path::new("C:\\Users\\astronaut\\dev\\rocket-controls\\src");
        let repo_root = Path::new("C:\\Users\\astronaut\\dev\\rocket-controls");

        let output = contract_path(full_path, repo_root, "rocket-controls");
        assert_eq!(output, "rocket-controls/src");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn contract_windows_style_no_top_level_directory() {
        let full_path = Path::new("C:\\Some\\Other\\Path");
        let top_level_path = Path::new("C:\\Users\\astronaut");

        let output = contract_path(full_path, top_level_path, "~");
        assert_eq!(output, "C:/Some/Other/Path");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn contract_windows_style_root_directory() {
        let full_path = Path::new("C:\\");
        let top_level_path = Path::new("C:\\Users\\astronaut");

        let output = contract_path(full_path, top_level_path, "~");
        assert_eq!(output, "C:/");
    }

    #[test]
    fn substitute_prefix_and_middle() {
        let full_path = "/absolute/path/foo/bar/baz";
        let mut substitutions = IndexMap::new();
        substitutions.insert("/absolute/path".to_string(), "");
        substitutions.insert("/bar/".to_string(), "/");

        let output = substitute_path(full_path.to_string(), &substitutions);
        assert_eq!(output, "/foo/baz");
    }

    #[test]
    fn fish_style_with_user_home_contracted_path() {
        let path = "~/starship/engines/booster/rocket";
        let output = to_fish_style(1, path, "engines/booster/rocket");
        assert_eq!(output, "~/s/");
    }

    #[test]
    fn fish_style_with_user_home_contracted_path_and_dot_dir() {
        let path = "~/.starship/engines/booster/rocket";
        let output = to_fish_style(1, path, "engines/booster/rocket");
        assert_eq!(output, "~/.s/");
    }

    #[test]
    fn fish_style_with_no_contracted_path() {
        // `truncation_length = 2`
        let path = "/absolute/Path/not/in_a/repo/but_nested";
        let output = to_fish_style(1, path, "repo/but_nested");
        assert_eq!(output, "/a/P/n/i/");
    }

    #[test]
    fn fish_style_with_pwd_dir_len_no_contracted_path() {
        // `truncation_length = 2`
        let path = "/absolute/Path/not/in_a/repo/but_nested";
        let output = to_fish_style(2, path, "repo/but_nested");
        assert_eq!(output, "/ab/Pa/no/in/");
    }

    #[test]
    fn fish_style_with_duplicate_directories() {
        let path = "~/starship/tmp/C++/C++/C++";
        let output = to_fish_style(1, path, "C++");
        assert_eq!(output, "~/s/t/C/C/");
    }

    #[test]
    fn fish_style_with_unicode() {
        let path = "~/starship/tmp/目录/a̐éö̲/目录";
        let output = to_fish_style(1, path, "目录");
        assert_eq!(output, "~/s/t/目/a̐/");
    }

    fn init_repo(path: &Path) -> io::Result<()> {
        create_command("git")?
            .args(["init"])
            .current_dir(path)
            .output()
            .map(|_| ())
    }

    fn make_known_tempdir(root: &Path) -> io::Result<(TempDir, String)> {
        fs::create_dir_all(root)?;
        let dir = TempDir::new_in(root)?;
        // the .to_string_lossy().to_string() here looks weird but is required
        // to convert it from a Cow.
        let path = dir
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        Ok((dir, path))
    }

    #[cfg(not(target_os = "windows"))]
    mod linux {
        use super::*;

        #[test]
        #[ignore]
        fn symlinked_subdirectory_git_repo_out_of_tree() -> io::Result<()> {
            let tmp_dir = TempDir::new_in(home_dir().unwrap().as_path())?;
            let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
            let src_dir = repo_dir.join("src/meters/fuel-gauge");
            let symlink_dir = tmp_dir.path().join("fuel-gauge");
            fs::create_dir_all(&src_dir)?;
            init_repo(&repo_dir)?;
            symlink(&src_dir, &symlink_dir)?;

            let actual = ModuleRenderer::new("directory")
                .env("HOME", tmp_dir.path().to_str().unwrap())
                .path(symlink_dir)
                .collect();
            let expected = Some(format!("{} ", Color::Cyan.bold().paint("~/fuel-gauge")));

            assert_eq!(expected, actual);

            tmp_dir.close()
        }

        #[test]
        #[ignore]
        fn git_repo_in_home_directory_truncate_to_repo_true() -> io::Result<()> {
            let tmp_dir = TempDir::new_in(home_dir().unwrap().as_path())?;
            let dir = tmp_dir.path().join("src/fuel-gauge");
            fs::create_dir_all(&dir)?;
            init_repo(tmp_dir.path())?;

            let actual = ModuleRenderer::new("directory")
                .config(toml::toml! {
                    [directory]
                    // `truncate_to_repo = true` should attempt to display the truncated path
                    truncate_to_repo = true
                    truncation_length = 5
                })
                .path(dir)
                .env("HOME", tmp_dir.path().to_str().unwrap())
                .collect();
            let expected = Some(format!("{} ", Color::Cyan.bold().paint("~/src/fuel-gauge")));

            assert_eq!(expected, actual);

            tmp_dir.close()
        }

        #[test]
        #[ignore]
        fn directory_in_root() {
            let actual = ModuleRenderer::new("directory").path("/etc").collect();
            let expected = Some(format!(
                "{}{} ",
                Color::Cyan.bold().paint("/etc"),
                Color::Red.normal().paint("🔒")
            ));

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn home_directory_default_home_symbol() {
        let actual = ModuleRenderer::new("directory")
            .path(home_dir().unwrap())
            .collect();
        let expected = Some(format!("{} ", Color::Cyan.bold().paint("~")));

        assert_eq!(expected, actual);
    }

    #[test]
    fn home_directory_custom_home_symbol() {
        let actual = ModuleRenderer::new("directory")
            .path(home_dir().unwrap())
            .config(toml::toml! {
                [directory]
                home_symbol = "🚀"
            })
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("🚀"))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn home_directory_custom_home_symbol_subdirectories() {
        let actual = ModuleRenderer::new("directory")
            .path(home_dir().unwrap().join("path/subpath"))
            .config(toml::toml! {
                [directory]
                home_symbol = "🚀"
            })
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("🚀/path/subpath"))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn substituted_truncated_path() {
        let actual = ModuleRenderer::new("directory")
            .path("/some/long/network/path/workspace/a/b/c/dev")
            .config(toml::toml! {
                [directory]
                truncation_length = 4
                [directory.substitutions]
                "/some/long/network/path" = "/some/net"
                "a/b/c" = "d"
            })
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("net/workspace/d/dev"))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn substitution_order() {
        let actual = ModuleRenderer::new("directory")
            .path("/path/to/sub")
            .config(toml::toml! {
                [directory.substitutions]
                "/path/to/sub" = "/correct/order"
                "/to/sub" = "/wrong/order"
            })
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("/correct/order"))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn strange_substitution() {
        let strange_sub = "/\\/;,!";
        let actual = ModuleRenderer::new("directory")
            .path("/foo/bar/regular/path")
            .config(toml::toml! {
                [directory]
                truncation_length = 0
                fish_style_pwd_dir_length = 2 // Overridden by substitutions
                [directory.substitutions]
                "regular" = strange_sub
            })
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("/foo/bar/{strange_sub}/path")))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn directory_in_home() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("starship");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory").path(dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("~/{name}/starship")))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncated_directory_in_home() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("engine/schematics");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory").path(dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("{name}/engine/schematics")))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn fish_directory_in_home() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("starship/schematics");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 1
                fish_style_pwd_dir_length = 2
            })
            .path(&dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "~/{}/st/schematics",
                name.split_at(3).0
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn root_directory() {
        // Note: We have disable the read_only settings here due to false positives when running
        // the tests on Windows as a non-admin.
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                read_only = ""
                read_only_style = ""
            })
            .path("/")
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("/"))
        ));

        assert_eq!(expected, actual);
    }

    #[test]
    fn truncated_directory_in_root() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(Path::new("/tmp"))?;
        let dir = tmp_dir.path().join("thrusters/rocket");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory").path(dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("{name}/thrusters/rocket")))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncated_directory_config_large() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let dir = tmp_dir.path().join("thrusters/rocket");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 100
            })
            .path(&dir)
            .collect();
        let dir_str = dir.to_slash_lossy().to_string();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(
                &truncate(&dir_str, 100).unwrap_or(dir_str)
            ))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn fish_style_directory_config_large() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let dir = tmp_dir.path().join("thrusters/rocket");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 1
                fish_style_pwd_dir_length = 100
            })
            .path(&dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&to_fish_style(
                100,
                &dir.to_slash_lossy(),
                ""
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncated_directory_config_small() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(Path::new("/tmp"))?;
        let dir = tmp_dir.path().join("rocket");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 2
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("{name}/rocket")))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn fish_directory_config_small() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let dir = tmp_dir.path().join("thrusters/rocket");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 2
                fish_style_pwd_dir_length = 1
            })
            .path(&dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "{}/thrusters/rocket",
                to_fish_style(1, &dir.to_slash_lossy(), "/thrusters/rocket")
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn git_repo_root() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        fs::create_dir(&repo_dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory").path(repo_dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_git_repo() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let dir = repo_dir.join("src");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory").path(dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls/src"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn truncated_directory_in_git_repo() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let dir = repo_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory").path(dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("src/meters/fuel-gauge"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_git_repo_truncate_to_repo_false() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let dir = repo_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // Don't truncate the path at all.
                truncation_length = 5
                truncate_to_repo = false
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(
                "above-repo/rocket-controls/src/meters/fuel-gauge"
            ))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_path_directory_in_git_repo_truncate_to_repo_false() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let dir = repo_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // Don't truncate the path at all.
                truncation_length = 5
                truncate_to_repo = false
                fish_style_pwd_dir_length = 1
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "{}/above-repo/rocket-controls/src/meters/fuel-gauge",
                to_fish_style(1, &tmp_dir.path().to_slash_lossy(), "")
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_path_directory_in_git_repo_truncate_to_repo_true() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let dir = repo_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // `truncate_to_repo = true` should display the truncated path
                truncation_length = 5
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
            })
            .path(dir)
            .collect();
        // Store the path string to avoid lifetime issues with to_slash_lossy()
        let before_repo_path = tmp_dir.path().join("above-repo").to_slash_lossy().to_string() + "/";
        let fish_prefix = to_fish_style(1, &before_repo_path, "");
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "{}rocket-controls/src/meters/fuel-gauge",
                fish_prefix
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_git_repo_truncate_to_repo_true() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let dir = repo_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // `truncate_to_repo = true` should display the truncated path
                truncation_length = 5
                truncate_to_repo = true
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls/src/meters/fuel-gauge"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn symlinked_git_repo_root() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let symlink_dir = tmp_dir.path().join("rocket-controls-symlink");
        fs::create_dir(&repo_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory").path(symlink_dir).collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls-symlink"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_symlinked_git_repo() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let src_dir = repo_dir.join("src");
        let symlink_dir = tmp_dir.path().join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .path(symlink_src_dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls-symlink/src"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn truncated_directory_in_symlinked_git_repo() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let src_dir = repo_dir.join("src/meters/fuel-gauge");
        let symlink_dir = tmp_dir.path().join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .path(symlink_src_dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("src/meters/fuel-gauge"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_symlinked_git_repo_truncate_to_repo_false() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let src_dir = repo_dir.join("src/meters/fuel-gauge");
        let symlink_dir = tmp_dir
            .path()
            .join("above-repo")
            .join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // Don't truncate the path at all.
                truncation_length = 5
                truncate_to_repo = false
            })
            .path(symlink_src_dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(
                "above-repo/rocket-controls-symlink/src/meters/fuel-gauge"
            ))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_path_directory_in_symlinked_git_repo_truncate_to_repo_false() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let src_dir = repo_dir.join("src/meters/fuel-gauge");
        let symlink_dir = tmp_dir
            .path()
            .join("above-repo")
            .join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // Don't truncate the path at all.
                truncation_length = 5
                truncate_to_repo = false
                fish_style_pwd_dir_length = 1
            })
            .path(symlink_src_dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "{}/above-repo/rocket-controls-symlink/src/meters/fuel-gauge",
                to_fish_style(1, &tmp_dir.path().to_slash_lossy(), "")
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_path_directory_in_symlinked_git_repo_truncate_to_repo_true() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let src_dir = repo_dir.join("src/meters/fuel-gauge");
        let symlink_dir = tmp_dir
            .path()
            .join("above-repo")
            .join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // `truncate_to_repo = true` should display the truncated path
                truncation_length = 5
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
            })
            .path(symlink_src_dir)
            .collect();
        // Store the path string to avoid lifetime issues with to_slash_lossy()
        let before_repo_path = tmp_dir.path().join("above-repo").to_slash_lossy().to_string() + "/";
        let fish_prefix = to_fish_style(1, &before_repo_path, "");
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(&format!(
                "{}rocket-controls-symlink/src/meters/fuel-gauge",
                fish_prefix
            )))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn directory_in_symlinked_git_repo_truncate_to_repo_true() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above-repo").join("rocket-controls");
        let src_dir = repo_dir.join("src/meters/fuel-gauge");
        let symlink_dir = tmp_dir
            .path()
            .join("above-repo")
            .join("rocket-controls-symlink");
        let symlink_src_dir = symlink_dir.join("src/meters/fuel-gauge");
        fs::create_dir_all(src_dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&repo_dir, &symlink_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // `truncate_to_repo = true` should display the truncated path
                truncation_length = 5
                truncate_to_repo = true
            })
            .path(symlink_src_dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep(
                "rocket-controls-symlink/src/meters/fuel-gauge"
            ))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn symlinked_directory_in_git_repo() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("rocket-controls");
        let dir = repo_dir.join("src");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();
        symlink(&dir, repo_dir.join("src/loop"))?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                // `truncate_to_repo = true` should display the truncated path
                truncation_length = 5
                truncate_to_repo = true
            })
            .path(repo_dir.join("src/loop/loop"))
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("rocket-controls/src/loop/loop"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncation_symbol_truncated_root() {
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 3
                truncation_symbol = "…/"
            })
            .path(Path::new("/a/four/element/path"))
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("…/four/element/path"))
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    fn truncation_symbol_not_truncated_root() {
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 4
                truncation_symbol = "…/"
            })
            .path(Path::new("/a/four/element/path"))
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("/a/four/element/path"))
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    fn truncation_symbol_truncated_home() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("a/subpath");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 3
                truncation_symbol = "…/"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("…/{name}/a/subpath")))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncation_symbol_not_truncated_home() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("a/subpath");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncate_to_repo = false // Necessary if homedir is a git repo
                truncation_length = 4
                truncation_symbol = "…/"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(&format!("~/{name}/a/subpath")))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncation_symbol_truncated_in_repo() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 3
                truncation_symbol = "…/"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("…/src/sub/path"))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn truncation_symbol_not_truncated_in_repo() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 5
                truncation_symbol = "…/"
                truncate_to_repo = true
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("…/repo/src/sub/path"))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn truncation_symbol_windows_root_not_truncated() {
        let dir = Path::new("C:\\temp");
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 2
                truncation_symbol = "…/"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("C:/temp"))
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn truncation_symbol_windows_root_truncated() {
        let dir = Path::new("C:\\temp");
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 1
                truncation_symbol = "…/"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("…/temp"))
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn truncation_symbol_windows_root_truncated_backslash() {
        let dir = Path::new("C:\\temp");
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 1
                truncation_symbol = r"…\"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(convert_path_sep("…\\temp"))
        ));
        assert_eq!(expected, actual);
    }

    #[test]
    fn use_logical_path_true_should_render_logical_dir_path() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let path = tmp_dir.path().join("src/meters/fuel-gauge");
        fs::create_dir_all(&path)?;
        let logical_path = "Logical:/fuel-gauge";

        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("Logical:/fuel-gauge"))
        ));

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                use_logical_path = true
                truncation_length = 3
            })
            .path(path)
            .logical_path(logical_path)
            .collect();

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn use_logical_path_false_should_render_current_dir_path() -> io::Result<()> {
        let tmp_dir = TempDir::new()?;
        let path = tmp_dir.path().join("src/meters/fuel-gauge");
        fs::create_dir_all(&path)?;
        let logical_path = "Logical:/fuel-gauge";

        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("src/meters/fuel-gauge"))
        ));

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                use_logical_path = false
                truncation_length = 3
            })
            .path(path)
            .logical_path(logical_path) // logical_path should be ignored
            .collect();

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    #[cfg(windows)]
    fn windows_trims_extended_path_prefix() {
        // Under Windows, path canonicalization returns the paths using extended-path prefixes `\\?\`
        // We expect this prefix to be trimmed before being rendered.
        let sys32_path = Path::new(r"\\?\C:\Windows\System32");

        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep("C:/Windows/System32"))
        ));

        // Note: We have disable the read_only settings here due to false positives when running
        // the tests on Windows as a non-admin.
        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                use_logical_path = false
                truncation_length = 0
                read_only = ""
                read_only_style = ""
            })
            .path(sys32_path)
            .collect();

        assert_eq!(expected, actual);
    }

    #[test]
    #[cfg(windows)]
    fn windows_trims_extended_unc_path_prefix() {
        // Under Windows, path canonicalization may return UNC paths using extended-path prefixes `\\?\UNC\`
        // We expect this prefix to be trimmed before being rendered.
        let unc_path = Path::new(r"\\?\UNC\server\share\a\b\c");

        // NOTE: path-slash doesn't convert slashes which are part of path prefixes under Windows,
        // which is why the first part of this string still includes backslashes
        let expected = Some(format!(
            "{} ",
            Color::Cyan
                .bold()
                .paint(convert_path_sep(r"\\server\share/a/b/c"))
        ));

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                use_logical_path = false
                truncation_length = 0
            })
            .path(unc_path)
            .collect();

        assert_eq!(expected, actual);
    }

    #[test]
    fn highlight_git_root_dir() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 5
                truncate_to_repo = true
                repo_root_style = "bold red"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{}{}repo{} ",
            Color::Cyan.bold().prefix(),
            Color::Red.prefix(),
            Color::Cyan.paint(convert_path_sep("/src/sub/path"))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn highlight_git_root_dir_config_change() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 5
                truncation_symbol = "…/"
                truncate_to_repo = false
                repo_root_style = "green"
                before_repo_root_style = "blue"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{}{}{}repo{}{} ",
            Color::Blue.prefix(),
            convert_path_sep("…/above/"),
            Color::Green.prefix(),
            Color::Blue.prefix(),
            Color::Cyan.bold().paint(convert_path_sep("/src/sub/path"))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn highlight_git_root_dir_zero_truncation_length() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir).unwrap();

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 0
                truncate_to_repo = false
                repo_root_style = "green"
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{}{}repo{} ",
            Color::Cyan.bold().paint(convert_path_sep(
                tmp_dir.path().join("above/").to_str().unwrap()
            )),
            Color::Green.prefix(),
            Color::Cyan.bold().paint(convert_path_sep("/src/sub/path"))
        ));
        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    // sample for invalid unicode from https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.to_string_lossy
    #[cfg(any(unix, target_os = "redox"))]
    fn invalid_path() -> PathBuf {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Here, the values 0x66 and 0x6f correspond to 'f' and 'o'
        // respectively. The value 0x80 is a lone continuation byte, invalid
        // in a UTF-8 sequence.
        let source = [0x66, 0x6f, 0x80, 0x6f];
        let os_str = OsStr::from_bytes(&source[..]);

        PathBuf::from(os_str)
    }

    #[cfg(windows)]
    fn invalid_path() -> PathBuf {
        use std::ffi::OsString;
        use std::os::windows::prelude::*;

        // Here the values 0x0066 and 0x006f correspond to 'f' and 'o'
        // respectively. The value 0xD800 is a lone surrogate half, invalid
        // in a UTF-16 sequence.
        let source = [0x0066, 0x006f, 0xD800, 0x006f];
        let os_string = OsString::from_wide(&source[..]);

        PathBuf::from(os_string)
    }

    #[test]
    #[cfg(any(unix, windows, target_os = "redox"))]
    fn invalid_unicode() {
        let path = invalid_path();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(path.to_string_lossy())
        ));

        let actual = ModuleRenderer::new("directory").path(path).collect();

        assert_eq!(expected, actual);
    }

    #[test]
    fn use_os_path_sep_false() -> io::Result<()> {
        let (tmp_dir, name) = make_known_tempdir(home_dir().unwrap().as_path())?;
        let dir = tmp_dir.path().join("starship");
        fs::create_dir_all(&dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                use_os_path_sep = false
            })
            .path(dir)
            .collect();
        let expected = Some(format!(
            "{} ",
            Color::Cyan.bold().paint(format!("~/{name}/starship"))
        ));

        assert_eq!(expected, actual);
        tmp_dir.close()
    }

    #[test]
    fn parent_and_sub_git_repo_are_in_same_name_folder() {
        assert_eq!(
            before_root_dir("~/user/gitrepo/gitrepo", "gitrepo"),
            "~/user/gitrepo/".to_string()
        );

        assert_eq!(
            before_root_dir("~/user/gitrepo-diff/gitrepo", "gitrepo"),
            "~/user/gitrepo-diff/".to_string()
        );

        assert_eq!(
            before_root_dir("~/user/gitrepo-diff/gitrepo", "aaa"),
            "~/user/gitrepo-diff/gitrepo".to_string()
        );
    }

    #[test]
    fn to_fish_style_empty_truncated() {
        // When truncated_dir_string is empty, fish-style the entire path
        let path = "~/projects/myrepo";
        let output = to_fish_style(1, path, "");
        assert_eq!(output, "~/p/m");
    }

    #[test]
    fn to_fish_style_with_leading_slash() {
        // Path starting with / should preserve the leading slash
        let path = "/src/deep/nested";
        let output = to_fish_style(1, path, "nested");
        assert_eq!(output, "/s/d/");
    }

    #[test]
    fn to_fish_style_single_component() {
        let path = "myrepo";
        let output = to_fish_style(1, path, "");
        assert_eq!(output, "m");
    }

    #[test]
    fn to_fish_style_preserves_short_names() {
        // Names shorter than or equal to pwd_dir_length should be kept whole
        let path = "~/a/bb/ccc/dddd";
        let output = to_fish_style(2, path, "dddd");
        assert_eq!(output, "~/a/bb/cc/");
    }

    #[test]
    #[ignore]
    fn fish_style_with_repo_root_highlight() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("above").join("repo");
        let dir = repo_dir.join("src/sub");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 5
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
                repo_root_style = "green"
                before_repo_root_style = "blue"
            })
            .path(&dir)
            .collect();

        // Verify the output contains expected components
        let actual_str = actual.as_ref().unwrap();
        // Should contain fish-styled prefix ending with /a/ (for "above")
        assert!(actual_str.contains("/a/"), "should have fish-styled 'above' as /a/");
        // Should contain the repo name
        assert!(actual_str.contains("repo"), "should contain repo name");
        // Should contain the path after repo
        assert!(actual_str.contains("/src/sub"), "should contain path after repo");
        // Should have green color code for repo (32m)
        assert!(actual_str.contains("\x1b[32m"), "should have green color for repo");
        // Should have blue color code for before_repo (34m)
        assert!(actual_str.contains("\x1b[34m"), "should have blue color for before_repo");

        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_style_with_repo_root_and_truncation_after() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("projects").join("myrepo");
        let dir = repo_dir.join("src/components/deep/nested/path");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 2
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
                repo_root_style = "green"
                before_repo_root_style = "blue"
            })
            .path(&dir)
            .collect();

        // Verify the output contains expected components
        let actual_str = actual.as_ref().unwrap();
        // Should contain fish-styled prefix ending with /p/ (for "projects")
        assert!(actual_str.contains("/p/"), "should have fish-styled 'projects' as /p/");
        // Should contain the repo name
        assert!(actual_str.contains("myrepo"), "should contain repo name");
        // Should contain fish-styled after_root: /s/c/d/ for src/components/deep/
        assert!(actual_str.contains("/s/c/d/"), "should have fish-styled path after repo");
        // Should contain the truncated path (last 2 components)
        assert!(actual_str.contains("nested/path"), "should contain truncated path");

        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_style_repo_root_no_truncation_needed() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join("dev").join("repo");
        let dir = repo_dir.join("src");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 10
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
                repo_root_style = "green"
                before_repo_root_style = "blue"
            })
            .path(&dir)
            .collect();

        // Verify the output contains expected components
        let actual_str = actual.as_ref().unwrap();
        // Should contain fish-styled prefix ending with /d/ (for "dev")
        assert!(actual_str.contains("/d/"), "should have fish-styled 'dev' as /d/");
        // Should contain the repo name
        assert!(actual_str.contains("repo"), "should contain repo name");
        // Should contain the full path after repo (no truncation needed)
        assert!(actual_str.contains("/src"), "should contain path after repo");
        // Should have green color code for repo
        assert!(actual_str.contains("\x1b[32m"), "should have green color for repo");

        tmp_dir.close()
    }

    #[test]
    #[ignore]
    fn fish_style_repo_root_dotfile_directories() -> io::Result<()> {
        let (tmp_dir, _) = make_known_tempdir(Path::new("/tmp"))?;
        let repo_dir = tmp_dir.path().join(".hidden").join("repo");
        let dir = repo_dir.join("src");
        fs::create_dir_all(&dir)?;
        init_repo(&repo_dir)?;

        let actual = ModuleRenderer::new("directory")
            .config(toml::toml! {
                [directory]
                truncation_length = 5
                truncate_to_repo = true
                fish_style_pwd_dir_length = 1
                repo_root_style = "green"
            })
            .path(&dir)
            .collect();

        // Verify the output contains expected components
        let actual_str = actual.as_ref().unwrap();
        // Should contain fish-styled dotfile: .hidden -> .h (dot + 1 char)
        assert!(actual_str.contains(".h/"), "should have fish-styled '.hidden' as .h/");
        // Should contain the repo name
        assert!(actual_str.contains("repo"), "should contain repo name");
        // Should contain the path after repo
        assert!(actual_str.contains("/src"), "should contain path after repo");
        // Should have green color code for repo
        assert!(actual_str.contains("\x1b[32m"), "should have green color for repo");

        tmp_dir.close()
    }
}
