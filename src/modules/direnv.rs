use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use super::{Context, Module, ModuleConfig};

use crate::configs::direnv::DirenvConfig;
use crate::formatter::StringFormatter;

use serde::Deserialize;

/// Creates a module with the current direnv rc
pub fn module<'a>(context: &'a Context) -> Option<Module<'a>> {
    let mut module = context.new_module("direnv");
    let config = DirenvConfig::try_load(module.config);

    let state = match DirenvState::from_env(context) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("{e}");

            return None;
        }
    };

    // TODO: handle loaded for both and when rc_path != loaded_rc_path
    if state.rc_path.is_none() && state.loaded_rc_path.is_none() {
        return None;
    }

    let parsed = StringFormatter::new(config.format).and_then(|formatter| {
        formatter
            .map_style(|variable| match variable {
                "style" => Some(Ok(config.style)),
                _ => None,
            })
            .map(|variable| match variable {
                "symbol" => Some(Ok(Cow::from(config.symbol))),
                "rc_path" => state.rc_path.as_ref().map(|p| Ok(p.to_string_lossy())),
                "allowed" => state
                    .allowed
                    .as_ref()
                    .map(|a| match a {
                        AllowStatus::Allowed => Cow::from(config.allowed_msg),
                        AllowStatus::NotAllowed => Cow::from(config.not_allowed_msg),
                        AllowStatus::Denied => Cow::from(config.denied_msg),
                    })
                    .map(Ok),
                "loaded" => state
                    .loaded_rc_path
                    .as_ref()
                    .map_or_else(|| Some(config.unloaded_msg), |_f| Some(config.loaded_msg))
                    .map(Cow::from)
                    .map(Ok),
                _ => None,
            })
            .parse(None, Some(context))
    });

    module.set_segments(match parsed {
        Ok(segments) => segments,
        Err(e) => {
            log::warn!("{e}");

            return None;
        }
    });

    Some(module)
}

struct DirenvState {
    pub rc_path: Option<PathBuf>,
    pub loaded_rc_path: Option<PathBuf>,
    pub allowed: Option<AllowStatus>,
    pub loaded_allowed: Option<AllowStatus>,
}

impl FromStr for DirenvState {
    type Err = Cow<'static, str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match serde_json::from_str::<RawDirenvState>(s) {
            Ok(raw) => Ok(DirenvState {
                rc_path: Some(raw.state.found_rc.path),
                loaded_rc_path: Some(raw.state.loaded_rc.path),
                allowed: Some(raw.state.found_rc.allowed.try_into()?),
                loaded_allowed: Some(raw.state.loaded_rc.allowed.try_into()?),
            }),
            Err(_) => DirenvState::from_lines(s),
        }
    }
}

impl DirenvState {
    fn is_rc_allowed(path: Option<&PathBuf>) -> Option<AllowStatus> {
        if path.is_none() {
            return None;
        }

        let file_name = path.clone().unwrap();
        let bytes = std::fs::read(file_name.clone()).unwrap();

        let mut allow_hasher = Sha256::new();
        allow_hasher.update(file_name.to_str().unwrap().as_bytes());
        allow_hasher.update("\n");
        allow_hasher.update(bytes);
        let allow_hash = format!("{:x}", allow_hasher.finalize());

        let allow_file =
            Context::expand_tilde(PathBuf::from_str("~/.local/share/direnv/allow").unwrap())
                .as_path()
                .join(allow_hash.as_str());

        if allow_file.as_path().exists() {
            return Some(AllowStatus::Allowed);
        }
        let mut deny_hasher = Sha256::new();
        deny_hasher.update(file_name.to_str().unwrap().as_bytes());
        deny_hasher.update("\n");
        let deny_hash = format!("{:x}", deny_hasher.finalize());

        let deny_file =
            Context::expand_tilde(PathBuf::from_str("~/.local/share/direnv/deny").unwrap())
                .as_path()
                .join(deny_hash.as_str());
        if deny_file.as_path().exists() {
            return Some(AllowStatus::Denied);
        }
        return Some(AllowStatus::NotAllowed);
    }

    fn from_env(context: &Context) -> Result<Self, Cow<'static, str>> {
        let mut rc_path = None;

        // discover .envrc file
        for path in context.current_dir.ancestors() {
            let maybe_path = path.join(".envrc");
            if Path::exists(Path::new(maybe_path.as_path())) {
                rc_path = Some(maybe_path);
                break;
            }
        }

        let loaded_rc_path = context
            .get_env("DIRENV_FILE")
            .map(|e| PathBuf::from_str(e.as_str()).unwrap());

        let allowed = DirenvState::is_rc_allowed(rc_path.as_ref());
        let loaded_allowed = DirenvState::is_rc_allowed(loaded_rc_path.as_ref());

        Ok(Self {
            rc_path,
            loaded_rc_path,
            allowed,
            loaded_allowed,
        })
    }

    fn from_lines(s: &str) -> Result<Self, Cow<'static, str>> {
        let mut rc_path = None;
        let mut loaded_rc_path = None;
        let mut allowed = None;
        let mut loaded_allowed = None;

        for line in s.lines() {
            if let Some(path) = line.strip_prefix("Found RC path") {
                rc_path = Some(PathBuf::from(path.trim()));
            } else if let Some(value) = line.strip_prefix("Found RC allowed") {
                allowed = Some(AllowStatus::from_str(value.trim())?);
            } else if let Some(path) = line.strip_prefix("Loaded RC path") {
                loaded_rc_path = Some(PathBuf::from(path.trim()));
            } else if let Some(value) = line.strip_prefix("Loaded RC allowed") {
                loaded_allowed = Some(AllowStatus::from_str(value.trim())?);
            }
        }

        if rc_path.is_none() || allowed.is_none() {
            return Err(Cow::from("unknown direnv state"));
        }

        Ok(Self {
            rc_path,
            loaded_rc_path,
            allowed,
            loaded_allowed,
        })
    }
}

#[derive(Debug)]
enum AllowStatus {
    Allowed,
    NotAllowed,
    Denied,
}

impl FromStr for AllowStatus {
    type Err = Cow<'static, str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0" | "true" => Ok(Self::Allowed),
            "1" => Ok(Self::NotAllowed),
            "2" | "false" => Ok(Self::Denied),
            _ => Err(Cow::from("invalid allow status")),
        }
    }
}

impl TryFrom<u8> for AllowStatus {
    type Error = Cow<'static, str>;

    fn try_from(u: u8) -> Result<Self, Self::Error> {
        match u {
            0 => Ok(Self::Allowed),
            1 => Ok(Self::NotAllowed),
            2 => Ok(Self::Denied),
            _ => Err(Cow::from("unknown integer allow status")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawDirenvState {
    pub state: State,
}

#[derive(Debug, Deserialize)]
struct State {
    #[serde(rename = "foundRC")]
    pub found_rc: RCStatus,
    #[serde(rename = "loadedRC")]
    pub loaded_rc: RCStatus,
}

#[derive(Debug, Deserialize)]
struct RCStatus {
    pub allowed: u8,
    pub path: PathBuf,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test::ModuleRenderer;
    use crate::utils::CommandOutput;
    use std::io;
    use std::path::Path;
    #[test]
    fn folder_without_rc_files_pre_2_33() {
        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_without_rc(),
                    stderr: String::default(),
                }),
            );

        assert_eq!(None, renderer.collect());
    }
    #[test]
    fn folder_without_rc_files() {
        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_without_rc_json(),
                    stderr: String::default(),
                }),
            );

        assert_eq!(None, renderer.collect());
    }
    #[test]
    fn folder_with_unloaded_rc_file_pre_2_33() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(&rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc(dir.path(), false, "0", true),
                    stderr: String::default(),
                }),
            );

        assert_eq!(
            Some(format!("direnv not loaded/allowed ")),
            renderer.collect()
        );

        dir.close()
    }
    #[test]
    fn folder_with_unloaded_rc_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc_json(dir.path(), 1, 0),
                    stderr: String::default(),
                }),
            );

        assert_eq!(
            Some("direnv not loaded/allowed ".to_string()),
            renderer.collect()
        );

        dir.close()
    }
    #[test]
    fn folder_with_loaded_rc_file_pre_2_33() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(&rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc(dir.path(), true, "0", true),
                    stderr: String::default(),
                }),
            );

        assert_eq!(Some(format!("direnv loaded/allowed ")), renderer.collect());

        dir.close()
    }
    #[test]
    fn folder_with_loaded_rc_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc_json(dir.path(), 0, 0),
                    stderr: String::default(),
                }),
            );

        assert_eq!(
            Some("direnv loaded/allowed ".to_string()),
            renderer.collect()
        );

        dir.close()
    }
    #[test]
    fn folder_with_loaded_and_denied_rc_file_pre_2_33() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(&rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc(dir.path(), true, "2", true),
                    stderr: String::default(),
                }),
            );

        assert_eq!(Some(format!("direnv loaded/denied ")), renderer.collect());

        dir.close()
    }
    #[test]
    fn folder_with_loaded_and_not_allowed_rc_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(&rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc_json(dir.path(), 0, 1),
                    stderr: String::default(),
                }),
            );

        assert_eq!(
            Some(format!("direnv loaded/not allowed ")),
            renderer.collect()
        );

        dir.close()
    }
    #[test]
    fn folder_with_loaded_and_denied_rc_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let rc_path = dir.path().join(".envrc");

        std::fs::File::create(rc_path)?.sync_all()?;

        let renderer = ModuleRenderer::new("direnv")
            .config(toml::toml! {
                [direnv]
                disabled = false
            })
            .path(dir.path())
            .cmd(
                "direnv status --json",
                Some(CommandOutput {
                    stdout: status_cmd_output_with_rc_json(dir.path(), 0, 2),
                    stderr: String::default(),
                }),
            );

        assert_eq!(
            Some("direnv loaded/denied ".to_string()),
            renderer.collect()
        );

        dir.close()
    }
    fn status_cmd_output_without_rc() -> String {
        String::from(
            r"\
direnv exec path /usr/bin/direnv
DIRENV_CONFIG /home/test/.config/direnv
bash_path /usr/bin/bash
disable_stdin false
warn_timeout 5s
whitelist.prefix []
whitelist.exact map[]
No .envrc or .env loaded
No .envrc or .env found",
        )
    }
    fn status_cmd_output_without_rc_json() -> String {
        json!({
            "config": {
                "ConfigDir": config_dir(),
                "SelfPath": self_path(),
            },
            "state": {
                "foundRC": null,
                "loadedRC": null,
            }
        })
        .to_string()
    }
    fn status_cmd_output_with_rc(
        dir: impl AsRef<Path>,
        loaded: bool,
        allowed: &str,
        use_legacy_boolean_flags: bool,
    ) -> String {
        let rc_path = dir.as_ref().join(".envrc");
        let rc_path = rc_path.to_string_lossy();

        let allowed_value = match (use_legacy_boolean_flags, allowed) {
            (true, "0") => "true",
            (true, ..) => "false",
            (false, val) => val,
        };

        let loaded = if loaded {
            format!(
                r#"\
            Loaded RC path {rc_path}
            Loaded watch: ".envrc" - 2023-04-30T09:51:04-04:00
            Loaded watch: "../.local/share/direnv/allow/abcd" - 2023-04-30T09:52:58-04:00
            Loaded RC allowed {allowed_value}
            Loaded RC allowPath
            "#
            )
        } else {
            String::from("No .envrc or .env loaded")
        };

        let state = allowed.to_string();

        format!(
            r#"\
direnv exec path /usr/bin/direnv
DIRENV_CONFIG /home/test/.config/direnv
bash_path /usr/bin/bash
disable_stdin false
warn_timeout 5s
whitelist.prefix []
whitelist.exact map[]
{loaded}
Found RC path {rc_path}
Found watch: ".envrc" - 2023-04-25T18:45:54-04:00
Found watch: "../.local/share/direnv/allow/abcd" - 1969-12-31T19:00:00-05:00
Found RC allowed {state}
Found RC allowPath /home/test/.local/share/direnv/allow/abcd
"#
        )
    }
    fn status_cmd_output_with_rc_json(dir: impl AsRef<Path>, loaded: u8, allowed: u8) -> String {
        let rc_path = dir.as_ref().join(".envrc");
        let rc_path = rc_path.to_string_lossy();

        json!({
            "config": {
                "ConfigDir": config_dir(),
                "SelfPath": self_path(),
            },
            "state": {
                "foundRC": {
                    "allowed": allowed,
                    "path": rc_path,
                },
                "loadedRC": {
                    "allowed": loaded,
                    "path": rc_path,
                }
            }
        })
        .to_string()
    }
    #[cfg(windows)]
    fn config_dir() -> &'static str {
        r"C:\\Users\\test\\AppData\\Local\\direnv"
    }
    #[cfg(not(windows))]
    fn config_dir() -> &'static str {
        "/home/test/.config/direnv"
    }
    #[cfg(windows)]
    fn self_path() -> &'static str {
        r"C:\\Program Files\\direnv\\direnv.exe"
    }
    #[cfg(not(windows))]
    fn self_path() -> &'static str {
        "/usr/bin/direnv"
    }
}
