use std::fmt;

pub struct BuildInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub git_commit: &'static str,
    pub git_branch: &'static str,
    pub rustc_version: &'static str,
    pub build_target: &'static str,
    pub build_profile: &'static str,
    pub build_time: &'static str,
}

const fn value_or_unknown(value: Option<&'static str>) -> &'static str {
    match value {
        Some(value) => value,
        None => "unknown",
    }
}

pub const BUILD_INFO: BuildInfo = BuildInfo {
    name: env!("CARGO_PKG_NAME"),
    version: env!("CARGO_PKG_VERSION"),
    git_commit: value_or_unknown(option_env!("XRAY_RS_GIT_COMMIT")),
    git_branch: value_or_unknown(option_env!("XRAY_RS_GIT_BRANCH")),
    rustc_version: value_or_unknown(option_env!("XRAY_RS_RUSTC_VERSION")),
    build_target: value_or_unknown(option_env!("XRAY_RS_BUILD_TARGET")),
    build_profile: value_or_unknown(option_env!("XRAY_RS_BUILD_PROFILE")),
    build_time: value_or_unknown(option_env!("XRAY_RS_BUILD_TIME")),
};

impl BuildInfo {
    pub fn summary_line(&self) -> String {
        format!(
            "{} {} (commit={}, branch={})",
            self.name, self.version, self.git_commit, self.git_branch
        )
    }

    pub fn detail_line(&self) -> String {
        format!(
            "rustc={}, target={}, profile={}, built={}",
            self.rustc_version, self.build_target, self.build_profile, self.build_time
        )
    }
}

impl fmt::Display for BuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}", self.name, self.version)?;
        writeln!(f, "commit: {}", self.git_commit)?;
        writeln!(f, "branch: {}", self.git_branch)?;
        writeln!(f, "rustc: {}", self.rustc_version)?;
        writeln!(f, "target: {}", self.build_target)?;
        writeln!(f, "profile: {}", self.build_profile)?;
        write!(f, "built: {}", self.build_time)
    }
}

pub fn log_startup_info() {
    log::info!(target: "build", "starting {}", BUILD_INFO.name);
    log::info!(target: "build", "{}", BUILD_INFO.summary_line());
    log::info!(target: "build", "{}", BUILD_INFO.detail_line());
}
