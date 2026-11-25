//! Categories and verdicts: the vocabulary shared by every part of the app.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// What kind of thing a domain is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Red: malware / phishing.
    Malware,
    /// Orange: telemetry.
    Telemetry,
    /// Yellow: ads / trackers.
    Ads,
    /// Blue: on the user's allowlist.
    Allowed,
    /// Green: clean.
    Clean,
    /// Grey: unknown / first time seen.
    Unknown,
}

impl Category {
    pub const ALL: [Category; 6] = [
        Category::Malware,
        Category::Telemetry,
        Category::Ads,
        Category::Allowed,
        Category::Clean,
        Category::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Malware => "malware",
            Category::Telemetry => "telemetry",
            Category::Ads => "ads",
            Category::Allowed => "allowed",
            Category::Clean => "clean",
            Category::Unknown => "unknown",
        }
    }

    /// Categories that come from blocklists (i.e. can cause a block).
    pub fn is_blockable(self) -> bool {
        matches!(self, Category::Malware | Category::Telemetry | Category::Ads)
    }

    /// Higher = more severe. Used when a domain appears in several lists.
    pub fn severity(self) -> u8 {
        match self {
            Category::Malware => 3,
            Category::Telemetry => 2,
            Category::Ads => 1,
            _ => 0,
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Category {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "malware" | "phishing" => Ok(Category::Malware),
            "telemetry" => Ok(Category::Telemetry),
            "ads" | "ad" | "trackers" | "tracker" => Ok(Category::Ads),
            "allowed" | "allow" => Ok(Category::Allowed),
            "clean" => Ok(Category::Clean),
            "unknown" => Ok(Category::Unknown),
            other => Err(format!("unknown category '{other}'")),
        }
    }
}

/// What we did with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Blocked,
    Allowed,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Blocked => "blocked",
            Action::Allowed => "allowed",
        }
    }
}

/// The result of checking a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub action: Action,
    pub category: Category,
    /// Name of the list (or "user") that produced the verdict, if any.
    pub source: Option<String>,
}

impl Verdict {
    pub fn pass(category: Category) -> Self {
        Verdict { action: Action::Allowed, category, source: None }
    }
}
