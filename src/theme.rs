//! One place that defines category colors (terminal report, and the TUI/web reuse the same names).

use crate::category::Category;
use crossterm::style::{Color, Stylize};
use std::io::IsTerminal;

pub fn color(c: Category) -> Color {
    match c {
        Category::Malware => Color::Red,
        Category::Telemetry => Color::AnsiValue(208), // orange
        Category::Ads => Color::Yellow,
        Category::Allowed => Color::Blue,
        Category::Clean => Color::Green,
        Category::Unknown => Color::AnsiValue(245), // grey
    }
}

/// Human label shown next to the color so the report is readable without color too.
pub fn label(c: Category) -> &'static str {
    match c {
        Category::Malware => "malware/phishing",
        Category::Telemetry => "telemetry",
        Category::Ads => "ads/trackers",
        Category::Allowed => "allowlisted",
        Category::Clean => "clean",
        Category::Unknown => "unknown/new",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

impl ColorMode {
    pub fn enabled(self) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
}

/// Paint `text` in the category's color (or leave plain when color is off).
pub fn paint(text: &str, cat: Category, on: bool) -> String {
    if on {
        text.with(color(cat)).to_string()
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str, on: bool) -> String {
    if on {
        text.bold().to_string()
    } else {
        text.to_string()
    }
}

pub fn dim(text: &str, on: bool) -> String {
    if on {
        text.dim().to_string()
    } else {
        text.to_string()
    }
}
