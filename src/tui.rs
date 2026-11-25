//! Live terminal view: a scrolling, color-coded feed of queries.
//!
//! The feed tails the SQLite history, so the same view works embedded (`run --tui`) or attached
//! to an already-running daemon (`tui`). Block/allow keys edit the user lists, which the daemon
//! hot-reloads within a couple of seconds.

use crate::category::{Action, Category};
use crate::filter::UserFiles;
use crate::store::{Row, Store};
use crate::theme::{label, tui_color};
use anyhow::Result;
use chrono::{Local, TimeZone};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row as TRow, Table, TableState, Wrap};
use ratatui::Frame;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const MAX_ROWS: usize = 5000;
const PAGE: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub enum Act {
    Quit,
    Block(String, Category),
    Allow(String),
    Forget(String),
}

pub struct App {
    /// Oldest first.
    rows: Vec<Row>,
    cats: HashSet<Category>,
    text: String,
    typing: bool,
    follow: bool,
    selected: Option<i64>,
    status: String,
    show_help: bool,
}

impl App {
    pub fn new() -> Self {
        App { rows: vec![], cats: HashSet::new(), text: String::new(), typing: false, follow: true, selected: None, status: String::new(), show_help: false }
    }

    pub fn ingest(&mut self, mut new: Vec<Row>) {
        self.rows.append(&mut new);
        if self.rows.len() > MAX_ROWS {
            let drop = self.rows.len() - MAX_ROWS;
            self.rows.drain(..drop);
        }
    }

    pub fn last_id(&self) -> i64 {
        self.rows.last().map(|r| r.id).unwrap_or(0)
    }

    pub fn set_status(&mut self, s: impl Into<String>) {
        self.status = s.into();
    }

    /// Visible rows, newest first.
    fn visible(&self) -> Vec<&Row> {
        let needle = self.text.to_ascii_lowercase();
        self.rows
            .iter()
            .rev()
            .filter(|r| self.cats.is_empty() || self.cats.contains(&r.category))
            .filter(|r| needle.is_empty() || r.domain.contains(&needle))
            .collect()
    }

    fn selected_row(&self) -> Option<&Row> {
        let v = self.visible();
        if self.follow {
            return v.first().copied();
        }
        let id = self.selected?;
        v.into_iter().find(|r| r.id == id)
    }

    fn move_sel(&mut self, delta: isize) {
        let v = self.visible();
        if v.is_empty() {
            return;
        }
        let cur = if self.follow { 0 } else { self.selected.and_then(|id| v.iter().position(|r| r.id == id)).unwrap_or(0) as isize };
        let next = (cur + delta).clamp(0, v.len() as isize - 1) as usize;
        let id = v[next].id;
        self.follow = next == 0;
        self.selected = Some(id);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Act> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Act::Quit);
        }
        if self.typing {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.typing = false,
                KeyCode::Backspace => {
                    self.text.pop();
                }
                KeyCode::Char(c) => self.text.push(c),
                _ => {}
            }
            return None;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(Act::Quit),
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-(PAGE as isize)),
            KeyCode::PageDown => self.move_sel(PAGE as isize),
            KeyCode::Home | KeyCode::Char('g') => {
                self.follow = true;
                self.selected = None;
            }
            KeyCode::End | KeyCode::Char('G') => self.move_sel(isize::MAX / 2),
            KeyCode::Char(' ') | KeyCode::Char('p') => {
                if self.follow {
                    self.selected = self.visible().first().map(|r| r.id);
                    self.follow = false;
                } else {
                    self.follow = true;
                    self.selected = None;
                }
            }
            KeyCode::Char(c @ '1'..='6') => {
                let cat = Category::ALL[c as usize - '1' as usize];
                if !self.cats.remove(&cat) {
                    self.cats.insert(cat);
                }
            }
            KeyCode::Char('0') | KeyCode::Char('x') => {
                self.cats.clear();
                self.text.clear();
            }
            KeyCode::Char('/') => self.typing = true,
            KeyCode::Char('?') | KeyCode::Char('h') => self.show_help = !self.show_help,
            KeyCode::Char('b') => {
                let r = self.selected_row()?;
                let cat = if r.category.is_blockable() { r.category } else { Category::Ads };
                return Some(Act::Block(r.domain.clone(), cat));
            }
            KeyCode::Char('a') => return Some(Act::Allow(self.selected_row()?.domain.clone())),
            KeyCode::Char('u') => return Some(Act::Forget(self.selected_row()?.domain.clone())),
            _ => {}
        }
        None
    }

    pub fn render(&self, f: &mut Frame) {
        let [head, body, foot] = Layout::vertical([Constraint::Length(4), Constraint::Min(3), Constraint::Length(2)]).areas(f.area());

        // --- header: category chips (counts over the rows in memory) ---
        let mut counts = [0usize; 6];
        for r in &self.rows {
            counts[Category::ALL.iter().position(|c| *c == r.category).unwrap_or(5)] += 1;
        }
        let mut spans = vec![Span::raw(" ")];
        for (i, c) in Category::ALL.iter().enumerate() {
            let mut st = Style::new().fg(tui_color(*c));
            if !self.cats.is_empty() {
                st = if self.cats.contains(c) { st.add_modifier(Modifier::REVERSED | Modifier::BOLD) } else { st.add_modifier(Modifier::DIM) };
            }
            spans.push(Span::styled(format!(" {} {} {} ", i + 1, label(*c), counts[i]), st));
            spans.push(Span::raw(" "));
        }
        let mode = if self.follow { Span::styled(" LIVE ", Style::new().black().on_green()) } else { Span::styled(" PAUSED ", Style::new().black().on_yellow()) };
        let mut title = vec![Span::raw(" goop-steppa "), mode];
        if !self.text.is_empty() || self.typing {
            title.push(Span::styled(format!(" /{}{} ", self.text, if self.typing { "_" } else { "" }), Style::new().bold()));
        }
        f.render_widget(
            Paragraph::new(Line::from(spans)).wrap(Wrap { trim: false }).block(Block::bordered().title(Line::from(title))),
            head,
        );

        // --- body ---
        let vis = self.visible();
        if self.show_help {
            f.render_widget(Paragraph::new(HELP).block(Block::bordered().title(" keys ")), body);
        } else if vis.is_empty() {
            let msg = if self.rows.is_empty() {
                "Waiting for queries...\n\nIs `goop-steppa run` going, and is your system resolver pointed at it?"
            } else {
                "No queries match the current filter.  (0 clears filters)"
            };
            f.render_widget(Paragraph::new(msg).alignment(Alignment::Center).block(Block::bordered()), body);
        } else {
            let sel_idx = if self.follow { Some(0) } else { self.selected.and_then(|id| vis.iter().position(|r| r.id == id)) };
            let rows: Vec<TRow> = vis
                .iter()
                .map(|r| {
                    let color = tui_color(r.category);
                    let t = Local.timestamp_millis_opt(r.ts_ms).single().map(|t| t.format("%H:%M:%S").to_string()).unwrap_or_default();
                    let (tag, mut tag_style) = match r.action {
                        Action::Blocked => ("BLOCK", Style::new().fg(color)),
                        Action::Allowed => ("ok", Style::new().fg(color)),
                    };
                    if r.action == Action::Blocked {
                        tag_style = tag_style.add_modifier(Modifier::BOLD);
                    }
                    TRow::new(vec![
                        Cell::from(t).style(Style::new().fg(Color::DarkGray)),
                        Cell::from(tag).style(tag_style),
                        Cell::from(label(r.category)).style(Style::new().fg(color)),
                        Cell::from(r.qtype.clone()).style(Style::new().fg(Color::DarkGray)),
                        Cell::from(r.domain.clone()).style(Style::new().fg(color)),
                        Cell::from(r.source.clone().unwrap_or_default()).style(Style::new().fg(Color::DarkGray)),
                    ])
                })
                .collect();
            let table = Table::new(
                rows,
                [Constraint::Length(8), Constraint::Length(5), Constraint::Length(17), Constraint::Length(6), Constraint::Min(20), Constraint::Length(26)],
            )
            .header(TRow::new(["time", "", "category", "type", "domain", "list"]).style(Style::new().bold()))
            .column_spacing(1)
            .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .block(Block::bordered());
            let mut st = TableState::default().with_selected(sel_idx);
            f.render_stateful_widget(table, body, &mut st);
        }

        // --- footer ---
        let status = Line::from(Span::styled(format!(" {}", self.status), Style::new().bold()));
        let keys = Line::from(Span::styled(
            " q quit  ↑↓ move  space pause  1-6 filter  0 clear  / search  b block  a allow  u forget  ? help",
            Style::new().fg(Color::DarkGray),
        ));
        f.render_widget(Paragraph::new(vec![status, keys]), foot);
    }
}

const HELP: &str = "
  Navigation   ↑/k ↓/j  move      PgUp/PgDn  page      g / Home  jump to newest & follow
               G / End  oldest in buffer                 space / p  pause or resume following

  Filtering    1 malware   2 telemetry   3 ads   4 allowlisted   5 clean   6 unknown/new
               (press again to toggle; several can be on)     / text search      0 or x  clear all

  Actions      b  block selected domain (+ subdomains), keeping its category (ads if it had none)
               a  allow selected domain (+ subdomains)  - the allowlist always wins
               u  forget: remove selected domain from your block AND allow lists

  Edits go to ~/.config/goop-steppa/{blocklist,allowlist}.txt; a running daemon applies them in ~2s.
  q / Esc / Ctrl-C quit.
";

/// Run the TUI until the user quits.
pub fn run(store: &Store, files: &UserFiles) -> Result<()> {
    let mut app = App::new();
    let mut initial = store.recent(0, 500, None)?;
    initial.reverse();
    app.ingest(initial);

    let mut terminal = ratatui::init();
    let res = event_loop(&mut terminal, &mut app, store, files);
    ratatui::restore();
    res
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut App, store: &Store, files: &UserFiles) -> Result<()> {
    let mut last_poll = Instant::now();
    loop {
        terminal.draw(|f| app.render(f))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                match app.handle_key(k) {
                    Some(Act::Quit) => return Ok(()),
                    Some(Act::Block(d, c)) => app.set_status(match files.block(&d, c) {
                        Ok(()) => format!("blocked {d} ({c})"),
                        Err(e) => format!("block failed: {e:#}"),
                    }),
                    Some(Act::Allow(d)) => app.set_status(match files.allow(&d) {
                        Ok(()) => format!("allowed {d}"),
                        Err(e) => format!("allow failed: {e:#}"),
                    }),
                    Some(Act::Forget(d)) => app.set_status(match files.forget(&d) {
                        Ok(()) => format!("forgot {d} (removed from your lists)"),
                        Err(e) => format!("forget failed: {e:#}"),
                    }),
                    None => {}
                }
            }
        }
        if last_poll.elapsed() >= Duration::from_millis(300) {
            last_poll = Instant::now();
            match store.after_id(app.last_id(), 1000) {
                Ok(rows) if !rows.is_empty() => app.ingest(rows),
                Ok(_) => {}
                Err(e) => app.set_status(format!("history read failed: {e:#}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn row(id: i64, domain: &str, action: Action, cat: Category) -> Row {
        Row { id, ts_ms: 1_700_000_000_000 + id * 1000, domain: domain.into(), qtype: "A".into(), action, category: cat, source: Some("L".into()) }
    }

    fn app() -> App {
        let mut a = App::new();
        a.ingest(vec![
            row(1, "good.org", Action::Allowed, Category::Clean),
            row(2, "ads.example.com", Action::Blocked, Category::Ads),
            row(3, "evil.com", Action::Blocked, Category::Malware),
            row(4, "new.net", Action::Allowed, Category::Unknown),
        ]);
        a
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn press(a: &mut App, s: &str) -> Option<Act> {
        let mut last = None;
        for ch in s.chars() {
            last = a.handle_key(key(KeyCode::Char(ch)));
        }
        last
    }

    #[test]
    fn newest_first_and_follow_selects_newest() {
        let a = app();
        let v = a.visible();
        assert_eq!(v[0].domain, "new.net");
        assert_eq!(a.selected_row().unwrap().domain, "new.net");
    }

    #[test]
    fn category_filter_toggles() {
        let mut a = app();
        press(&mut a, "3");
        assert_eq!(a.visible().iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(), vec!["ads.example.com"]);
        press(&mut a, "1");
        assert_eq!(a.visible().len(), 2);
        press(&mut a, "3");
        assert_eq!(a.visible().len(), 1);
        press(&mut a, "0");
        assert_eq!(a.visible().len(), 4);
    }

    #[test]
    fn text_search() {
        let mut a = app();
        press(&mut a, "/");
        press(&mut a, "evil");
        a.handle_key(key(KeyCode::Enter));
        assert_eq!(a.visible().len(), 1);
        assert_eq!(a.visible()[0].domain, "evil.com");
        // typing mode swallows hotkeys like 'q'
        press(&mut a, "/");
        assert_eq!(press(&mut a, "q"), None);
    }

    #[test]
    fn selection_is_stable_when_new_rows_arrive_while_paused() {
        let mut a = app();
        a.handle_key(key(KeyCode::Down)); // moves to evil.com, pauses
        assert!(!a.follow);
        assert_eq!(a.selected_row().unwrap().domain, "evil.com");
        a.ingest(vec![row(5, "later.org", Action::Allowed, Category::Clean)]);
        assert_eq!(a.selected_row().unwrap().domain, "evil.com", "selection must not jump");
        // jump back to newest resumes following
        press(&mut a, "g");
        assert!(a.follow);
        assert_eq!(a.selected_row().unwrap().domain, "later.org");
    }

    #[test]
    fn moving_back_to_top_resumes_follow_and_bounds_hold() {
        let mut a = app();
        a.handle_key(key(KeyCode::Down));
        a.handle_key(key(KeyCode::Up));
        assert!(a.follow);
        press(&mut a, "G");
        assert_eq!(a.selected_row().unwrap().domain, "good.org");
        a.handle_key(key(KeyCode::Down)); // clamped at the oldest
        assert_eq!(a.selected_row().unwrap().domain, "good.org");
    }

    #[test]
    fn block_allow_forget_actions() {
        let mut a = app();
        a.handle_key(key(KeyCode::Down)); // evil.com (malware)
        assert_eq!(press(&mut a, "b"), Some(Act::Block("evil.com".into(), Category::Malware)));
        assert_eq!(press(&mut a, "a"), Some(Act::Allow("evil.com".into())));
        assert_eq!(press(&mut a, "u"), Some(Act::Forget("evil.com".into())));
        press(&mut a, "g"); // new.net is unknown: blocking defaults to ads
        assert_eq!(press(&mut a, "b"), Some(Act::Block("new.net".into(), Category::Ads)));
    }

    #[test]
    fn actions_with_nothing_selected_do_nothing() {
        let mut a = App::new();
        assert_eq!(press(&mut a, "b"), None);
        assert_eq!(press(&mut a, "a"), None);
    }

    #[test]
    fn quit_keys() {
        let mut a = app();
        assert_eq!(press(&mut a, "q"), Some(Act::Quit));
        assert_eq!(a.handle_key(key(KeyCode::Esc)), Some(Act::Quit));
        assert_eq!(a.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)), Some(Act::Quit));
    }

    #[test]
    fn buffer_is_capped() {
        let mut a = App::new();
        a.ingest((0..(MAX_ROWS as i64 + 50)).map(|i| row(i + 1, "a.com", Action::Allowed, Category::Clean)).collect());
        assert_eq!(a.rows.len(), MAX_ROWS);
        assert_eq!(a.rows[0].id, 51);
    }

    fn draw(a: &App, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| a.render(f)).unwrap();
        t.backend().buffer().clone()
    }

    fn text(b: &ratatui::buffer::Buffer) -> String {
        (0..b.area.height).map(|y| (0..b.area.width).map(|x| b[(x, y)].symbol().to_string()).collect::<String>()).collect::<Vec<_>>().join("\n")
    }

    /// Foreground color of the first cell of `needle`'s first occurrence.
    fn fg_of(b: &ratatui::buffer::Buffer, needle: &str) -> Option<Color> {
        for y in 0..b.area.height {
            let line: String = (0..b.area.width).map(|x| b[(x, y)].symbol().to_string()).collect();
            if let Some(x) = line.find(needle) {
                return Some(b[(x as u16, y)].fg);
            }
        }
        None
    }

    #[test]
    fn renders_rows_in_category_colors() {
        let b = draw(&app(), 110, 16);
        let t = text(&b);
        for n in ["goop-steppa", "LIVE", "evil.com", "BLOCK", "malware/phishing", "new.net", "q quit"] {
            assert!(t.contains(n), "missing {n:?}\n{t}");
        }
        assert_eq!(fg_of(&b, "evil.com"), Some(Color::Indexed(9)), "malware = red");
        assert_eq!(fg_of(&b, "ads.example.com"), Some(Color::Indexed(11)), "ads = yellow");
        assert_eq!(fg_of(&b, "good.org"), Some(Color::Indexed(10)), "clean = green");
    }

    #[test]
    fn renders_empty_state_and_filtered_empty_state() {
        let t = text(&draw(&App::new(), 90, 12));
        assert!(t.contains("Waiting for queries"));
        let mut a = app();
        press(&mut a, "2"); // no telemetry rows
        assert!(text(&draw(&a, 90, 12)).contains("No queries match"));
    }

    #[test]
    fn paused_indicator_and_help() {
        let mut a = app();
        press(&mut a, " ");
        assert!(text(&draw(&a, 100, 12)).contains("PAUSED"));
        press(&mut a, "?");
        assert!(text(&draw(&a, 120, 24)).contains("the allowlist always wins"));
    }

    #[test]
    fn mode_indicator_visible_at_80_columns() {
        let t = text(&draw(&app(), 80, 14));
        assert!(t.contains("LIVE"), "{t}");
        assert!(t.contains("6 unknown/new"), "chips must wrap, not be cut off:\n{t}");
    }

    #[test]
    fn status_line_is_rendered() {
        let mut a = app();
        a.set_status("blocked evil.com (malware)");
        assert!(text(&draw(&a, 100, 14)).contains("blocked evil.com (malware)"));
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let _ = draw(&app(), 20, 5);
        let _ = draw(&app(), 1, 1);
    }
}
