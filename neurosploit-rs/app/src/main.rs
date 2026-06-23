//! NeuroSploit v3.4.0 — single binary: `serve` (web dashboard) or `run` (CLI).

mod web;

use clap::{Parser, Subcommand};
use harness::{agents, models::ModelRef, pool::ModelPool, types::RunConfig, RunOutput};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "neurosploit", version, about = "NeuroSploit v3.4.0 — multi-model autonomous pentest harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the web dashboard.
    Serve {
        #[arg(long, default_value_t = 8788)]
        port: u16,
    },
    /// Run an engagement from the CLI.
    Run {
        url: String,
        /// Models as provider:model (repeatable). First is primary; rest fail over + vote.
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 3)]
        vote_n: usize,
        /// Exercise the pipeline without calling any model API.
        #[arg(long)]
        offline: bool,
        /// Use local agentic CLI subscriptions (Claude Code / Codex / Grok)
        /// instead of HTTP API keys.
        #[arg(long)]
        subscription: bool,
        /// Enable Playwright MCP (browser proof) on the subscription/CLI path.
        #[arg(long)]
        mcp: bool,
    },
    /// White-box: analyse a local repository's source code for vulnerabilities.
    Whitebox {
        /// Path to the repository to analyse.
        path: String,
        #[arg(long = "model")]
        models: Vec<String>,
        #[arg(long, default_value_t = 0)]
        max_agents: usize,
        #[arg(long, default_value_t = 2)]
        vote_n: usize,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        subscription: bool,
    },
    /// Show agent library counts.
    Agents,
    /// List providers and models.
    Models,
}

/// Locate the repo root that holds `agents_md/` (walk up from CWD, then fall
/// back to the crate's compile-time location).
fn find_base() -> PathBuf {
    if let Ok(b) = std::env::var("NEUROSPLOIT_BASE") {
        return PathBuf::from(b);
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.as_path();
        for _ in 0..6 {
            if dir.join("agents_md").is_dir() {
                return dir.to_path_buf();
            }
            match dir.parent() {
                Some(p) => dir = p,
                None => break,
            }
        }
    }
    // crate is at <root>/neurosploit-rs/app → root is two levels up
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let base = find_base();

    match cli.cmd {
        Cmd::Agents => {
            let lib = agents::load(&base);
            println!("{{\"vulns\":{},\"meta\":{},\"total\":{}}}", lib.vulns.len(), lib.meta.len(), lib.total());
        }
        Cmd::Models => {
            for p in harness::providers() {
                println!("{:<4} {:<14} {} models  [{}]", p.kind, p.key, p.models.len(), p.label);
                for m in &p.models {
                    println!("      {}:{}", p.key, m);
                }
            }
        }
        Cmd::Run { url, models, max_agents, vote_n, offline, subscription, mcp } => {
            let url = if url.starts_with("http") { url } else { format!("https://{url}") };
            let mut cfg = RunConfig::new(&url);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, mcp, false).await?;
            print_findings(&out);
        }
        Cmd::Whitebox { path, models, max_agents, vote_n, offline, subscription } => {
            let mut cfg = RunConfig::new(&path);
            cfg.max_agents = max_agents;
            cfg.vote_n = vote_n;
            cfg.offline = offline;
            cfg.subscription = subscription;
            if !models.is_empty() {
                cfg.models = models;
            }
            let out = run_engagement(&base, cfg, false, true).await?;
            print_findings(&out);
        }
        Cmd::Serve { port } => {
            web::serve(base, port).await?;
        }
    }
    Ok(())
}

/// Shared engagement runner for CLI `run` / `whitebox`.
async fn run_engagement(base: &Path, mut cfg: RunConfig, mcp: bool, whitebox: bool) -> anyhow::Result<RunOutput> {
    let lib = agents::load(base);
    let workdir = base.join("runs").join(format!("{}-{}", sanitize(&cfg.target), now_ts()));
    cfg.workdir = Some(workdir.display().to_string());
    cfg.rl_path = Some(base.join("data").join("rl_state_rs.json").display().to_string());

    let mcp_config = if mcp && cfg.subscription {
        match harness::write_mcp_config(&workdir) {
            Ok(p) => {
                println!("  [*] Playwright MCP enabled → {}", p.display());
                Some(p.display().to_string())
            }
            Err(e) => {
                eprintln!("  [!] MCP config failed: {e}");
                None
            }
        }
    } else {
        None
    };

    let refs: Vec<ModelRef> = cfg.models.iter().map(|s| ModelRef::parse(s)).collect();
    let pool = ModelPool::with_auth(refs, cfg.concurrency, cfg.subscription, mcp_config);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
    let printer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            println!("  [*] {line}");
        }
    });
    let out = if whitebox {
        harness::run_whitebox(cfg, &lib, &pool, tx).await
    } else {
        harness::run(cfg, &lib, &pool, tx).await
    };
    let _ = printer.await;
    Ok(out)
}

fn print_findings(out: &RunOutput) {
    println!("\n=== {} validated finding(s) ===", out.findings.len());
    println!("{}", serde_json::to_string_pretty(&out.findings).unwrap_or_default());
    if !out.artifacts.is_empty() {
        println!("artifacts: {}", out.artifacts.join(", "));
    }
}

fn sanitize(s: &str) -> String {
    let s = s.replace("https://", "").replace("http://", "");
    let mut o: String = s.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect();
    o.truncate(50);
    let o = o.trim_matches('_').to_string();
    if o.is_empty() {
        "target".into()
    } else {
        o
    }
}

fn now_ts() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
