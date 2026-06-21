use crate::agents::{Agent, Library};
use crate::pool::ModelPool;
use crate::types::{Finding, RunConfig};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::sync::mpsc::Sender;

/// Result of an engagement run.
#[derive(Default, Serialize)]
pub struct RunOutput {
    pub findings: Vec<Finding>,
    pub agents_ran: Vec<String>,
    pub candidates: usize,
}

const RECON_SYS: &str = "You are a web recon specialist. Map the target's attack surface and reply with a compact JSON object (tech, endpoints, auth, apis, ai_features). No prose.";
const VOTE_SYS: &str = "You are an adversarial security validator. Decide if the candidate finding is a REAL, reproducible, exploitable vulnerability with proof. Reply with JSON {\"verdict\":\"confirmed\"|\"rejected\",\"reason\":\"...\"}. Default to rejected when uncertain.";

/// Run the full harness pipeline, streaming human-readable progress over `tx`.
pub async fn run(cfg: RunConfig, lib: &Library, pool: &ModelPool, tx: Sender<String>) -> RunOutput {
    let _ = tx
        .send(format!(
            "Loaded {} agents ({} vuln / {} meta) · models: {} · vote_n={} · concurrency={}",
            lib.total(),
            lib.vulns.len(),
            lib.meta.len(),
            pool.candidates.iter().map(|m| m.label()).collect::<Vec<_>>().join(", "),
            cfg.vote_n,
            cfg.concurrency,
        ))
        .await;

    // ---- 1. Recon -------------------------------------------------------
    let recon = if cfg.offline {
        let _ = tx.send("recon: offline mode — skipping model calls".into()).await;
        "{}".to_string()
    } else {
        match pool.complete(RECON_SYS, &format!("Target: {}", cfg.target)).await {
            Ok((m, t)) => {
                let _ = tx.send(format!("recon complete via {}", m.label())).await;
                t
            }
            Err(e) => {
                let _ = tx.send(format!("recon failed ({e}) — continuing with empty recon")).await;
                "{}".to_string()
            }
        }
    };

    // ---- 2. Select agents ----------------------------------------------
    let cap = if cfg.max_agents > 0 { cfg.max_agents } else { lib.vulns.len() };
    let selected: Vec<Agent> = lib.vulns.iter().take(cap).cloned().collect();
    let _ = tx.send(format!("selected {} specialist agents", selected.len())).await;

    if cfg.offline {
        let _ = tx.send("offline: no exploitation performed (provide API keys to run live)".into()).await;
        return RunOutput {
            findings: vec![],
            agents_ran: selected.iter().map(|a| a.name.clone()).collect(),
            candidates: 0,
        };
    }

    // ---- 3. Exploit (parallel, bounded by the pool semaphore) ----------
    let target = cfg.target.clone();
    let candidates: Vec<Finding> = stream::iter(selected.iter().cloned())
        .map(|ag| {
            let target = target.clone();
            let recon = recon.clone();
            let txc = tx.clone();
            async move {
                let user = format!(
                    "{}\n\nReply ONLY with a JSON array of confirmed findings (may be empty []). \
                     Each item: {{id,title,severity,cwe,endpoint,payload,evidence,impact,remediation,confidence}}.",
                    ag.user.replace("{target}", &target).replace("{recon_json}", &recon)
                );
                match pool.complete(&ag.system, &user).await {
                    Ok((m, text)) => {
                        let f = extract_findings(&text, &ag.name);
                        let _ = txc
                            .send(format!("exploit {} via {} → {} candidate(s)", ag.name, m.label(), f.len()))
                            .await;
                        f
                    }
                    Err(e) => {
                        let _ = txc.send(format!("exploit {} failed: {e}", ag.name)).await;
                        vec![]
                    }
                }
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect::<Vec<Vec<Finding>>>()
        .await
        .into_iter()
        .flatten()
        .collect();

    let _ = tx.send(format!("{} candidate finding(s) — validating by {}-model vote", candidates.len(), cfg.vote_n)).await;

    // ---- 4. Validate by N-model voting ---------------------------------
    let vote_n = cfg.vote_n;
    let validated: Vec<Finding> = stream::iter(candidates.into_iter())
        .map(|mut f| {
            let txc = tx.clone();
            async move {
                let q = format!(
                    "Finding: {} | severity {} | {} | endpoint {} | payload {} | evidence {}",
                    f.title, f.severity, f.cwe, f.endpoint, f.payload, f.evidence
                );
                let (yes, total) = pool.vote(VOTE_SYS, &q, vote_n).await;
                f.validated = total > 0 && yes * 2 >= total;
                f.votes = format!("{yes}/{total}");
                if f.confidence == 0.0 && total > 0 {
                    f.confidence = yes as f64 / total as f64;
                }
                let _ = txc
                    .send(format!("vote {} → {} ({})", f.title, if f.validated { "CONFIRMED" } else { "rejected" }, f.votes))
                    .await;
                f
            }
        })
        .buffer_unordered(cfg.concurrency)
        .collect::<Vec<Finding>>()
        .await;

    let candidates = validated.len();
    let findings: Vec<Finding> = validated.into_iter().filter(|f| f.validated).collect();
    let _ = tx.send(format!("{} validated finding(s)", findings.len())).await;

    RunOutput {
        findings,
        agents_ran: selected.iter().map(|a| a.name.clone()).collect(),
        candidates,
    }
}

/// Pull a JSON array (or object) of findings out of a model's reply.
fn extract_findings(text: &str, agent: &str) -> Vec<Finding> {
    let slice = match (text.find('['), text.rfind(']')) {
        (Some(a), Some(b)) if b > a => &text[a..=b],
        _ => match (text.find('{'), text.rfind('}')) {
            (Some(a), Some(b)) if b > a => &text[a..=b],
            _ => return vec![],
        },
    };
    let mut out: Vec<Finding> = if let Ok(v) = serde_json::from_str::<Vec<Finding>>(slice) {
        v
    } else if let Ok(one) = serde_json::from_str::<Finding>(slice) {
        vec![one]
    } else {
        return vec![];
    };
    for f in out.iter_mut() {
        f.agent = agent.to_string();
        if f.id.is_empty() {
            f.id = format!("{}-{}", agent, &f.title.chars().take(12).collect::<String>());
        }
    }
    out
}
