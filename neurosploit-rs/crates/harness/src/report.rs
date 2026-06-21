use crate::types::Finding;

fn sev_rank(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn sev_color(s: &str) -> &'static str {
    match s {
        "Critical" => "#c0392b",
        "High" => "#e67e22",
        "Medium" => "#f1c40f",
        "Low" => "#3498db",
        _ => "#7f8c8d",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Render an HTML report for the validated findings.
pub fn html(target: &str, findings: &[Finding]) -> String {
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| sev_rank(&f.severity));

    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for f in &sorted {
        *counts.entry(f.severity.as_str()).or_default() += 1;
    }
    let chips: String = if counts.is_empty() {
        "<span class=chip style=background:#27ae60>No validated findings</span>".into()
    } else {
        counts
            .iter()
            .map(|(s, n)| format!("<span class=chip style=background:{}>{}: {}</span>", sev_color(s), s, n))
            .collect()
    };

    let rows: String = sorted
        .iter()
        .enumerate()
        .map(|(i, f)| {
            format!(
                "<section class=finding><h3><span class=sev style=background:{}>{}</span> {}. {}</h3>\
                 <div class=m>{} · {} · CVSS {} · votes {} · conf {:.2}</div>\
                 <div class=m>Endpoint: {}</div>\
                 <h4>Payload</h4><pre>{}</pre><h4>Evidence</h4><pre>{}</pre>\
                 <h4>Impact</h4><p>{}</p><h4>Remediation</h4><p>{}</p></section>",
                sev_color(&f.severity), esc(&f.severity), i + 1, esc(&f.title),
                esc(&f.agent), esc(&f.cwe), esc(&f.cvss), esc(&f.votes), f.confidence,
                esc(&f.endpoint), esc(&f.payload), esc(&f.evidence), esc(&f.impact), esc(&f.remediation),
            )
        })
        .collect();
    let body = if rows.is_empty() {
        "<p><em>No validated findings were produced for this engagement.</em></p>".to_string()
    } else {
        rows
    };

    format!(
        "<!DOCTYPE html><html><head><meta charset=utf-8><title>NeuroSploit Report — {t}</title><style>\
         body{{font:14px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:860px;margin:40px auto;padding:0 24px}}\
         h1{{margin:0}}.meta{{color:#666;margin:4px 0 18px}}.chip{{color:#fff;border-radius:999px;padding:4px 12px;margin-right:8px;font-size:13px;font-weight:600}}\
         .finding{{border:1px solid #e3e3e3;border-radius:12px;padding:16px 20px;margin:16px 0}}.finding h3{{margin:0 0 8px;font-size:16px}}\
         .sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px;margin-right:8px}}.m{{color:#666;font-size:12px}}\
         pre{{background:#0f1117;color:#dfe6f3;padding:11px;border-radius:8px;overflow:auto;font-size:12.5px}}\
         h4{{margin:12px 0 3px;font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:#8b5cf6}}\
         .b{{color:#8b5cf6;font-weight:800}}</style></head><body>\
         <h1><span class=b>NeuroSploit</span> Penetration Test Report</h1>\
         <div class=meta>Target: <b>{t}</b> · v3.4.0 Rust harness · multi-model validated</div>\
         <div>{chips}</div><h2>Findings ({n})</h2>{body}\
         <p class=meta>Authorized testing only. Findings confirmed by multi-model adversarial voting.</p></body></html>",
        t = esc(target), chips = chips, n = sorted.len(), body = body,
    )
}
