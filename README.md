# NeuroSploit v3.4.1 🦀

![Version](https://img.shields.io/badge/Version-3.4.1-blue)
![Harness](https://img.shields.io/badge/Harness-Rust%20%7C%20tokio-e6b673)
![License](https://img.shields.io/badge/License-MIT-green)
![Agents](https://img.shields.io/badge/MD%20Agents-249-red)
![Models](https://img.shields.io/badge/Models-12%20providers-success)

**Autonomous, multi-model penetration-testing harness — Rust, CLI-only.**

This branch is the **slim, Rust-only** distribution: the `neurosploit-rs/` workspace
plus the `agents_md/` agent library. It turns a URL (black-box) or a code
repository (white-box) into an autonomous engagement that drives a pool of LLMs
— via **API key** or local **subscription** (Claude Code / Codex / Gemini / Grok)
— recons the target, **intelligently selects only the agents matching the
discovered surface**, runs them in parallel, then validates every finding by
**cross-model voting** before reporting.

> The full project (Python engine, web GUIs, history) lives on the `main` branch.

---

## Build

```bash
cd neurosploit-rs
cargo build --release        # → target/release/neurosploit
```

Requires a Rust toolchain (`rustup`). **Recommended: run on Kali Linux** (or the
Kali Docker image) so the offensive tools the agents use are already present:

```bash
docker run -it --rm kalilinux/kali-rolling
apt update && apt install -y curl nmap ffuf nodejs npm
# rustscan (faster port scan): cargo install rustscan   (or grab a release from GitHub)
```

The agents degrade gracefully: if `rustscan` isn't installed they use `nmap`; if
neither, they probe with `curl`. If a Playwright MCP browser is available they use
it for JS-heavy pages, otherwise they fall back to `curl`.

---

## Usage

Run with **no arguments** for an interactive wizard:

```bash
./target/release/neurosploit
```

Or drive it directly:

```bash
# Black-box — subscription (no API key), Opus, browser via Playwright if present, verbose
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --subscription --model anthropic:claude-opus-4-8 --mcp -v

# Black-box — API keys, multi-model voting panel (1st finds, others adjudicate)
./target/release/neurosploit run http://testphp.vulnweb.com/ \
    --model anthropic:claude-opus-4-8 --model openai:gpt-5.1 --vote-n 3

# White-box — clone a vulnerable app and review its source
git clone https://github.com/digininja/DVWA /tmp/DVWA
./target/release/neurosploit whitebox /tmp/DVWA \
    --subscription --model anthropic:claude-opus-4-8 -v

# Offline pipeline self-test (no keys/login needed)
./target/release/neurosploit run http://testphp.vulnweb.com/ --offline

# Utilities
./target/release/neurosploit agents     # library counts
./target/release/neurosploit models      # providers & models
./target/release/neurosploit --help        # full help with examples
```

### Options (`run` / `whitebox`)

| Flag | Meaning |
|------|---------|
| `--model provider:model` | Repeatable. First = primary; the rest fail over **and** form the voting jury. |
| `--subscription` | Use the local CLI login (Claude/Codex/Gemini/Grok) instead of an API key. |
| `--mcp` | Enable Playwright MCP (auto-provisioned via `npx`; backends without MCP use built-in tools). |
| `--vote-n N` | How many models must agree a finding is real (default 3 / 2 for whitebox). |
| `--max-agents N` | Cap agents run (`0` = all matching the recon). |
| `--offline` | Exercise the full pipeline without calling any model. |
| `-v, --verbose` | Log each agent as it launches, recon, and votes. |

### Auth

- **API key** — export the provider's key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`, `XAI_API_KEY`, `NVIDIA_NIM_API_KEY`, …). See `.env.example`.
- **Subscription** — `--subscription` drives your local `claude` / `codex` /
  `gemini` / `grok` login. No API key needed.

---

## How it works

```
target ─▶ recon (curl/nmap/…) ─▶ INTELLIGENT agent selection (recon-aware)
       ─▶ parallel exploitation ─▶ cross-model validation vote
       ─▶ severity/score ─▶ report (HTML + Typst PDF) ─▶ RL reward update
```

Every run writes a self-contained folder `runs/ns-<ts>-<target>/`:

| File | Contents |
|------|----------|
| `status.json` | `running` → `complete` with a summary |
| `recon.json` / `recon.md` | mapped attack surface |
| `exploitation.md` | raw per-agent transcript |
| `findings.json` / `findings.md` | validated findings (reuse by other tools/AIs) |
| `report.html`, `report.typ`, `report.pdf` | final report (PDF via the Typst engine) |

A reinforcement-learning reward store (`data/rl_state_rs.json`) biases agent
selection on future runs.

## Agent library — `agents_md/` (249)

| Category | Count | Purpose |
|----------|-------|---------|
| `vulns/` | 196 | Exploit a specific vulnerability class |
| `recon/` | 12 | Information gathering / attack surface |
| `code/` | 24 | White-box source-code (SAST) review |
| `meta/` | 17 | Orchestrator, validator, scorers, reporter, RL |

Each agent is a self-contained markdown playbook (`## User Prompt` methodology +
`## System Prompt` strict anti-false-positive rules). Drop a new `.md` into the
matching folder and the harness picks it up.

---

## Safety

For **authorized** testing only. Agents are instructed to stay in scope, never run
destructive/DoS actions, and require proof-of-exploitation. You are responsible for
having permission for any target.

## License

MIT.
