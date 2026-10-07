[繁體中文](README.md) | English

# Passive Website Security Check (passive-site-check)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-brightgreen.svg)](CHANGELOG.md)
[![Report language](https://img.shields.io/badge/report-follows%20your%20language-blue.svg)](#usage)

Give Claude a URL and it runs a **passive** security check on the site, then writes a plain-language red/yellow/green report. Every finding comes with its location, evidence, and a fix.

Built for people who make websites but don't know much about security: personal sites, or frontend sites hosted on Cloudflare Pages, Firebase, or Vercel.

> ⚠️ Use it only on **your own sites**, or sites **you are authorized to check**.

## Fastest install: let your AI do it

Paste this URL into your AI assistant (Claude Code, claude.ai, or Codex) and say "install this":

```
https://github.com/invokerdtw/passive-site-check
```

The AI reads [INSTALL_FOR_AI.md](INSTALL_FOR_AI.md), works out which environment you're in, and either installs it for you or walks you through the steps.

## Manual install

**Claude Code**:

```
/plugin marketplace add invokerdtw/passive-site-check
/plugin install passive-site-check@site-check-tools
```

Requires Python 3. It uses only the standard library, so there's nothing else to install.

**Codex**: copy the whole `plugins/passive-site-check/skills/site-security-check/` folder into `~/.codex/skills/`, then restart Codex.

**claude.ai**:
1. Download [`claude-ai/site-security-check.zip`](claude-ai/site-security-check.zip). Don't unzip it.
2. Turn on Code execution under Settings → Capabilities.
3. Upload the zip in the Skills section.

> Tested on claude.ai (free account): the code environment can only reach allowlisted domains, and the fetch tool won't accept URLs it builds itself, so you'll usually get a partial check and be asked to paste URLs or headers for the rest. For a full check, use Claude Code or Codex.

## Usage

Tell Claude: "security check my site https://my-site.example"

The report is written in the language you ask in: ask in English and you get an English report, ask in Chinese and you get Traditional Chinese, and other languages work the same way. You can also say "in English" (or any language) to choose explicitly.

## What it checks

| Area | Details |
|---|---|
| Files that shouldn't be public | `.git`, `.env`, source maps. Detected by matching content, so sites that redirect every URL to the homepage don't cause false positives |
| API keys leaked in frontend code | OpenAI, Anthropic, Stripe, AWS, GitHub, Supabase service_role, and more. Only the location and first 6 characters are recorded; **keys are never tested** |
| Security headers | CSP, HSTS, X-Frame-Options, and others |
| External resources | Whether external scripts use SRI, mixed content, and risky DOM patterns |
| Firebase / Supabase | Infers from the code whether unauthenticated reads or writes are open. It never actually reads or writes the database |
| Privacy | Which third parties receive user data, form input, or chat content |
| Prompt injection | Hidden text in the page that tries to instruct an AI. It's listed in the report, never followed |

## What it won't do

- No scanning, no path guessing, no form submissions, no logins, no key testing.
- It doesn't download `.git` history or open cloud links mentioned in the report.
- Plain GET requests only, capped at 60 requests by default, with a 3-minute limit per check.
- Redirects are followed only within the same site. If the homepage redirects to a different domain, it stops and asks you to confirm the new domain is also yours.

This is an automated passive check. **It is not a full penetration test.**

## File structure

```
.claude-plugin/marketplace.json          Claude Code marketplace
plugins/passive-site-check/              the plugin itself
  └ skills/site-security-check/
      ├ SKILL.md                          interpretation rules and report format
      └ probe.py                          passive check script (Python standard library)
claude-ai/site-security-check.zip        for uploading to claude.ai
INSTALL_FOR_AI.md                        install guide written for AI assistants (Chinese: INSTALL_FOR_AI.zh-TW.md)
CHANGELOG.md                             version history (Chinese: CHANGELOG.zh-TW.md)
```

`probe.py` can run on its own: `python3 probe.py https://my-site.example` prints the results as JSON.

## License

[MIT](LICENSE)
