[繁體中文](INSTALL_FOR_AI.zh-TW.md) | English

# Installation guide for AI assistants

> If a user gives you this repo URL and asks you to install it, follow this file. Talk to the user in **their** language.

Repo: `https://github.com/invokerdtw/passive-site-check`

## Step 1: Work out which environment you are in

| You are… | Go to |
|---|---|
| Claude Code (you can run shell commands and the `claude` command exists) | A |
| claude.ai on the web or the desktop app (you cannot run commands on the user's computer) | B |
| Codex (OpenAI Codex CLI / App) | C |
| Another AI tool | D |

## A. Claude Code: install it yourself

1. Check that the `claude` command exists:
   ```bash
   claude --version
   ```
2. Add the marketplace and install:
   ```bash
   claude plugin marketplace add invokerdtw/passive-site-check
   claude plugin install passive-site-check@site-check-tools
   ```
3. Verify:
   ```bash
   claude plugin list
   ```
   It is installed only if `passive-site-check` appears in the list. If it doesn't, show the user the exact error message from the previous step; don't report success.
4. Tell the user:
   - They need to **start a new Claude Code session** for the skill to load.
   - Usage: "security check my site https://my-site.example" (any language works; the report follows the language they ask in).
   - It needs Python 3 and uses only the standard library, so there is nothing else to install.

**Fallback when plugin commands don't work** (for example, an old Claude Code version):
- Download this repo and copy the whole `plugins/passive-site-check/skills/site-security-check/` folder to `~/.claude/skills/site-security-check/`.
- Then confirm that both `~/.claude/skills/site-security-check/SKILL.md` and `probe.py` exist.

## B. claude.ai: give the user these steps

You can't upload files for the user, so hand them these steps:

1. Download the skill file: `https://github.com/invokerdtw/passive-site-check/raw/main/claude-ai/site-security-check.zip`. **Don't unzip it.**
2. claude.ai → Settings → Capabilities: turn on **Code execution and file creation**.
3. Upload that zip in the Skills section of the same page.
4. Start a new chat and say "security check my site https://my-site.example".

Whether claude.ai can reach the site directly depends on the account. The skill switches between three modes automatically and states at the top of the report which one it used.
Tested on a free account: the code environment can only reach allowlisted domains and the fetch tool rejects URLs it builds itself, so usually only a partial check is possible. Tell the user this up front; for a full check, use Claude Code or Codex.

## C. Codex: install it yourself

Codex reads the same SKILL.md format, so placing the skill folder in Codex's skills directory is enough.

1. Download the repo and copy the skill folder into Codex's skills directory (default `~/.codex/skills/`; if `CODEX_HOME` is set, use `$CODEX_HOME/skills/`):
   ```bash
   git clone --depth 1 https://github.com/invokerdtw/passive-site-check.git /tmp/passive-site-check
   mkdir -p ~/.codex/skills
   cp -r /tmp/passive-site-check/plugins/passive-site-check/skills/site-security-check ~/.codex/skills/
   ```
   On Windows PowerShell use:
   ```powershell
   git clone --depth 1 https://github.com/invokerdtw/passive-site-check.git $env:TEMP\passive-site-check
   New-Item -ItemType Directory -Force "$HOME\.codex\skills" | Out-Null
   Copy-Item -Recurse "$env:TEMP\passive-site-check\plugins\passive-site-check\skills\site-security-check" "$HOME\.codex\skills\"
   ```
2. Verify: confirm that both `~/.codex/skills/site-security-check/SKILL.md` and `probe.py` exist.
3. Tell the user:
   - They need to **start a new Codex session** for the skill to load.
   - The Codex sandbox may block network access by default. During a check Codex will ask them to approve network access; that is expected.
   - Usage: "security check my site https://my-site.example".

## D. Other AI tools

- The interpretation rules are in `plugins/passive-site-check/skills/site-security-check/SKILL.md`.
- The check script is `probe.py` in the same folder (Python 3, GET only).
- If the tool supports custom instructions, load SKILL.md as instructions; if it can run Python, run `probe.py` as described in SKILL.md.

## Don't do these during installation

- Don't use `sudo` or change system settings. The skill only needs to go into the user's own Claude (or Codex) settings folder.
- Don't test-scan any website during installation. The first check must be on a site the user names as **their own**.
