[繁體中文](CHANGELOG.zh-TW.md) | English

# Changelog

## 0.5.0 — 2026-10-07

- The report now follows the user's language: ask in English and you get an English report; ask in Chinese and you get Traditional Chinese (Taiwan); other languages get that language; English when it can't tell. You can also name the language explicitly, for example "in English".
- `probe.py` messages (warnings, reasons, help text) are now in English. Detection logic, the GET-only rule, and the request cap are unchanged.
- Plugin and marketplace descriptions are now bilingual.
- The documentation (README, INSTALL_FOR_AI, CHANGELOG) now comes as separate English and Traditional Chinese files. Each file has a language switch on its first line, and links between documents stay in the same language.

## 0.4.2 — 2026-10-05

- When important items could not be checked (security headers, same-site JS, public paths), the first line of the report now says "partial: N items not checked" instead of looking like everything passed.
- Added test results for claude.ai free accounts: the code environment can only reach allowlisted domains and the fetch tool rejects URLs it builds itself, so usually only a partial check is possible.

## 0.4.1 — 2026-10-05

First public release.

- Three ways to install (Claude Code plugin, claude.ai skill, Codex skill), all sharing the same interpretation rules.
- Passive checks: public files (`.git`, `.env`, source maps), frontend keys, security headers, SRI, mixed content, Firebase/Supabase, where data goes, prompt injection.
- Safety design:
  - GET only, with caps on request count and total time.
  - Redirects are followed only within the same site; `file://` and other non-HTTP schemes are blocked.
  - Keys in the output are always masked, keeping only the first 6 characters.
  - File exposure is decided by matching content, not by status code.
