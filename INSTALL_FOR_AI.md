# 給 AI 的安裝說明（Installation guide for AI assistants）

> 使用者把這個 repo 的網址交給你、請你「幫我裝」時，照這份做。
> If a user gives you this repo URL and asks you to install it, follow this file.

Repo：`https://github.com/PeterChung-TW/passive-site-check`

## 第 1 步：判斷你在哪個環境

| 你是… | 走哪一節 |
|---|---|
| Claude Code（你能執行 shell 指令，而且有 `claude` 指令） | A |
| claude.ai 網頁版或桌面 App（不能在使用者電腦上執行指令） | B |
| Codex（OpenAI Codex CLI／App） | C |
| 其他 AI 工具 | D |

## A. Claude Code：你自己裝

1. 確認有 `claude` 指令：
   ```bash
   claude --version
   ```
2. 加入 marketplace 並安裝：
   ```bash
   claude plugin marketplace add PeterChung-TW/passive-site-check
   claude plugin install passive-site-check@site-check-tools
   ```
3. 驗證：
   ```bash
   claude plugin list
   ```
   清單裡看到 `passive-site-check` 才算裝好。沒看到，就把上一步的錯誤訊息原文告訴使用者，不要說成功。
4. 告訴使用者：
   - 要**開新的 Claude Code session**，skill 才會載入。
   - 用法：「幫我資安健檢 https://你的網站」。
   - 需要 Python 3，只用標準函式庫，不必另外裝套件。

**plugin 指令不能用時的備援**（例如 Claude Code 版本太舊）：
- 下載這個 repo，把 `plugins/passive-site-check/skills/site-security-check/` 整個資料夾，複製到 `~/.claude/skills/site-security-check/`。
- 複製完確認 `~/.claude/skills/site-security-check/SKILL.md` 和 `probe.py` 都在。

## B. claude.ai：請使用者照步驟做

你沒辦法替使用者上傳檔案，所以把下面這段步驟交給他：

1. 下載 skill 檔：`https://github.com/PeterChung-TW/passive-site-check/raw/main/claude-ai/site-security-check.zip`。下載後**不要解壓縮**。
2. claude.ai → Settings → Capabilities，開啟 **Code execution and file creation**。
3. 在同一頁的 Skills 區上傳那個 zip。
4. 開新對話，說「幫我資安健檢 https://你的網站」。

網頁版能不能直接連到網站，要看帳號環境。skill 會自動在三種模式之間切換，並在報告開頭寫明用了哪一種。
實測（免費帳號）：程式碼環境只能連白名單網域、抓取工具不接受自組網址，多半只能部分檢查；請事先告訴使用者，要完整檢查改用 Claude Code 或 Codex。

## C. Codex：你自己裝

Codex 讀的是同一種 SKILL.md 格式，把 skill 資料夾放進 Codex 的 skills 目錄就能用。

1. 下載 repo，把 skill 資料夾複製到 Codex 的 skills 目錄（預設在 `~/.codex/skills/`；有設 `CODEX_HOME` 的話，放在 `$CODEX_HOME/skills/`）：
   ```bash
   git clone --depth 1 https://github.com/PeterChung-TW/passive-site-check.git /tmp/passive-site-check
   mkdir -p ~/.codex/skills
   cp -r /tmp/passive-site-check/plugins/passive-site-check/skills/site-security-check ~/.codex/skills/
   ```
   Windows PowerShell 請改用：
   ```powershell
   git clone --depth 1 https://github.com/PeterChung-TW/passive-site-check.git $env:TEMP\passive-site-check
   New-Item -ItemType Directory -Force "$HOME\.codex\skills" | Out-Null
   Copy-Item -Recurse "$env:TEMP\passive-site-check\plugins\passive-site-check\skills\site-security-check" "$HOME\.codex\skills\"
   ```
2. 驗證：確認 `~/.codex/skills/site-security-check/SKILL.md` 和 `probe.py` 都在。
3. 告訴使用者：
   - 要**重新開一個 Codex session**，skill 才會載入。
   - Codex 沙箱預設可能不能連外網。檢查時 Codex 會請你核准網路存取，這是正常的。
   - 用法：「幫我資安健檢 https://你的網站」。

## D. 其他 AI 工具

- 這個 skill 的判讀規則寫在 `plugins/passive-site-check/skills/site-security-check/SKILL.md`。
- 檢查程式是同資料夾的 `probe.py`（Python 3，只送 GET）。
- 工具支援自訂指示的話，可以把 SKILL.md 當作指示載入；能執行 Python 的話，就照 SKILL.md 裡的流程跑 `probe.py`。

## 安裝時不要做的事

- 不要用 `sudo`，也不要改系統設定。這個 skill 只需要放進使用者自己的 Claude 設定資料夾。
- 不要在安裝過程中拿任何網站來測試掃描。第一次檢查必須由使用者指定**他自己的**網站。
