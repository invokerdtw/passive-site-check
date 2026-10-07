繁體中文 | [English](README.en.md)

# 網站被動資安健檢（passive-site-check）

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-brightgreen.svg)](CHANGELOG.zh-TW.md)
[![報告語言](https://img.shields.io/badge/%E5%A0%B1%E5%91%8A%E8%AA%9E%E8%A8%80-%E8%B7%9F%E9%9A%A8%E6%8F%90%E5%95%8F-blue.svg)](#使用)

給一個網址，Claude 會對網站做一次**被動**資安檢查，再寫成紅黃綠燈的白話報告。每一項都附位置、證據和修法。

適合會做網站、但不熟資安的人，例如個人站，或放在 Cloudflare Pages／Firebase／Vercel 上的前端網站。

> ⚠️ 只能用在**你自己的網站**，或**你有權檢查的網站**。

## 最快的安裝方式：交給 AI

把這個網址貼給 AI（Claude Code、claude.ai、Codex 都可以），說一句「幫我裝」：

```
https://github.com/invokerdtw/passive-site-check
```

AI 會讀 [INSTALL_FOR_AI.zh-TW.md](INSTALL_FOR_AI.zh-TW.md)，判斷你用的是哪個環境，然後幫你裝好或帶你一步步裝。

## 手動安裝

**Claude Code**：

```
/plugin marketplace add invokerdtw/passive-site-check
/plugin install passive-site-check@site-check-tools
```

需要 Python 3，只用標準函式庫，不必另外裝套件。

**Codex**：把 `plugins/passive-site-check/skills/site-security-check/` 整個資料夾複製到 `~/.codex/skills/`，重開 Codex。

**claude.ai**：
1. 下載 [`claude-ai/site-security-check.zip`](claude-ai/site-security-check.zip)，不要解壓縮。
2. 在 Settings → Capabilities 開啟 Code execution。
3. 在 Skills 區上傳那個 zip。

> claude.ai 實測（免費帳號）：程式碼環境只能連白名單網域，抓取工具不接受自己組的網址，所以多半只能做部分檢查，剩下的會請你貼網址或標頭。要完整檢查請用 Claude Code 或 Codex。

## 使用

對 Claude 說：「幫我資安健檢 https://my-site.example」

報告語言跟著你的提問走：用中文問就出台灣繁體中文報告，用英文問（"security check my site https://my-site.example"）就出英文報告，其他語言照該語言。也可以直接說「用中文」或 "in English" 指定。

## 會查什麼

| 項目 | 說明 |
|---|---|
| 不該公開的檔案 | `.git`、`.env`、source map。用內容比對判定，不會因為網站把所有網址都導回首頁而誤報 |
| 前端外洩的金鑰 | OpenAI、Anthropic、Stripe、AWS、GitHub、Supabase service_role 等。只記錄位置和前 6 碼，**不會拿去測試能不能用** |
| 安全標頭 | CSP、HSTS、X-Frame-Options 等 |
| 外部資源 | 外部腳本有沒有 SRI、有沒有混合內容、危險的 DOM 寫法 |
| Firebase／Supabase | 從程式碼推斷有沒有開放未登入讀寫，不會真的去讀寫資料庫 |
| 隱私 | 使用者資料、表單、對話被送到哪些第三方 |
| 提示注入 | 網頁裡藏著要 AI 做事的文字。會列出來，不會照做 |

## 不會做什麼

- 不掃描、不猜路徑、不送表單、不登入、不測金鑰。
- 不下載 `.git` 歷史，不打開報告裡提到的雲端連結。
- 只送普通 GET，總請求數預設上限 60，單次檢查最長 3 分鐘。
- 轉址只跟同一個網站。首頁轉到別的網域時會先停下來，請你確認新網域也是你的。

這是自動化的被動檢查，**不等於完整的滲透測試**。

## 檔案結構

```
.claude-plugin/marketplace.json          Claude Code marketplace
plugins/passive-site-check/              plugin 本體
  └ skills/site-security-check/
      ├ SKILL.md                          判讀規則與報告格式
      └ probe.py                          被動檢查程式（Python 標準函式庫）
claude-ai/site-security-check.zip        claude.ai 上傳用
INSTALL_FOR_AI.zh-TW.md                  給 AI 讀的安裝說明（英文版：INSTALL_FOR_AI.md）
CHANGELOG.zh-TW.md                       版本紀錄（英文版：CHANGELOG.md）
```

`probe.py` 可以單獨執行：`python3 probe.py https://my-site.example`，結果會印成 JSON。

## 授權

[MIT](LICENSE)
