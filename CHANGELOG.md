# Changelog

## 0.4.1 — 2026-10-05

首次公開版本。

- Claude Code plugin 與 claude.ai skill 兩種安裝方式，共用同一份判讀規則。
- 被動檢查：公開檔案（`.git`／`.env`／source map）、前端金鑰、安全標頭、SRI、混合內容、Firebase／Supabase、隱私去向、提示注入。
- 安全設計：
  - 只送 GET，請求數與總時間有上限。
  - 轉址只跟同一個網站，擋 `file://` 等非 HTTP 協定。
  - 輸出裡的金鑰一律遮罩，只留前 6 碼。
  - 判定檔案外洩靠內容比對，不看狀態碼。
