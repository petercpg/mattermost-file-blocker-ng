# Mattermost File Blocker NG Plugin

[![CI](https://github.com/mattermost/mattermost-file-blocker-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/mattermost/mattermost-file-blocker-ng/actions/workflows/ci.yml)
[![Mattermost 11.7 ESR](https://img.shields.io/badge/Mattermost-11.7%20ESR-blue.svg)](https://mattermost.com)

**Mattermost File Blocker NG** 是一款專為企業安全設計的 Mattermost 伺服器端外掛。外掛基於官方 [mattermost-plugin-starter-template](https://github.com/mattermost/mattermost-plugin-starter-template) 樣板開發，最低相容支援 **Mattermost 11.7 ESR** 及其以上版本。

透過 Mattermost 核心的 `FileWillBeUploaded` 掛鉤，本外掛能即時攔截未經授權的檔案上傳，有效防禦惡意可執行檔投遞、偽裝副檔名繞過、以及近年氾濫的 **ClickFix / 社交工程指令檔釣魚攻擊**。全功能內建多語言（i18n）支援（繁體中文、英文等）。

---

## 🛡️ 核心防禦能力與特色

1. **雙重過濾模式 (Blacklist vs Whitelist)**
   - **黑名單模式（預設）**：阻擋常見高風險副檔名（`.exe`, `.bat`, `.cmd`, `.sh`, `.ps1`, `.vbs`, `.js`, `.lnk` 等，不阻擋 `.iso`）。
   - **白名單模式（嚴格資安）**：僅允許特定副檔名（如 `.pdf`, `.png`, `.jpg`, `.docx` 等），其餘一律攔截。

2. **多層與雙重副檔名分析 (Double Extension Inspection)**
   - 精準防範攻擊者常用之詐騙後綴（如 `ClickFix_Update.pdf.bat`、`invoice.doc.ps1`）。只要檔名任一層級命中黑名單即判定違規。

3. **深度特徵探測 (Magic Bytes & Script Sniffing)**
   - **可執行檔特徵探測**：分析檔案開頭前 512 bytes，精準識別 Windows PE（`MZ`）、Linux ELF、macOS Mach-O 與 Windows 捷徑（`LNK`）。即使惡意程式改名為 `.txt` 或 `.pdf` 亦無所遁形。
   - **Shebang 與腳本特徵嗅探**：偵測 Unix Shebang（`#!/bin/sh`、`#!/bin/bash`）與常見 Windows 批次/PowerShell 攻擊特徵碼（如 `@echo off`、`powershell.exe -enc`、`certutil`、`mshta`）。

4. **ZIP 壓縮包內嵌掃描 (Inspect Inside Archives)**
   - 許多 ClickFix 攻擊會將惡意腳本壓縮為 `.zip` 傳遞。本外掛可自動解析 ZIP Central Directory，若包內藏有黑名單副檔名，**整包直接阻擋**。

5. **細緻豁免機制 (Exemptions)**
   - 支援系統管理員（System Admins）免受限制。
   - 支援指定頻道 ID 豁免（例如專屬 IT 測試頻道）。

6. **友善回饋與即時審計 (Auditing & Alerting)**
   - 阻擋時向使用者展示自訂提示，支援動態變數：`{{filename}}`、`{{extension}}`、`{{reason}}`。
   - 伺服器端結構化 Audit Log 記錄。
   - （選用）即時將資安阻擋事件推播至指定的管理頻道。

---

## ⚙️ 後台設定說明 (System Console)

安裝並啟用外掛後，系統管理員可前往 **System Console > Plugins > File Blocker NG** 進行配置：

| 設定項目 | 鍵值 (Key) | 預設值 | 說明 |
| :--- | :--- | :--- | :--- |
| **Enable File Blocker** | `EnableBlocker` | `true` | 是否啟用檔案攔截功能 |
| **Filtering Mode** | `FilterMode` | `blacklist` | 檢查模式：`blacklist`（黑名單）或 `whitelist`（白名單） |
| **Blocked Extensions** | `BlockedExtensions` | `exe, bat, cmd, sh, bash, ps1, psm1, dll, com, vbs, js, hta, scr, pif, reg, lnk` | 封鎖的副檔名清單（逗號分隔，不分大小寫） |
| **Allowed Extensions** | `AllowedExtensions` | `pdf, doc, docx, xls, xlsx, ppt, pptx, png, jpg, jpeg, gif, txt, zip` | 白名單模式下允許的副檔名清單 |
| **Blocked MIME Types** | `BlockedMimeTypes` | `application/x-msdownload, application/x-sh, application/x-bat, application/x-executable` | 封鎖的 MIME 類型（支援萬用字元 `*`） |
| **Enable Deep Inspection** | `EnableDeepInspection` | `true` | 是否啟用二進位檔頭與 ClickFix 腳本特徵檢查 |
| **Inspect Inside ZIP Archives** | `InspectZipArchives` | `true` | 是否掃描 ZIP 壓縮包內部的檔案名稱 |
| **Exempt System Administrators** | `AllowSystemAdmins` | `true` | 系統管理員是否豁免檔案上傳限制 |
| **Exempt Channel IDs** | `ExemptChannelIDs` | `""` | 豁免檢查的頻道 ID（逗號分隔） |
| **Custom Rejection Message** | `CustomRejectMessage` | `"檔案上傳遭拒：系統資安政策禁止上傳此類型的檔案或腳本。請注意防範 ClickFix 與假指令攻擊。如有業務需求請洽 IT 資安人員。"` | 阻擋時向使用者呈現的自訂錯誤訊息 |
| **Security Alert Channel ID** | `AlertChannelID` | `""` | 發送阻擋告警之頻道 ID，留空則僅記錄 Log |

---

## 🛠️ 開發與編譯指南

### 環境需求
- **Go**: 1.24+ 或 1.26+（已驗證支援最新 Go 版本）
- **Mattermost Server**: 11.7 ESR 以上版本
- **GNU Make**

### 常用命令

```bash
# 1. 執行所有單元測試
make test

# 2. 跨平台編譯伺服器端二進位檔 (Linux, Darwin, Windows)
make server

# 3. 產出正式外掛安裝包 (dist/com.mattermost.file-blocker-ng-0.1.0.tar.gz)
make dist

# 4. 清理構建產物
make clean
```

---

## 📦 安裝步驟

1. 執行 `make dist`，產出檔案位於 `dist/com.mattermost.file-blocker-ng-0.1.0.tar.gz`。
2. 登入 Mattermost 系統主控台（**System Console**）。
3. 導覽至 **Plugins > Plugin Management**。
4. 在 **Upload Plugin** 區塊中選取剛剛產出的 `.tar.gz` 壓縮包進行上傳。
5. 上傳完成後，在已安裝外掛清單中找到 **File Blocker NG** 並點擊 **Enable** 啟用。
6. 前往左側選單的 **File Blocker NG** 調整所需的安全性策略。
