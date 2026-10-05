# 本機程序排查與清理

雙擊同一個資料夾中的 `run.cmd`, 工具會檢查 Node, Python, Serena, cmd 與相關啟動程序, 清理能確認已失去呼叫端的殘留 MCP

保留這個資料夾中的所有檔案. 使用 Windows 內建 PowerShell, 執行時會開啟結果視窗, 完成後按任意鍵關閉

清理條件必須全部成立:

- 上層程序已結束, 且能辨識為支援的 MCP 啟動方式
- 屬於目前使用者及登入工作階段, 啟動已超過 5 分鐘
- 已確認標準輸入管線中斷, 程序及子程序沒有可見視窗或其他程序連線
- 觀察期間沒有持續處理工作, 清理前程序識別資訊與狀態仍相符

仍由 Codex 或 VS Code 持有的程序會保留. 無法確認用途, 權限不足, 32-bit 程序或無法驗證標準輸入管線時, 會保留並列出原因

每次結果保存為同一資料夾中的 `last-check.json`, 包含程序 ID, 來源分類, 判斷理由與本次實際終止的 ID

只檢查時, 在這個資料夾開啟 PowerShell, 執行:

```powershell
.\process-cleaner.ps1 -AuditOnly
```

標準輸入檢查使用 Windows 內部程序資訊, 啟動時會先核對目前的資料配置, 無法通過核對時保留候選程序. Windows 內部結構可能隨版本改變, 詳見 [Microsoft 的 API 說明](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
