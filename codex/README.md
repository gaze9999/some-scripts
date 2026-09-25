# 清理雲端無法刪除的任務

## 執行 PowerShell Script

Execution Policy 阻擋 `.ps1` 時:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-cloud-task-ids.ps1
```

目前環境已允許執行 Script 時:

```powershell
.\get-codex-cloud-task-ids.ps1
```

先使用 Dry Run:

```js
const MODE = 'dry-run';
```

確認後改為:

```js
const MODE = 'delete';
```

最後確認剩餘 Cloud tasks:

```powershell
codex cloud list
```

## 步驟

```plaintext
PowerShell
    │
    ├─ codex cloud list
    │     ↓
    ├─ 自動追蹤所有 --cursor
    │     ↓
    ├─ Regex 擷取 task_e_...
    │     ↓
    └─ taskIds JS Array → Clipboard
                    │
                    v
ChatGPT Web DevTools
                    │
                    ├─ MODE = 'dry-run'
                    │
                    ├─ 確認清單
                    │
                    └─ MODE = 'delete'
                              ↓
                 DELETE /wham/tasks/{id}
                              ↓
                         GET 驗證
                              ↓
                         HTTP 404
```