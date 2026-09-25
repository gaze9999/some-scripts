# 清理雲端無法刪除的任務

##

- `get-codex-cloud-task-ids.ps1`: 取得清單

- `delete-codex-cloud-tasks-workaround.js`: 刪除用

## 

```powershell -ExecutionPolicy Bypass -File .\get-codex-cloud-task-ids.ps1```

`.\get-codex-cloud-task-ids.ps1`

```js const MODE = 'dry-run'; ```

```js const MODE = 'delete'; ```

```powershell codex cloud list```

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