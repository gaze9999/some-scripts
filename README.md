# Some Scripts

個人工具腳本, 各資料夾有自己的語言、執行環境與說明, 依各自的說明執行

| 路徑 | 內容 | 說明 |
| --- | --- | --- |
| `angular/` | 使用指定專案已安裝的 TypeScript 稽核、檢查與整理 import, 另有資料遮罩工具 `masking.util.ts` | [angular/README.md](angular/README.md) |
| `codex/` | 清理 Codex 雲端無法刪除的任務 | [codex/README.md](codex/README.md) |
| `scripts/process-cleaner/` | Windows 本機程序排查與殘留 MCP 清理 | [scripts/process-cleaner/README.md](scripts/process-cleaner/README.md) |
| `scripts/clear_line_cache.sh` | macOS LINE 廣告快取清理 | 檔案開頭註解 |
| `scripts/delete-dependabot.sh` | 刪除 origin 上的 dependabot 遠端分支 | 檔案開頭註解 |
| `scripts/extract_list_unsubscribe.py` | 從原始郵件擷取並整理 List-Unsubscribe 連結 | `--help` |
| `tgs-exhibitors/` | TGS 2025 展覽商家資料與 Python 爬蟲、分析範例 | [tgs-exhibitors/README.md](tgs-exhibitors/README.md) |
| `tools/`、`tests/` | 公開內容檢查器與測試 | [docs/public-content.md](docs/public-content.md) |

`scripts/clear_line_cache.sh` 與 `codex/` 的腳本提供 dry run, 先以 dry run 確認要清除或刪除的對象

## 公開內容檢查

這是公開儲存庫, 每份 clone 先確認既有 hooks 設定, 再啟用版控內的 hooks, 需要 Python 3.10 以上

```sh
git config --local --get core.hooksPath
```

```sh
git config --local core.hooksPath .githooks
```

檢查範圍與交付前命令見 [docs/public-content.md](docs/public-content.md)
