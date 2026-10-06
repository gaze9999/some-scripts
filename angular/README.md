# Angular import 工具

三個工具使用指定專案已安裝的 TypeScript, 格式檢查另使用該專案的 Prettier 與既有設定, 不會安裝相依套件

```text
node angular/import-audit.cjs --project PROJECT_PATH --scope src/feature
node angular/check-imports.cjs --project PROJECT_PATH --scope src/feature
node angular/format-imports.cjs --project PROJECT_PATH --scope src/feature
node angular/format-imports.cjs --project PROJECT_PATH --scope src/feature --write
```

`--scope` 必須位於指定專案內, 可選單一 `.ts` 檔或目錄. 掃描略過 node_modules、Git、快取、建置與 coverage 目錄, 遇到連結會停止

`import-audit` 提供識別字使用次數的初步候選, 別名、同名區域變數、Angular template、動態載入及 symbol references 仍需編譯器或專案工具核對, 結果不能直接當成刪除 import 的依據

`check-imports` 唯讀比較 import 格式並列出重複 module、default import / export. `format-imports` 預設預覽, 只有 `--write` 才修改開頭 import 區塊與其後空白, 保留後續程式碼, 寫入前再次核對來源內容
