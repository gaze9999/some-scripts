```
tgs-exhibitors/                    # Tokyo Game Show 展覽商家爬蟲工具
├── README.md                       # 基本說明和使用範例
├── GUIDE.md                        # 完整使用指南
├── requirements.txt                # Python 依賴列表
├── .gitignore                      # Git 忽略規則
│
├── scraper.py                      # 主爬蟲工具
│   └── 功能：
│       • 載入 CSV 資料
│       • 統計分析
│       • 圖片下載
│       • JSON/CSV 匯出
│
├── analyzer.py                     # 進階分析工具
│   └── 功能：
│       • 按國家/展區篩選
│       • 關鍵字搜尋
│       • 統計分析
│       • 資料匯出
│
├── quickstart.py                   # 快速開始腳本
│   └── 功能：
│       • 一鍵執行基本分析
│       • 生成統計報告
│       • 匯出結果
│
├── tgs_exhibitors.csv              # 核心資料檔案
│   └── 包含：
│       • Exhibitor (參展商名稱)
│       • Location (展區位置)
│       • Area (展示區域)
│       • Booth Number (攤位編號)
│       • Country (國家/地區)
│       • Is Online (線上展示)
│       • Exhibitor Figure (圖片 URL)
│       • Exhibitor ID (ID)
│
└── output/                         # 輸出目錄
    ├── tgs_report.json             # 統計報告
    ├── tgs_exhibitors.json         # 完整資料 JSON
    ├── countries_statistics.csv    # 國家統計
    ├── areas_statistics.csv        # 展區統計
    └── images/                     # 下載的紀者圖片
        ├── 参展商名_ID.jpg
        └── ...
```

## 使用流程

### 第 1 步：安裝依賴

```bash
pip3 install -r requirements.txt
```

### 第 2 步：選擇你的操作

#### 快速分析（推薦新手）
```bash
python3 quickstart.py
```

#### 詳細分析
```bash
python3 scraper.py --action analyze
```

#### 下載所有圖片
```bash
python3 scraper.py --action download
```

#### 進階分析
```bash
python3 analyzer.py
```

### 第 3 步：查看結果

```bash
# 查看統計報告
cat output/tgs_report.json

# 查看國家統計
cat output/countries_statistics.csv

# 查看展區統計
cat output/areas_statistics.csv
```

## 核心功能

### 1. 資料載入
✓ 支援 UTF-8 和 BIG5 編碼
✓ 自動驗證資料完整性
✓ 錯誤處理和提示

### 2. 統計分析
✓ 按國家統計參展商數量
✓ 按展區統計參展商數量
✓ 線上展示統計
✓ 生成統計報告

### 3. 資料搜尋
✓ 關鍵字搜尋
✓ 按國家篩選
✓ 按展區篩選
✓ 按位置篩選

### 4. 資料匯出
✓ JSON 格式
✓ CSV 格式
✓ 統計報告
✓ 圖片下載

## 常見用法

### 查詢特定國家的參展商

```python
from analyzer import TGSAnalyzer

analyzer = TGSAnalyzer()

# 查詢韓國參展商
korea = analyzer.get_exhibitors_by_country('韓国')
print(f"韓國參展商: {len(korea)}")
print(korea[['Exhibitor', 'Booth Number']])

# 查詢日本參展商
japan = analyzer.get_exhibitors_by_country()
print(f"日本參展商: {len(japan)}")
```

### 搜尋特定參展商

```python
from analyzer import TGSAnalyzer

analyzer = TGSAnalyzer()

# 搜尋包含"バンダイ"的參展商
results = analyzer.search_exhibitor('バンダイ')
print(results[['Exhibitor', 'Location', 'Booth Number']])
```

### 按展區篩選

```python
from analyzer import TGSAnalyzer

analyzer = TGSAnalyzer()

# 查詢 Family Game Park 的參展商
family_park = analyzer.get_exhibitors_by_area('ファミリーゲームパーク')
print(f"Family Park: {len(family_park)}")
print(family_park[['Exhibitor', 'Booth Number']])
```

### 匯出統計報告

```python
from scraper import TGSExhibitorScraper

scraper = TGSExhibitorScraper()
scraper.load_exhibitors()
scraper.generate_report()           # 生成 JSON 報告
scraper.export_json()               # 匯出完整 JSON
scraper.export_statistics_csv()     # 匯出統計 CSV
```

## 部署到 Vue Practice 應用

### 方法 1: 靜態資料集成

```bash
# 複製資料到 Vue Practice 的公開目錄
cp tgs_exhibitors.csv ~/works/socs2_frontend/public/data/
cp output/tgs_exhibitors.json ~/works/socs2_frontend/public/data/
```

### 方法 2: API 端點

在 Vue Practice 中建立新的模組來展示此資料：

```typescript
// modules/exhibitors/types/index.ts
export interface Exhibitor {
  exhibitor: string
  location: string
  area: string
  booth_number: string
  country?: string
  is_online: string
  exhibitor_figure?: string
  exhibitor_id: string
}
```

## 性能優化

### 加快圖片下載

```bash
# 增加 worker 數量（預設 5）
python3 -c "
from scraper import TGSExhibitorScraper
scraper = TGSExhibitorScraper()
scraper.load_exhibitors()
scraper.download_images(max_workers=10)
"
```

### 批量處理大量資料

```python
import pandas as pd
from pathlib import Path

# 分批處理
chunk_size = 100
df = pd.read_csv('tgs_exhibitors.csv')

for i, chunk in enumerate(df.groupby(df.index // chunk_size)):
    print(f"處理批次 {i+1}")
    # 執行操作...
```

## 故障診斷

### 檢查安裝狀態

```bash
python3 -c "
import pandas; print('✓ pandas OK')
import requests; print('✓ requests OK')
from bs4 import BeautifulSoup; print('✓ BeautifulSoup OK')
"
```

### 驗證資料完整性

```bash
python3 scraper.py --action load
```

### 查看詳細日誌

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from scraper import TGSExhibitorScraper
scraper = TGSExhibitorScraper()
scraper.load_exhibitors()
```

## 技術棧

| 組件          | 版本  | 用途      |
| ------------- | ----- | --------- |
| Python        | 3.8+  | 執行環境  |
| pandas        | 2.0+  | 資料處理  |
| requests      | 2.31+ | HTTP 請求 |
| BeautifulSoup | 4.12+ | HTML 解析 |

## 許可和使用條款

- 資料來源：Tokyo Game Show 官方
- 此工具僅供教學和研究使用
- 請尊重參展商的知識產權和隱私

## 版本歷史

**v1.0.0 (2026-02-24)**
- ✨ 初始版本發佈
- 🎉 包含 20+ 筆範例資料
- 📊 完整的分析工具
- 📝 詳細的文檔說明

## 相關資源

- [TGS 官方網站](https://tgs.cesa.or.jp/)
- [Pandas 文檔](https://pandas.pydata.org/docs/)
- [Requests 文檔](https://requests.readthedocs.io/)
- [BeautifulSoup 文檔](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)

---

**建立日期**: 2026-02-24  
**最後更新**: 2026-02-24  
**專案狀態**: ✅ 穩定版本
