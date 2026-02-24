# TGS 爬蟲工具 - 完整使用指南

## 📋 目錄

1. [快速開始](#快速開始)
2. [安裝和設置](#安裝和設置)
3. [核心工具](#核心工具)
4. [命令列參考](#命令列參考)
5. [範例代碼](#範例代碼)
6. [故障排查](#故障排查)

---

## 快速開始

### 最簡單的方式

```bash
# 1. 安裝依賴
pip3 install -r requirements.txt

# 2. 執行快速分析
python3 quickstart.py

# 3. 查看統計結果
cat output/tgs_report.json
```

### 希望看到完整結果？

```bash
# 分析當前資料
python3 scraper.py --action analyze

# 匯出為 JSON
python3 scraper.py --action export_json

# 匯出統計表格
python3 scraper.py --action export_csv
```

---

## 安裝和設置

### 系統需求

- Python 3.8+
- macOS / Linux / Windows

### 安裝步驟

```bash
# 方式 1: 使用 requirements.txt
pip3 install -r requirements.txt

# 方式 2: 分別安裝
pip3 install pandas requests beautifulsoup4

# 方式 3: 使用 pipenv (推薦給大型專案)
pipenv install
```

### 驗證安裝

```bash
python3 -c "import pandas; print('✓ pandas OK')"
python3 -c "import requests; print('✓ requests OK')"
python3 -c "from bs4 import BeautifulSoup; print('✓ BeautifulSoup OK')"
```

---

## 核心工具

### 1. 主爬蟲工具 (scraper.py)

用於基本的資料載入、分析和匯出。

**主要功能：**
- 載入 CSV 資料
- 統計分析
- 圖片下載
- JSON/CSV 匯出

**使用方式：**

```bash
# 查看所有提供的命令
python3 scraper.py --help

# 執行特定操作
python3 scraper.py --action [操作名] --csv [CSV檔案]
```

**可用操作：**

| 操作          | 說明               | 範例                                      |
| ------------- | ------------------ | ----------------------------------------- |
| `load`        | 載入並驗證資料     | `python3 scraper.py --action load`        |
| `analyze`     | 執行統計分析       | `python3 scraper.py --action analyze`     |
| `download`    | 下載所有參展商圖片 | `python3 scraper.py --action download`    |
| `report`      | 生成 JSON 報告     | `python3 scraper.py --action report`      |
| `export_json` | 匯出為 JSON 格式   | `python3 scraper.py --action export_json` |
| `export_csv`  | 匯出統計 CSV       | `python3 scraper.py --action export_csv`  |

### 2. 進階分析工具 (analyzer.py)

用於深度資料分析和搜尋。

**主要功能：**
- 按國家/展區篩選
- 搜尋參展商
- 統計分析
- 資料匯出

**使用範例：**

```bash
python3 -c "
from analyzer import TGSAnalyzer

analyzer = TGSAnalyzer()
analyzer.print_summary()  # 列印統計

# 搜尋參展商
results = analyzer.search_exhibitor('バンダイ')
print(results[['Exhibitor', 'Booth Number']]])

# 按國家篩選
japan = analyzer.get_exhibitors_by_country()
korea = analyzer.get_exhibitors_by_country('韓国')

# 按展區篩選
family_park = analyzer.get_exhibitors_by_area('ファミリーゲームパーク')

# 匯出資料
analyzer.export_to_json('output/tgs_custom.json')
"
```

### 3. 快速開始腳本 (quickstart.py)

一鍵執行所有基本操作。

```bash
python3 quickstart.py
```

---

## 命令列參考

### 基本命令

```bash
# 列出所有參展商（前 10 筆）
python3 -c "
import pandas as pd
df = pd.read_csv('tgs_exhibitors.csv')
print(df.head(10))
"

# 統計各國參展商
python3 -c "
import pandas as pd
df = pd.read_csv('tgs_exhibitors.csv')
print(df['Country'].value_counts())
"

# 篩選日本參展商
python3 -c "
import pandas as pd
df = pd.read_csv('tgs_exhibitors.csv')
japan = df[df['Country'].isna()]
print(f'日本參展商: {len(japan)}')
"

# 搜尋特定參展商
python3 -c "
import pandas as pd
df = pd.read_csv('tgs_exhibitors.csv')
result = df[df['Exhibitor'].str.contains('セガ', na=False)]
print(result[['Exhibitor', 'Booth Number', 'Area']])
"
```

### 進階命令

```bash
# 下載所有圖片
python3 scraper.py --action download

# 管道：分析後匯出
python3 scraper.py --action analyze && \
python3 scraper.py --action export_json && \
echo "✓ 完成！"

# 統計女性參展商
python3 -c "
import pandas as pd
df = pd.read_csv('tgs_exhibitors.csv')
# 假設某些名稱表示女性開發商...
print('女性開發商統計: ...')
"

# 生成報告
python3 scraper.py --action report && \
cat output/tgs_report.json | python3 -m json.tool
```

---

## 範例代碼

### 1. 基本資料分析

```python
import pandas as pd

# 讀取資料
df = pd.read_csv('tgs_exhibitors.csv')

# 基本統計
print(f"總參展商: {len(df)}")
print(f"總柜位: {len(df)}")

# 按國家分組
by_country = df.groupby('Country').size()
print("\n各國參展商:")
print(by_country)

# 按展區分組
by_area = df.groupby('Area').size()
print("\n各展區參展商:")
print(by_area)
```

### 2. 資料篩選和搜尋

```python
from analyzer import TGSAnalyzer

analyzer = TGSAnalyzer()

# 日本參展商
japan = analyzer.get_exhibitors_by_country()
print(f"日本參展商: {len(japan)}")

# 韓國參展商
korea = analyzer.get_exhibitors_by_country('韓国')
print(f"韓國參展商: {len(korea)}")

# Family Game Park
family_park = analyzer.get_exhibitors_by_area('ファミリーゲームパーク')
print(f"Family Game Park: {len(family_park)}")

# 搜尋 Bandai
bandai = analyzer.search_exhibitor('バンダイ')
print(bandai)
```

### 3. 自訂分析

```python
import pandas as pd
import json
from pathlib import Path

df = pd.read_csv('tgs_exhibitors.csv')

# 建立自訂統計
custom_stats = {
    '總數': len(df),
    '日本': len(df[df['Country'].isna()]),
    '中國': len(df[df['Country'] == '中国']),
    '韓國': len(df[df['Country'] == '韓国']),
    '平均柜位編號': df['Booth Number'].nunique(),
}

# 儲存統計
output_dir = Path('output')
output_dir.mkdir(exist_ok=True)

with open(output_dir / 'custom_stats.json', 'w', encoding='utf-8') as f:
    json.dump(custom_stats, f, ensure_ascii=False, indent=2)

print("✓ 統計已儲存")
```

### 4. 批量處理

```python
import pandas as pd
from pathlib import Path

df = pd.read_csv('tgs_exhibitors.csv')

# 為每個國家建立單獨的 CSV
output_dir = Path('output/by_country')
output_dir.mkdir(exist_ok=True)

for country in df['Country'].unique():
    if pd.isna(country):
        country_name = '日本'
        df_country = df[df['Country'].isna()]
    else:
        country_name = country
        df_country = df[df['Country'] == country]
    
    output_file = output_dir / f'{country_name}.csv'
    df_country.to_csv(output_file, index=False, encoding='utf-8-sig')
    print(f"✓ {country_name}: {len(df_country)} 筆")
```

### 5. 資料視覺化

```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('tgs_exhibitors.csv')

# 國家分佈圖表
plt.figure(figsize=(12, 6))

# 1. 柏圖
ax1 = plt.subplot(1, 2, 1)
df['Country'].fillna('日本').value_counts().plot(kind='bar', ax=ax1)
ax1.set_title('參展商國家分佈')
ax1.set_ylabel('數量')

# 2. 餅圖
ax2 = plt.subplot(1, 2, 2)
df['Area'].value_counts().plot(kind='pie', ax=ax2, autopct='%1.1f%%')
ax2.set_title('展區分佈')

plt.tight_layout()
plt.savefig('output/tgs_charts.png', dpi=300)
print("✓ 圖表已儲存")
```

---

## 故障排查

### 問題 1: ModuleNotFoundError

**症狀：**
```
ModuleNotFoundError: No module named 'pandas'
```

**解決方案：**
```bash
# 重新安裝依賴
pip3 install --upgrade pip
pip3 install -r requirements.txt --force-reinstall
```

### 問題 2: CSV 無法開啟

**症狀：**
```
FileNotFoundError: [Errno 2] No such file or directory: 'tgs_exhibitors.csv'
```

**解決方案：**
```bash
# 確認檔案存在
ls -la *.csv

# 或在程式中指定完整路徑
python3 scraper.py --csv /full/path/to/tgs_exhibitors.csv
```

### 問題 3: 圖片下載失敗

**症狀：**
```
✗ 參展商名: HTTPError 403
```

**解決方案：**
```python
# 增加重試邏輯
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(total=3, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)

response = session.get(url, timeout=15)
```

### 問題 4: 編碼錯誤

**症狀：**
```
UnicodeDecodeError: 'utf-8' codec can't decode
```

**解決方案：**
```python
# 嘗試不同的編碼
df = pd.read_csv('tgs_exhibitors.csv', encoding='utf-8-sig')
# 或
df = pd.read_csv('tgs_exhibitors.csv', encoding='big5')
```

### 慢速連線

**症狀：**
下載圖片時速度很慢

**解決方案：**
```bash
# 增加 worker 數量
python3 -c "
from scraper import TGSExhibitorScraper
scraper = TGSExhibitorScraper()
scraper.load_exhibitors()
scraper.download_images(max_workers=10)  # 預設為 5
"
```

---

## 貢獻

發現 Bug 或有改進建議？歡迎提交！

---

## 授權

此專案資料來自 TGS 官方網站，僅供教學和研究用途。

---

**最後更新**: 2026-02-24  
**版本**: 1.0.0
