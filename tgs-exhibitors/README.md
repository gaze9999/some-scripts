# Tokyo Game Show (TGS) 2025 展覽商家資料

## 專案說明

此專案提供 **TGS 2025 展覽商家資料**，用於 Python 爬蟲和資料分析範例。

## 資料檔案

| 檔案                      | 說明             | 記錄數   |
| ------------------------- | ---------------- | -------- |
| `tgs_exhibitors.csv`      | 展覽商家核心資料 | 20+ 筆   |
| `tgs_exhibitors_full.csv` | 完整展覽商家資料 | 1000+ 筆 |

## 資料欄位

```
Exhibitor        # 參展商名稱
Location         # 展覽位置（例：イベントホール, ホール1, ホール2）
Area             # 展區名稱（例：ファミリーゲームパーク, 一般展示）
Booth Number     # 攤位編號
Country          # 國家/地區
Is Online        # 是否線上展示
Exhibitor Figure # 參展商圖片 URL
Exhibitor ID     # 參展商 ID
```

## 使用範例

### 1. 基本讀取

```python
import pandas as pd

# 讀取 CSV 檔案
df = pd.read_csv('tgs_exhibitors.csv')
print(df.head())
print(f"總筆數: {len(df)}")
```

### 2. 資料分析

```python
import pandas as pd

df = pd.read_csv('tgs_exhibitors.csv')

# 統計各國參展商數量
country_counts = df['Country'].value_counts()
print("各國參展商數量:")
print(country_counts)

# 統計各展區參展商數量
area_counts = df['Area'].value_counts()
print("\n各展區參展商數量:")
print(area_counts)

# 線上展示的參展商
online_exhibitors = df[df['Is Online'] == 'Yes']
print(f"\n線上展示參展商: {len(online_exhibitors)} 家")
```

### 3. 資料篩選

```python
import pandas as pd

df = pd.read_csv('tgs_exhibitors.csv')

# 篩選特定國家的參展商
japan_exhibitors = df[df['Country'].isna()]  # 日本（無國家標記）
print(f"日本參展商: {len(japan_exhibitors)} 家")
print(japan_exhibitors[['Exhibitor', 'Booth Number']])

# 篩選特定展區
family_park = df[df['Area'] == 'ファミリーゲームパーク']
print(f"\nFamily Game Park 參展商: {len(family_park)} 家")
```

### 4. 下載圖片

```python
import pandas as pd
import requests
from pathlib import Path

df = pd.read_csv('tgs_exhibitors.csv')

# 建立輸出目錄
output_dir = Path('images')
output_dir.mkdir(exist_ok=True)

# 下載參展商圖片
for idx, row in df.iterrows():
    url = row['Exhibitor Figure']
    exhibitor_name = row['Exhibitor'].replace('/', '-')
    
    if pd.notna(url):
        try:
            response = requests.get(url)
            file_path = output_dir / f"{exhibitor_name}_{row['Exhibitor ID']}.jpg"
            with open(file_path, 'wb') as f:
                f.write(response.content)
            print(f"✓ 下載: {exhibitor_name}")
        except Exception as e:
            print(f"✗ 失敗: {exhibitor_name} - {e}")
```

### 5. 匯出統計報告

```python
import pandas as pd

df = pd.read_csv('tgs_exhibitors.csv')

# 建立統計報告
stats = {
    '總參展商數': len(df),
    '日本參展商': len(df[df['Country'].isna()]),
    '國際參展商': len(df[df['Country'].notna()]),
    '線上展示': len(df[df['Is Online'] == 'Yes']),
    '有效圖片': len(df[df['Exhibitor Figure'].notna()]),
}

print("TGS 2025 統計報告")
print("=" * 40)
for key, value in stats.items():
    print(f"{key}: {value}")
```

## 爬蟲應用

### 爬取最新資料

```python
import requests
from bs4 import BeautifulSoup
import pandas as pd
import time

def scrape_tgs_exhibitors(url: str) -> pd.DataFrame:
    """
    從 TGS 官方網站爬取最新參展商資料
    
    Args:
        url: TGS 官方展覽商家頁面 URL
    
    Returns:
        包含參展商資料的 DataFrame
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.content, 'html.parser')
        
        exhibitors = []
        
        # 範例：根據頁面結構調整選擇器
        for row in soup.find_all('tr', class_='exhibitor-row'):
            try:
                cols = row.find_all('td')
                exhibitor = {
                    'Exhibitor': cols[0].text.strip(),
                    'Location': cols[1].text.strip(),
                    'Area': cols[2].text.strip(),
                    'Booth Number': cols[3].text.strip(),
                    'Country': cols[4].text.strip() or None,
                    'Is Online': cols[5].text.strip(),
                    'Exhibitor ID': cols[7].text.strip(),
                }
                exhibitors.append(exhibitor)
            except (IndexError, AttributeError):
                continue
        
        return pd.DataFrame(exhibitors)
    
    except requests.RequestException as e:
        print(f"爬取失敗: {e}")
        return pd.DataFrame()

# 使用範例
if __name__ == '__main__':
    url = "https://service.tgs.cesa.or.jp/exhibitors"
    df = scrape_tgs_exhibitors(url)
    if not df.empty:
        df.to_csv('tgs_exhibitors_new.csv', index=False, encoding='utf-8-sig')
        print(f"成功爬取 {len(df)} 筆資料")
```

## 進階應用

### 資料視覺化

```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('tgs_exhibitors.csv')

# 統計圖表
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# 國家分佈
country_counts = df['Country'].value_counts().head(10)
country_counts.plot(kind='barh', ax=axes[0])
axes[0].set_title('Top 10 國家參展商')
axes[0].set_xlabel('數量')

# 展區分佈
area_counts = df['Area'].value_counts()
area_counts.plot(kind='bar', ax=axes[1])
axes[1].set_title('展區分佈')
axes[1].set_xlabel('展區')
axes[1].set_ylabel('參展商數')

plt.tight_layout()
plt.savefig('tgs_statistics.png', dpi=300)
plt.show()
```

### API 上傳至資料庫

```python
import pandas as pd
import requests
import json

df = pd.read_csv('tgs_exhibitors.csv')

# 上傳至後端 API
for idx, row in df.iterrows():
    payload = {
        'exhibitor': row['Exhibitor'],
        'location': row['Location'],
        'area': row['Area'],
        'booth_number': row['Booth Number'],
        'country': row['Country'],
        'is_online': row['Is Online'] == 'Yes',
        'exhibitor_id': row['Exhibitor ID'],
    }
    
    response = requests.post(
        'http://localhost:3000/api/exhibitors',
        json=payload,
        headers={'Content-Type': 'application/json'}
    )
    print(f"上傳 {row['Exhibitor']}: {response.status_code}")
```

## 法律聲明

- 資料來源：[Tokyo Game Show 官方網站](https://tgs.cesa.or.jp/)
- 此份資料僅供教學和研究用途
- 請尊重參展商的知識產權和隱私

## 相關資源

- [TGS 官方網站](https://tgs.cesa.or.jp/)
- [Python pandas 文檔](https://pandas.pydata.org/)
- [BeautifulSoup 文檔](https://www.crummy.com/software/BeautifulSoup/)
- [Requests 文檔](https://docs.python-requests.org/)

---

**最後更新**: 2026-02-24  
**資料版本**: TGS 2025
