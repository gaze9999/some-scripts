#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
進階資料分析工具

提供進階的 TGS 參展商資料分析功能
"""

import pandas as pd
import json
from pathlib import Path
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class TGSAnalyzer:
    """TGS 參展商資料分析器"""

    def __init__(self, csv_file: str = 'tgs_exhibitors.csv'):
        """初始化分析器"""
        self.csv_file = Path(csv_file)
        self.df: pd.DataFrame = None
        self.load_data()

    def load_data(self) -> bool:
        """載入 CSV 資料"""
        if not self.csv_file.exists():
            print(f"檔案不存在: {self.csv_file}")
            return False

        try:
            self.df = pd.read_csv(self.csv_file, encoding='utf-8')
            print(f"✓ 成功載入 {len(self.df)} 筆資料")
            return True
        except Exception as e:
            print(f"✗ 載入失敗: {e}")
            return False

    def get_exhibitors_by_country(self, country: str = None) -> pd.DataFrame:
        """按國家篩選參展商"""
        if country is None:
            return self.df[self.df['Country'].isna() | (self.df['Country'] == '')]

        return self.df[self.df['Country'] == country]

    def get_exhibitors_by_area(self, area: str) -> pd.DataFrame:
        """按展區篩選參展商"""
        return self.df[self.df['Area'] == area]

    def get_exhibitors_by_location(self, location: str) -> pd.DataFrame:
        """按位置篩選參展商"""
        return self.df[self.df['Location'] == location]

    def get_online_exhibitors(self) -> pd.DataFrame:
        """獲取線上參展商"""
        return self.df[self.df['Is Online'].str.lower() == 'yes']

    def get_statistics(self) -> Dict:
        """獲取基本統計資訊"""
        return {
            '總數': len(self.df),
            '日本參展': len(self.get_exhibitors_by_country()),
            '國際參展': len(self.df[self.df['Country'].notna() & (self.df['Country'] != '')]),
            '線上展示': len(self.get_online_exhibitors()),
            '有圖片': len(self.df[self.df['Exhibitor Figure'].notna()]),
        }

    def get_top_countries(self, n: int = 10) -> List[tuple]:
        """獲取參展商最多的國家（排除日本）"""
        country_counts = self.df[self.df['Country'].notna() & (self.df['Country'] != '')][
            'Country'
        ].value_counts()
        return country_counts.head(n).to_dict()

    def get_area_distribution(self) -> Dict[str, int]:
        """獲取展區分佈"""
        return self.df['Area'].value_counts().to_dict()

    def export_to_json(self, output_file: str = 'output/tgs_data.json') -> bool:
        """匯出為 JSON"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(exist_ok=True)

            data = self.df.to_json(orient='records', force_ascii=False, indent=2)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(data)

            print(f"✓ 已匯出: {output_file}")
            return True
        except Exception as e:
            print(f"✗ 匯出失敗: {e}")
            return False

    def search_exhibitor(self, keyword: str) -> pd.DataFrame:
        """搜尋參展商"""
        return self.df[
            self.df['Exhibitor'].str.contains(keyword, case=False, na=False)
        ]

    def print_summary(self) -> None:
        """列印統計摘要"""
        stats = self.get_statistics()
        countries = self.get_top_countries(5)
        areas = self.get_area_distribution()

        print("\n" + "=" * 60)
        print("TGS 2025 參展商統計分析")
        print("=" * 60)

        print("\n【基本統計】")
        for key, value in stats.items():
            print(f"  {key:12} : {value:5}")

        print("\n【國家排名 (前 5)】")
        for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {country:15} : {count:3} 家")

        print("\n【展區分佈】")
        for area, count in areas.items():
            print(f"  {area:20} : {count:3} 家")

        print("=" * 60 + "\n")


if __name__ == '__main__':
    # 使用範例
    analyzer = TGSAnalyzer()

    # 列印統計
    analyzer.print_summary()

    # 搜尋特定參展商
    print("【搜尋 'バンダイ' 結果】")
    results = analyzer.search_exhibitor('バンダイ')
    if not results.empty:
        print(results[['Exhibitor', 'Location', 'Booth Number', 'Country']].to_string())

    # 日本參展商
    print("\n【日本參展商】")
    japan = analyzer.get_exhibitors_by_country()
    print(f"共 {len(japan)} 家")
    print(japan[['Exhibitor', 'Booth Number', 'Area']].head(10).to_string())

    # 匯出 JSON
    analyzer.export_to_json()
