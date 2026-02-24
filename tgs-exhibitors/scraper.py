#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tokyo Game Show (TGS) 2025 參展商爬蟲

功能：
- 從本地 CSV 讀取展覽商家資料
- 資料清理與驗證
- 基本統計分析
- 下載參展商圖片
- 匯出統計報告

使用方式：
    python scraper.py --action analyze
    python scraper.py --action download_images
    python scraper.py --action generate_report
"""

import csv
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class Exhibitor:
    """參展商資料類別"""
    exhibitor: str
    location: str
    area: str
    booth_number: str
    country: Optional[str]
    is_online: str
    exhibitor_figure: Optional[str]
    exhibitor_id: str

    def to_dict(self) -> Dict:
        """轉換為字典"""
        return asdict(self)

    @property
    def is_japan(self) -> bool:
        """是否為日本參展商"""
        return self.country is None or self.country == ''

    @property
    def is_online_bool(self) -> bool:
        """是否為線上展示"""
        return self.is_online.lower() == 'yes'


class TGSExhibitorScraper:
    """TGS 參展商爬蟲"""

    def __init__(self, csv_file: str = 'tgs_exhibitors.csv'):
        """初始化爬蟲"""
        self.csv_file = Path(csv_file)
        self.exhibitors: List[Exhibitor] = []
        self.output_dir = Path('output')
        self.output_dir.mkdir(exist_ok=True)

    def load_exhibitors(self) -> bool:
        """從 CSV 載入參展商資料"""
        if not self.csv_file.exists():
            logger.error(f"CSV 檔案不存在: {self.csv_file}")
            return False

        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    exhibitor = Exhibitor(
                        exhibitor=row['Exhibitor'].strip(),
                        location=row['Location'].strip(),
                        area=row['Area'].strip(),
                        booth_number=row['Booth Number'].strip(),
                        country=row['Country'].strip() if row['Country'].strip() else None,
                        is_online=row['Is Online'].strip(),
                        exhibitor_figure=row.get('Exhibitor Figure', '').strip() or None,
                        exhibitor_id=row['Exhibitor ID'].strip(),
                    )
                    self.exhibitors.append(exhibitor)

            logger.info(f"成功載入 {len(self.exhibitors)} 筆參展商資料")
            return True

        except Exception as e:
            logger.error(f"載入 CSV 出錯: {e}")
            return False

    def analyze(self) -> Dict:
        """對資料進行分析"""
        if not self.exhibitors:
            logger.warning("沒有資料可分析")
            return {}

        # 統計各國參展商
        country_counts = {}
        for exhibitor in self.exhibitors:
            country = exhibitor.country or '日本'
            country_counts[country] = country_counts.get(country, 0) + 1

        # 統計各展區
        area_counts = {}
        for exhibitor in self.exhibitors:
            area = exhibitor.area
            area_counts[area] = area_counts.get(area, 0) + 1

        # 統計線上展示
        online_count = sum(1 for e in self.exhibitors if e.is_online_bool)

        stats = {
            '總參展商數': len(self.exhibitors),
            '日本參展商': sum(1 for e in self.exhibitors if e.is_japan),
            '國際參展商': sum(1 for e in self.exhibitors if not e.is_japan),
            '線上展示': online_count,
            '有效圖片': sum(1 for e in self.exhibitors if e.exhibitor_figure),
            '各國統計': country_counts,
            '各展區統計': area_counts,
        }

        return stats

    def download_images(self, max_workers: int = 5) -> None:
        """下載參展商圖片"""
        image_dir = self.output_dir / 'images'
        image_dir.mkdir(exist_ok=True)

        exhibitors_with_images = [
            e for e in self.exhibitors if e.exhibitor_figure
        ]

        if not exhibitors_with_images:
            logger.warning("沒有圖片可下載")
            return

        logger.info(f"開始下載 {len(exhibitors_with_images)} 張圖片...")

        def download_image(exhibitor: Exhibitor) -> bool:
            """下載單張圖片"""
            try:
                response = requests.get(
                    exhibitor.exhibitor_figure,
                    timeout=10,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    }
                )
                response.raise_for_status()

                # 生成檔名
                safe_name = exhibitor.exhibitor.replace('/', '-')[:50]
                file_ext = self._get_file_extension(exhibitor.exhibitor_figure)
                filename = f"{safe_name}_{exhibitor.exhibitor_id}{file_ext}"
                file_path = image_dir / filename

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                logger.info(f"✓ {exhibitor.exhibitor}")
                return True

            except Exception as e:
                logger.error(f"✗ {exhibitor.exhibitor}: {e}")
                return False

        # 並發下載
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(download_image, e)
                for e in exhibitors_with_images
            ]
            completed = sum(1 for f in as_completed(futures) if f.result())

        logger.info(f"下載完成: {completed}/{len(exhibitors_with_images)}")

    def generate_report(self) -> None:
        """生成統計報告"""
        stats = self.analyze()

        if not stats:
            logger.warning("無法生成報告")
            return

        # 生成 JSON 報告
        report_file = self.output_dir / 'tgs_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)

        logger.info(f"報告已儲存: {report_file}")

        # 列印統計摘要
        self._print_summary(stats)

    def _print_summary(self, stats: Dict) -> None:
        """列印統計摘要"""
        print("\n" + "=" * 50)
        print("TGS 2025 參展商統計報告")
        print("=" * 50)
        print(f"總參展商數:      {stats['總參展商數']} 家")
        print(f"日本參展商:      {stats['日本參展商']} 家")
        print(f"國際參展商:      {stats['國際參展商']} 家")
        print(f"線上展示:        {stats['線上展示']} 家")
        print(f"有效圖片:        {stats['有效圖片']} 張")

        print("\n各國參展商統計 (前 10):")
        sorted_countries = sorted(
            stats['各國統計'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for country, count in sorted_countries:
            print(f"  {country}: {count} 家")

        print("\n各展區參展商統計:")
        for area, count in stats['各展區統計'].items():
            print(f"  {area}: {count} 家")

        print("=" * 50 + "\n")

    @staticmethod
    def _get_file_extension(url: str) -> str:
        """從 URL 提取副檔名"""
        try:
            path = urlparse(url).path
            return Path(path).suffix or '.jpg'
        except:
            return '.jpg'

    def export_json(self) -> None:
        """匯出為 JSON 格式"""
        json_file = self.output_dir / 'tgs_exhibitors.json'
        data = [e.to_dict() for e in self.exhibitors]

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"JSON 檔案已儲存: {json_file}")

    def export_statistics_csv(self) -> None:
        """匯出統計資訊為 CSV"""
        stats = self.analyze()

        # 國家統計 CSV
        countries_file = self.output_dir / 'countries_statistics.csv'
        with open(countries_file, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['國家', '參展商數'])
            for country, count in sorted(
                stats['各國統計'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                writer.writerow([country, count])

        # 展區統計 CSV
        areas_file = self.output_dir / 'areas_statistics.csv'
        with open(areas_file, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['展區', '參展商數'])
            for area, count in sorted(
                stats['各展區統計'].items(),
                key=lambda x: x[1],
                reverse=True
            ):
                writer.writerow([area, count])

        logger.info(f"統計 CSV 已儲存")


def main():
    """主程式"""
    parser = argparse.ArgumentParser(
        description='Tokyo Game Show 參展商爬蟲工具'
    )
    parser.add_argument(
        '--action',
        choices=['load', 'analyze', 'download', 'report', 'export_json', 'export_csv'],
        default='analyze',
        help='執行動作'
    )
    parser.add_argument(
        '--csv',
        default='tgs_exhibitors.csv',
        help='CSV 檔案路徑'
    )

    args = parser.parse_args()

    scraper = TGSExhibitorScraper(args.csv)

    if args.action == 'load' or args.action == 'analyze':
        scraper.load_exhibitors()
        scraper.analyze()
        scraper._print_summary(scraper.analyze())

    elif args.action == 'download':
        scraper.load_exhibitors()
        scraper.download_images()

    elif args.action == 'report':
        scraper.load_exhibitors()
        scraper.generate_report()

    elif args.action == 'export_json':
        scraper.load_exhibitors()
        scraper.export_json()

    elif args.action == 'export_csv':
        scraper.load_exhibitors()
        scraper.export_statistics_csv()


if __name__ == '__main__':
    main()
