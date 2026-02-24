#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
快速開始指南 - TGS 爬蟲工具

簡單的使用範例
"""

import sys
from pathlib import Path

# 新增專案路徑
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from scraper import TGSExhibitorScraper


def quick_start():
    """快速開始示例"""
    
    print("=" * 60)
    print("Tokyo Game Show 2025 - 爬蟲工具快速開始")
    print("=" * 60)
    
    # 初始化爬蟲
    print("\n1️⃣  載入資料...")
    scraper = TGSExhibitorScraper('tgs_exhibitors.csv')
    
    if not scraper.exhibitors:
        print("❌ 無法載入資料")
        return
    
    # 執行基本分析
    print("\n2️⃣  執行分析...")
    stats = scraper.analyze()
    
    # 列印結果
    print("\n📊 統計結果:")
    print(f"   • 總參展商: {stats['總參展商數']} 家")
    print(f"   • 日本參展: {stats['日本參展商']} 家")
    print(f"   • 國際參展: {stats['國際參展商']} 家")
    print(f"   • 線上展示: {stats['線上展示']} 家")
    
    # 國家排名
    print("\n🌍 區域分佈 (前 5):")
    sorted_countries = sorted(
        stats['各國統計'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]
    for country, count in sorted_countries:
        bar = "█" * (count // 2)
        print(f"   {country:10} │ {bar} ({count})")
    
    # 展區分佈
    print("\n🎮 展區分佈:")
    for area, count in stats['各展區統計'].items():
        print(f"   • {area:20} : {count:3} 家")
    
    # 匯出結果
    print("\n3️⃣  匯出資料...")
    scraper.generate_report()
    scraper.export_json()
    
    print("\n✅ 完成！")
    print(f"   報告位置: ./output/")
    
    print("\n" + "=" * 60)
    print("進階功能:")
    print("=" * 60)
    print("  下載圖片:  python3 scraper.py --action download")
    print("  匯出 JSON:  python3 scraper.py --action export_json")
    print("  匯出統計:  python3 scraper.py --action export_csv")
    print("  進階分析:  python3 analyzer.py")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    try:
        quick_start()
    except KeyboardInterrupt:
        print("\n⏹️  已取消")
    except Exception as e:
        print(f"\n❌ 錯誤: {e}")
        import traceback
        traceback.print_exc()
