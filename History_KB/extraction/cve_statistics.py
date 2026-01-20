#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE统计信息分析工具
分析 protocol_core_cves.csv 文件，统计CVE数量、协议分布等信息
"""

import csv
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


class CVEStatistics:
    """CVE统计数据类"""
    
    def __init__(self, csv_file_path: str):
        """
        初始化CVE统计
        
        Args:
            csv_file_path: CSV文件路径
        """
        self.csv_file_path = csv_file_path
        self.data = []
        self.protocol_counts = defaultdict(int)
        self.severity_counts = defaultdict(int)
        self.year_counts = defaultdict(int)
        self.total_cves = 0
        self.protocols = set()
        
    def load_data(self):
        """加载CSV数据"""
        if not os.path.exists(self.csv_file_path):
            print(f"错误: 文件不存在: {self.csv_file_path}")
            sys.exit(1)
        
        print(f"正在加载数据: {self.csv_file_path}")
        
        # 增加CSV字段大小限制，以处理较大的字段（如summary、cpe_list等）
        # 默认限制是131072字节，这里增加到10MB
        csv.field_size_limit(10 * 1024 * 1024)
        
        try:
            with open(self.csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # 只保存必要字段，减少内存占用
                    essential_data = {
                        'cve_id': row.get('cve_id', '').strip(),
                        'protocol_family': row.get('protocol_family', 'Unknown').strip(),
                        'published': row.get('published', '').strip(),
                        'v3_severity': row.get('v3_severity', '').strip(),
                        'v3_score': row.get('v3_score', '').strip(),
                    }
                    self.data.append(essential_data)
                    self.total_cves += 1
                    
                    # 统计协议
                    protocol = essential_data['protocol_family']
                    if protocol:
                        self.protocols.add(protocol)
                        self.protocol_counts[protocol] += 1
                    
                    # 统计严重程度
                    severity = essential_data['v3_severity']
                    if severity:
                        self.severity_counts[severity] += 1
                    else:
                        self.severity_counts['UNKNOWN'] += 1
                    
                    # 统计年份
                    published = essential_data['published']
                    if published:
                        try:
                            # 解析日期，格式可能是: 1999-03-22T05:00:00.000
                            date_str = published.split('T')[0]
                            year = date_str.split('-')[0]
                            self.year_counts[year] += 1
                        except Exception:
                            pass
            
            print(f"成功加载 {self.total_cves} 条CVE记录")
            
        except Exception as e:
            print(f"加载数据时出错: {e}")
            sys.exit(1)
    
    def print_basic_statistics(self):
        """打印基本信息统计"""
        print("\n" + "="*80)
        print("CVE基本信息统计")
        print("="*80)
        print(f"总CVE数量: {self.total_cves}")
        print(f"包含的协议数量: {len(self.protocols)}")
        print(f"协议列表: {', '.join(sorted(self.protocols))}")
    
    def print_protocol_statistics(self):
        """打印协议分布统计"""
        print("\n" + "="*80)
        print("协议分布统计")
        print("="*80)
        
        # 按数量排序
        sorted_protocols = sorted(self.protocol_counts.items(), 
                                 key=lambda x: x[1], 
                                 reverse=True)
        
        print(f"{'协议':<30} {'CVE数量':<15} {'占比':<15}")
        print("-" * 60)
        
        for protocol, count in sorted_protocols:
            percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
            print(f"{protocol:<30} {count:<15} {percentage:.2f}%")
        
        print("-" * 60)
        print(f"{'总计':<30} {self.total_cves:<15} {'100.00%':<15}")
    
    def print_severity_statistics(self):
        """打印严重程度统计"""
        print("\n" + "="*80)
        print("严重程度分布统计 (CVSS v3)")
        print("="*80)
        
        # 定义严重程度排序
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']
        
        print(f"{'严重程度':<20} {'CVE数量':<15} {'占比':<15}")
        print("-" * 50)
        
        total_with_severity = sum(count for sev, count in self.severity_counts.items() 
                                 if sev != 'UNKNOWN')
        
        for severity in severity_order:
            count = self.severity_counts.get(severity, 0)
            if count > 0:
                percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
                print(f"{severity:<20} {count:<15} {percentage:.2f}%")
        
        print("-" * 50)
        print(f"{'总计':<20} {self.total_cves:<15} {'100.00%':<15}")
    
    def print_year_statistics(self):
        """打印年份分布统计"""
        print("\n" + "="*80)
        print("年份分布统计")
        print("="*80)
        
        sorted_years = sorted(self.year_counts.items())
        
        print(f"{'年份':<15} {'CVE数量':<15} {'占比':<15}")
        print("-" * 45)
        
        for year, count in sorted_years:
            percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
            print(f"{year:<15} {count:<15} {percentage:.2f}%")
        
        print("-" * 45)
        print(f"{'总计':<15} {self.total_cves:<15} {'100.00%':<15}")
        
        # 统计最早和最晚的年份
        if sorted_years:
            earliest_year = sorted_years[0][0]
            latest_year = sorted_years[-1][0]
            print(f"\n最早CVE年份: {earliest_year}")
            print(f"最新CVE年份: {latest_year}")
    
    def print_protocol_severity_matrix(self):
        """打印协议-严重程度矩阵"""
        print("\n" + "="*80)
        print("协议-严重程度交叉统计")
        print("="*80)
        
        # 构建矩阵
        matrix = defaultdict(lambda: defaultdict(int))
        for row in self.data:
            protocol = row.get('protocol_family', 'Unknown').strip()
            severity = row.get('v3_severity', 'UNKNOWN').strip() or 'UNKNOWN'
            matrix[protocol][severity] += 1
        
        # 获取所有协议和严重程度
        protocols = sorted(set(protocol for protocol in matrix.keys()))
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']
        
        # 打印表头
        header = f"{'协议':<30}"
        for severity in severities:
            header += f"{severity:<12}"
        header += "总计"
        print(header)
        print("-" * len(header))
        
        # 打印每一行
        for protocol in protocols:
            row_str = f"{protocol:<30}"
            total = 0
            for severity in severities:
                count = matrix[protocol].get(severity, 0)
                total += count
                row_str += f"{count:<12}"
            row_str += str(total)
            print(row_str)
    
    def print_protocol_year_trend(self, top_n: int = 5):
        """打印主要协议的年趋势（Top N协议）"""
        print("\n" + "="*80)
        print(f"主要协议年趋势分析 (Top {top_n} 协议)")
        print("="*80)
        
        # 获取Top N协议
        top_protocols = sorted(self.protocol_counts.items(), 
                              key=lambda x: x[1], 
                              reverse=True)[:top_n]
        
        # 构建协议-年份矩阵
        protocol_year_matrix = defaultdict(lambda: defaultdict(int))
        for row in self.data:
            protocol = row.get('protocol_family', 'Unknown').strip()
            published = row.get('published', '').strip()
            if published:
                try:
                    date_str = published.split('T')[0]
                    year = date_str.split('-')[0]
                    protocol_year_matrix[protocol][year] += 1
                except Exception:
                    pass
        
        # 获取所有年份
        all_years = sorted(set(year for protocol_dict in protocol_year_matrix.values() 
                              for year in protocol_dict.keys()))
        
        for protocol, _ in top_protocols:
            print(f"\n协议: {protocol}")
            print(f"{'年份':<15} {'CVE数量':<15}")
            print("-" * 30)
            for year in all_years:
                count = protocol_year_matrix[protocol].get(year, 0)
                if count > 0:
                    print(f"{year:<15} {count:<15}")
    
    def save_statistics_to_file(self, output_file: str):
        """保存统计结果到文件"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("CVE统计信息分析报告\n")
                f.write("="*80 + "\n\n")
                
                # 基本信息
                f.write(f"总CVE数量: {self.total_cves}\n")
                f.write(f"包含的协议数量: {len(self.protocols)}\n")
                f.write(f"协议列表: {', '.join(sorted(self.protocols))}\n\n")
                
                # 协议分布
                f.write("协议分布统计:\n")
                f.write("-" * 60 + "\n")
                sorted_protocols = sorted(self.protocol_counts.items(), 
                                         key=lambda x: x[1], 
                                         reverse=True)
                for protocol, count in sorted_protocols:
                    percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
                    f.write(f"{protocol}: {count} ({percentage:.2f}%)\n")
                f.write("\n")
                
                # 严重程度分布
                f.write("严重程度分布:\n")
                f.write("-" * 60 + "\n")
                severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']
                for severity in severity_order:
                    count = self.severity_counts.get(severity, 0)
                    if count > 0:
                        percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
                        f.write(f"{severity}: {count} ({percentage:.2f}%)\n")
                f.write("\n")
                
                # 年份分布
                f.write("年份分布统计:\n")
                f.write("-" * 60 + "\n")
                sorted_years = sorted(self.year_counts.items())
                for year, count in sorted_years:
                    percentage = (count / self.total_cves) * 100 if self.total_cves > 0 else 0
                    f.write(f"{year}: {count} ({percentage:.2f}%)\n")
            
            print(f"\n统计结果已保存到: {output_file}")
            
        except Exception as e:
            print(f"保存统计结果时出错: {e}")
    
    def print_all_statistics(self):
        """打印所有统计信息"""
        self.print_basic_statistics()
        self.print_protocol_statistics()
        self.print_severity_statistics()
        self.print_year_statistics()
        self.print_protocol_severity_matrix()
        self.print_protocol_year_trend(top_n=5)


def main():
    """主函数"""
    # 默认CSV文件路径
    script_dir = Path(__file__).parent
    default_csv = script_dir.parent / "data" / "protocol_core_cves_identify.csv"
    
    # 检查命令行参数
    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    else:
        csv_file = str(default_csv)
    
    # 检查文件是否存在
    if not os.path.exists(csv_file):
        print(f"错误: 文件不存在: {csv_file}")
        print(f"请提供CSV文件路径作为参数，或确保默认文件存在: {default_csv}")
        sys.exit(1)
    
    # 创建统计对象
    stats = CVEStatistics(csv_file)
    
    # 加载数据
    stats.load_data()
    
    # 打印所有统计信息
    stats.print_all_statistics()
    
    # 保存统计结果
    output_file = script_dir.parent / "data" / "cve_statistics_report.txt"
    stats.save_statistics_to_file(str(output_file))
    
    print("\n" + "="*80)
    print("统计分析完成!")
    print("="*80)


if __name__ == "__main__":
    main()

