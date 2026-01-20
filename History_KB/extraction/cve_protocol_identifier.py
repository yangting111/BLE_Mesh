#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE协议识别和重新标记工具
使用 LLMCrossVerification 识别 protocol_core_cves.csv 中标记为 Unknown 的CVE
如果识别为协议实现漏洞，重新标记协议；如果不是，则删除
"""

import asyncio
import csv
import os
import sys
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

# 添加项目路径
current_dir = os.path.dirname(os.path.abspath(__file__))
transfer_dir = os.path.abspath(os.path.join(current_dir, "../../"))
llm_usage_dir = os.path.abspath(os.path.join(current_dir, "../../LLM_usage"))
prompt_dir = os.path.abspath(os.path.join(current_dir, "../Prompt"))
sys.path.append(transfer_dir)
sys.path.append(llm_usage_dir)
sys.path.append(prompt_dir)

from LLM_usage.llm_cross_verification import LLMCrossVerification, VerificationResult, LLMModel, ModelResponse, JudgeModel
from History_KB.Prompt.protocol_identification_prompt import get_cve_protocol_identification_prompt
from History_KB.Prompt.protocol_identification_judge_prompt import get_protocol_identification_judge_prompt

# 允许的九类协议
VALID_PROTOCOL_FAMILIES = {
    "TLS/DTLS",
    "SSH",
    "HTTP",
    "MQTT",
    "CoAP",
    "IP/ICMP/ARP",
    "Wi-Fi",
    "BT/BLE",
    "ZigBee"
}


def is_valid_protocol_family(protocol_family: str) -> bool:
    """
    检查协议是否属于有效的九类协议
    
    Args:
        protocol_family: 协议家族名称
        
    Returns:
        如果是有效的协议类别，返回True；否则返回False
    """
    if not protocol_family:
        return False
    return protocol_family.strip() in VALID_PROTOCOL_FAMILIES


class ProtocolIdentificationJudgeModel(JudgeModel):
    """协议识别Judge模型，使用自定义的judge prompt"""
    
    async def verify_responses(self, prompt: str, responses: List[ModelResponse]) -> Dict[str, Any]:
        """验证多个模型的响应，返回解析后的结果和judge响应对象"""
        try:
            # 构建judge prompt
            responses_text = "\n\n".join([
                f"Model {resp.model_name}:\n{resp.response}"
                for resp in responses
            ])
            
            # 使用协议识别专用的judge prompt
            judge_prompt = get_protocol_identification_judge_prompt(
                prompt=prompt,
                responses_text=responses_text
            )
            
            # 使用judge模型生成分析
            judge_response = await self.generate_response(judge_prompt)
            print(f"Judge response: {judge_response.response[:200]}...")  # 只打印前200字符
            
            # 解析JSON响应，处理 "Final Answer:" 前缀
            response_text = judge_response.response.strip()
            
            # 查找 "Final Answer:" 前缀
            if "Final Answer:" in response_text:
                json_start = response_text.find("Final Answer:") + len("Final Answer:")
                json_text = response_text[json_start:].strip()
            else:
                json_text = response_text
            
            # 尝试提取JSON部分（去除可能的markdown代码块标记）
            if json_text.startswith("```"):
                lines = json_text.split("\n")
                json_text = "\n".join([line for line in lines if not line.strip().startswith("```")])
            
            # 尝试解析JSON
            try:
                result = json.loads(json_text)
                parsed_result = {
                    "analysis": result.get("analysis", ""),
                    "final_fact": result.get("final_fact", "Inconclusive"),
                    "protocol_family": result.get("protocol_family", "Unknown"),
                    "judge_response": judge_response
                }
                return parsed_result
            except json.JSONDecodeError as e:
                # 如果无法解析JSON，尝试提取可能的JSON部分
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', json_text, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group(0))
                        return {
                            "analysis": result.get("analysis", ""),
                            "final_fact": result.get("final_fact", "Inconclusive"),
                            "protocol_family": result.get("protocol_family", "Unknown"),
                            "judge_response": judge_response
                        }
                    except json.JSONDecodeError:
                        pass
                
                # 如果完全无法解析，返回文本分析
                print(f"Warning: Failed to parse JSON from judge response: {e}")
                return {
                    "analysis": judge_response.response,
                    "final_fact": "Inconclusive",
                    "protocol_family": "Unknown",
                    "judge_response": judge_response
                }
                
        except Exception as e:
            print(f"Judge model verification error: {e}")
            return {
                "analysis": f"Verification process error: {str(e)}",
                "final_fact": "Inconclusive",
                "protocol_family": "Unknown",
                "judge_response": None
            }


class ProtocolIdentificationVerifier(LLMCrossVerification):
    """协议识别验证器，基于 LLMCrossVerification 但使用自定义的 JudgeModel"""
    
    def __init__(self, model_providers: List[str] = None, judge_provider: str = "deepseek"):
        """
        初始化协议识别验证器
        
        Args:
            model_providers: 模型提供商列表
            judge_provider: 判断模型提供商
        """
        if model_providers is None:
            model_providers = ["openai", "grok", "google"]
        
        # 初始化三个模型（使用父类的方法）
        self.model_a = LLMModel(model_providers[0], f"Model-A-{model_providers[0]}")
        self.model_b = LLMModel(model_providers[1], f"Model-B-{model_providers[1]}")
        self.model_c = LLMModel(model_providers[2], f"Model-C-{model_providers[2]}")
        
        # 使用协议识别专用的Judge模型
        self.judge_model = ProtocolIdentificationJudgeModel(judge_provider, "Judge")
    
    async def verify_prompt(self, prompt: str) -> Dict[str, Any]:
        """验证单个prompt，返回包含协议信息的字典"""
        print(f"starting to verify prompt: {prompt[:200]}...")
        
        # 并行获取三个模型的响应
        tasks = [
            self.model_a.generate_response(prompt),
            self.model_b.generate_response(prompt),
            self.model_c.generate_response(prompt)
        ]
        
        responses = await asyncio.gather(*tasks)
        
        print(f"Get {len(responses)} model responses")
        
        # 使用judge模型进行验证
        judge_result = await self.judge_model.verify_responses(prompt, responses)
        
        # 获取judge的token使用情况
        judge_response = judge_result.get("judge_response")
        judge_tokens = None
        if judge_response and hasattr(judge_response, 'tokens_used'):
            judge_tokens = judge_response.tokens_used
        
        # 构建验证结果字典（包含协议信息）
        result = {
            'prompt': prompt,
            'model_responses': responses,
            'judge_analysis': judge_result.get("analysis", ""),
            'final_verified_fact': judge_result.get("final_fact", "Inconclusive"),
            'protocol_family': judge_result.get("protocol_family", "Unknown"),
            'judge_tokens_used': judge_tokens,
            'verification_timestamp': time.time()
        }
        
        return result
    
    def _create_verification_prompt(self, cve_data: Dict[str, Any]) -> str:
        """根据CVE数据创建验证prompt"""
        return get_cve_protocol_identification_prompt(
            cve_id=cve_data.get('cve_id', ''),
            summary=cve_data.get('summary', '')
        )
    
    async def verify_single_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """验证单个CVE"""
        try:
            # 创建验证prompt
            prompt = self._create_verification_prompt(cve_data)
            
            # 使用父类的 verify_prompt 方法
            result = await self.verify_prompt(prompt)
            
            # 添加CVE数据到结果
            result['cve_id'] = cve_data.get('cve_id', '')
            result['published'] = cve_data.get('published', '')
            result['v3_severity'] = cve_data.get('v3_severity', '')
            result['v3_score'] = cve_data.get('v3_score', '')
            result['summary'] = cve_data.get('summary', '')
            result['cpe_list'] = cve_data.get('cpe_list', '')
            
            # 转换 model_responses 为字典格式
            result['model_responses'] = [
                {
                    'model_name': resp.model_name,
                    'response': resp.response,
                    'tokens_used': resp.tokens_used
                }
                for resp in result['model_responses']
            ]
            
            return result
            
        except Exception as e:
            print(f"error verifying CVE {cve_data.get('cve_id', 'Unknown')}: {e}")
            return {
                'cve_id': cve_data.get('cve_id', ''),
                'error': str(e),
                'verification_timestamp': time.time()
            }
    
    async def verify_cve_batch(self, cve_data_list: List[Dict[str, Any]], 
                              max_concurrent: int = 2) -> List[Dict[str, Any]]:
        """批量验证CVE列表"""
        results = []
        
        # 使用信号量控制并发数
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def verify_with_semaphore(cve_data):
            async with semaphore:
                return await self.verify_single_cve(cve_data)
        
        # 创建所有任务
        tasks = [verify_with_semaphore(cve_data) for cve_data in cve_data_list]
        
        # 执行所有任务
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理异常结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'cve_id': cve_data_list[i].get('cve_id', ''),
                    'error': str(result),
                    'verification_timestamp': time.time()
                })
            else:
                processed_results.append(result)
        
        return processed_results


class CVEProtocolIdentifier:
    """CVE协议识别器"""
    
    def __init__(self, model_providers: List[str] = None, judge_provider: str = "deepseek"):
        """
        初始化CVE协议识别器
        
        Args:
            model_providers: 模型提供商列表
            judge_provider: 判断模型提供商
        """
        self.verifier = ProtocolIdentificationVerifier(model_providers, judge_provider)
        self.stats = {
            'total_unknown': 0,
            'verified_protocol_related': 0,
            'verified_not_protocol_related': 0,
            'invalid_protocol_family': 0,  # 协议不属于九类有效协议
            'inconclusive': 0,
            'protocol_identified': 0,
            'protocol_not_identified': 0,
            'errors': 0
        }
    
    def load_cve_data(self, csv_file_path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
        """
        加载CVE数据，分离Unknown和非Unknown的记录
        
        Args:
            csv_file_path: CSV文件路径
            
        Returns:
            (unknown_cves, known_cves, fieldnames) 元组
        """
        # 增加CSV字段大小限制
        csv.field_size_limit(10 * 1024 * 1024)
        
        unknown_cves = []
        known_cves = []
        fieldnames = []
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []
                
                for row in reader:
                    protocol_family = row.get('protocol_family', '').strip()
                    if protocol_family.upper() == 'UNKNOWN' or not protocol_family:
                        unknown_cves.append(row)
                    else:
                        known_cves.append(row)
            
            print(f"加载完成: 总计 {len(unknown_cves) + len(known_cves)} 条记录")
            print(f"  - Unknown协议: {len(unknown_cves)} 条")
            print(f"  - 已知协议: {len(known_cves)} 条")
            
            return unknown_cves, known_cves, fieldnames
            
        except Exception as e:
            print(f"加载数据时出错: {e}")
            return [], [], []
    
    async def identify_unknown_cves(self, unknown_cves: List[Dict[str, Any]], 
                                   max_concurrent: int = 2,
                                   batch_size: int = 5) -> List[Dict[str, Any]]:
        """
        识别Unknown协议的CVE
        
        Args:
            unknown_cves: Unknown协议的CVE列表
            max_concurrent: 最大并发数
            batch_size: 批次大小
            
        Returns:
            处理后的CVE列表（包含重新标记的协议）
        """
        self.stats['total_unknown'] = len(unknown_cves)
        identified_cves = []
        
        # 分批处理
        total_batches = (len(unknown_cves) + batch_size - 1) // batch_size
        
        for batch_idx in range(total_batches):
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, len(unknown_cves))
            batch = unknown_cves[start_idx:end_idx]
            
            print(f"\n处理批次 {batch_idx + 1}/{total_batches} ({len(batch)} 条CVE)...")
            
            # 验证批次
            verification_results = await self.verifier.verify_cve_batch(
                batch, 
                max_concurrent=max_concurrent
            )
            
            # 处理验证结果
            for i, result in enumerate(verification_results):
                cve_data = batch[i]
                
                if 'error' in result:
                    print(f"  CVE {cve_data.get('cve_id', 'Unknown')}: 验证出错 - {result.get('error')}")
                    self.stats['errors'] += 1
                    # 出错时保留原记录，标记为Unknown
                    identified_cves.append(cve_data)
                    continue
                
                final_fact = result.get('final_verified_fact', '').strip()
                protocol_family = result.get('protocol_family', 'Unknown').strip()
                cve_id = cve_data.get('cve_id', 'Unknown')
                
                print(f"  CVE {cve_id}: {final_fact} | Protocol: {protocol_family}")
                
                if final_fact == "Protocol-Related":
                    self.stats['verified_protocol_related'] += 1
                    
                    # 验证协议是否属于有效的九类协议
                    if protocol_family and is_valid_protocol_family(protocol_family):
                        # 协议属于有效的九类，更新协议标记并保留
                        cve_data['protocol_family'] = protocol_family.strip()
                        identified_cves.append(cve_data)
                        self.stats['protocol_identified'] += 1
                        print(f"    -> 识别为协议: {protocol_family}")
                    else:
                        # 协议不属于有效的九类，删除
                        self.stats['verified_not_protocol_related'] += 1
                        self.stats['invalid_protocol_family'] += 1
                        print(f"    -> 删除（协议 '{protocol_family}' 不属于九类有效协议）")
                
                elif final_fact == "Not Protocol-Related":
                    self.stats['verified_not_protocol_related'] += 1
                    # 不添加到结果列表，即删除
                    print(f"    -> 删除（非协议相关）")
                
                elif final_fact == "Inconclusive":
                    self.stats['inconclusive'] += 1
                    # 不确定的情况，如果识别出了有效的协议类型，则使用它
                    if protocol_family and is_valid_protocol_family(protocol_family):
                        cve_data['protocol_family'] = protocol_family.strip()
                        identified_cves.append(cve_data)
                        self.stats['protocol_identified'] += 1
                        print(f"    -> 不确定，但识别为有效协议: {protocol_family}")
                    else:
                        # 无法确定或协议不属于有效九类，删除
                        self.stats['verified_not_protocol_related'] += 1
                        if protocol_family:
                            self.stats['invalid_protocol_family'] += 1
                            print(f"    -> 删除（协议 '{protocol_family}' 不属于九类有效协议）")
                        else:
                            print(f"    -> 删除（无法识别有效协议）")
                else:
                    # 其他情况，删除（保守策略）
                    self.stats['verified_not_protocol_related'] += 1
                    print(f"    -> 删除（未知结果类型: {final_fact}）")
            
            # 批次间延迟，避免API限流
            if batch_idx < total_batches - 1:
                print(f"等待 5 秒后处理下一批次...")
                await asyncio.sleep(5)
        
        return identified_cves
    
    def save_identified_cves(self, known_cves: List[Dict[str, Any]], 
                            identified_cves: List[Dict[str, Any]],
                            fieldnames: List[str],
                            output_file: str):
        """
        保存识别后的CVE数据到CSV文件
        
        Args:
            known_cves: 已知协议的CVE列表
            identified_cves: 识别后的Unknown CVE列表
            fieldnames: CSV字段名列表（保持原始顺序）
            output_file: 输出文件路径
        """
        try:
            # 合并所有CVE
            all_cves = known_cves + identified_cves
            
            # 确保字段名列表不为空
            if not fieldnames and all_cves:
                fieldnames = list(all_cves[0].keys())
            
            # 写入CSV文件
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_cves)
            
            print(f"\n保存完成: {output_file}")
            print(f"  - 总记录数: {len(all_cves)}")
            print(f"  - 已知协议（非Unknown）: {len(known_cves)}")
            print(f"  - Unknown识别后保留: {len(identified_cves)}")
            print(f"  - Unknown删除记录数: {self.stats['total_unknown'] - len(identified_cves)}")
            print(f"    * 非协议相关或协议不属于九类有效协议: {self.stats['verified_not_protocol_related']} 条")
            
        except Exception as e:
            print(f"保存文件时出错: {e}")
            raise
    
    def print_statistics(self):
        """打印统计信息"""
        print("\n" + "="*80)
        print("处理统计信息")
        print("="*80)
        print(f"Unknown协议总数: {self.stats['total_unknown']}")
        print(f"  确认为协议相关: {self.stats['verified_protocol_related']}")
        print(f"  确认为非协议相关: {self.stats['verified_not_protocol_related']} (已删除)")
        print(f"    其中协议不属于九类有效协议: {self.stats['invalid_protocol_family']}")
        print(f"  不确定: {self.stats['inconclusive']}")
        print(f"  错误: {self.stats['errors']}")
        print(f"\n协议识别统计:")
        print(f"  成功识别有效协议类型（九类之一）: {self.stats['protocol_identified']}")
        
        print(f"\n说明:")
        print(f"  - 只有识别为九类有效协议之一的CVE才会被保留")
        print(f"  - 九类有效协议：TLS/DTLS, SSH, HTTP, MQTT, CoAP, IP/ICMP/ARP, Wi-Fi, BT/BLE, ZigBee")
        print(f"  - 不属于九类有效协议的CVE将被删除")


async def main():
    """主函数"""
    print("CVE协议识别和重新标记工具")
    print("="*80)
    
    # 文件路径
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "data"
    input_file = data_dir / "protocol_core_cves.csv"
    output_file = data_dir / "protocol_core_cves_identify.csv"
    
    # 检查输入文件是否存在
    if not input_file.exists():
        print(f"错误: 输入文件不存在: {input_file}")
        return
    
    try:
        # 创建识别器
        identifier = CVEProtocolIdentifier(
            model_providers=["openai", "grok", "google"],
            judge_provider="deepseek"
        )
        
        # 加载数据
        print(f"\n加载数据: {input_file}")
        unknown_cves, known_cves, fieldnames = identifier.load_cve_data(str(input_file))
        
        if not unknown_cves:
            print("\n没有找到Unknown协议的CVE，无需处理")
            # 直接复制文件
            import shutil
            shutil.copy2(input_file, output_file)
            print(f"文件已复制到: {output_file}")
            return
        
        # 识别Unknown协议的CVE
        print(f"\n开始识别 {len(unknown_cves)} 条Unknown协议的CVE...")
        identified_cves = await identifier.identify_unknown_cves(
            unknown_cves,
            max_concurrent=2,  # 控制并发数，避免API限流
            batch_size=5       # 每批处理5条，可以根据需要调整
        )
        
        # 保存结果
        print(f"\n保存结果到: {output_file}")
        identifier.save_identified_cves(known_cves, identified_cves, fieldnames, str(output_file))
        
        # 打印统计信息
        identifier.print_statistics()
        
        print("\n" + "="*80)
        print("处理完成!")
        print("="*80)
        
    except Exception as e:
        print(f"\n处理过程出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
