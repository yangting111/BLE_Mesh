#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
协议识别Judge模型Prompt模板
用于判断CVE是否与协议实现相关，并识别具体协议类型
"""

# 协议识别Judge模型Prompt模板
PROTOCOL_IDENTIFICATION_JUDGE_PROMPT_TEMPLATE = """You are an expert judge specialized in network protocol security. Please analyze the following three model responses to identify which network protocol implementation this CVE vulnerability belongs to.

Original Question: {prompt}

Model Responses:
{responses_text}

### Analysis Requirements

Please conduct the following analysis:
1. Compare the consistency and differences between the three model responses
2. Evaluate the accuracy and credibility of each response regarding protocol identification
3. Identify potential errors or biases in the responses
4. Determine if this is a protocol implementation vulnerability within the nine specified protocol categories
5. Identify the specific protocol family if it is protocol-related, but ONLY from the following NINE protocol categories:
   - "TLS/DTLS" - Transport Layer Security / Datagram Transport Layer Security
   - "SSH" - Secure Shell
   - "HTTP" - Hypertext Transfer Protocol
   - "MQTT" - Message Queuing Telemetry Transport
   - "CoAP" - Constrained Application Protocol
   - "IP/ICMP/ARP" - Internet Protocol / Internet Control Message Protocol / Address Resolution Protocol
   - "Wi-Fi" - Wireless Fidelity
   - "BT/BLE" - Bluetooth / Bluetooth Low Energy
   - "ZigBee" - ZigBee protocol
   
   If the protocol does NOT belong to any of these nine categories, it must be classified as "Not Protocol-Related"

### Output Requirements

Return analysis results in JSON format with the following fields:
- analysis: Detailed analysis of the model responses and protocol identification
- final_fact: Only return `"Protocol-Related"` or `"Not Protocol-Related"` or `"Inconclusive"`. IMPORTANT: If the protocol does NOT belong to the nine specified categories, return "Not Protocol-Related"
- protocol_family: If Protocol-Related, return the specific protocol family from the nine categories: "TLS/DTLS", "SSH", "HTTP", "MQTT", "CoAP", "IP/ICMP/ARP", "Wi-Fi", "BT/BLE", "ZigBee". If Not Protocol-Related, return "None". If Inconclusive, return "Unknown" or the most likely protocol from the nine categories if identifiable.

Final output MUST be a valid JSON object.
You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
Only return this line:

### Example Output:
Final Answer: {{
    "analysis": "Response comparison: Model-A and Model-B both identified this as a TLS/DTLS protocol vulnerability related to OpenSSL, specifically affecting the certificate validation process. Model-C also identified it as protocol-related but was less specific about the protocol type. All models agree this is a protocol implementation vulnerability.",
    "final_fact": "Protocol-Related",
    "protocol_family": "TLS/DTLS"
}}"""


def get_protocol_identification_judge_prompt(prompt, responses_text):
    """
    生成协议识别Judge模型prompt
    
    Args:
        prompt: 原始问题
        responses_text: 模型响应文本
    
    Returns:
        str: 格式化的prompt字符串
    """
    return PROTOCOL_IDENTIFICATION_JUDGE_PROMPT_TEMPLATE.format(
        prompt=prompt,
        responses_text=responses_text
    )


if __name__ == "__main__":
    # 测试prompt生成
    test_prompt = get_protocol_identification_judge_prompt(
        prompt="Test question about CVE protocol identification",
        responses_text="Model response 1\nModel response 2\nModel response 3"
    )
    print("Generated judge prompt:")
    print(test_prompt)

