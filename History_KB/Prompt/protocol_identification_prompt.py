#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE协议识别Prompt模板
根据CVE描述识别是哪个协议实现漏洞
"""

# CVE协议识别Prompt模板
CVE_PROTOCOL_IDENTIFICATION_PROMPT_TEMPLATE = """You are a network protocol security expert. Please analyze the following CVE vulnerability information and identify which network protocol implementation this vulnerability belongs to.

CVE Information:
- CVE ID: {cve_id}
- Description: {summary}

### Analysis Requirements

Please analyze from the following perspectives:
1. Does this vulnerability involve network protocol stack implementation?
2. Which specific protocol does this vulnerability relate to?
3. Which protocol implementation (library/tool) is affected?
4. Is the vulnerability related to protocol state machines, handshake processes, packet parsing, or data processing?

### Output Requirements

1. Judgment: Determine if this is a protocol implementation vulnerability within the nine specified protocol categories:
   - "Protocol-Related" - The vulnerability is related to network protocol implementation AND belongs to one of the nine specified protocol categories
   - "Not Protocol-Related" - The vulnerability is NOT related to network protocol implementation OR does NOT belong to any of the nine specified protocol categories
   - "Inconclusive" - Cannot determine with the given information

2. Protocol Family: If Protocol-Related, you MUST identify the specific protocol family from the following NINE protocol categories ONLY:
   - "TLS/DTLS" - Transport Layer Security / Datagram Transport Layer Security
   - "SSH" - Secure Shell
   - "HTTP" - Hypertext Transfer Protocol
   - "MQTT" - Message Queuing Telemetry Transport
   - "CoAP" - Constrained Application Protocol
   - "IP/ICMP/ARP" - Internet Protocol / Internet Control Message Protocol / Address Resolution Protocol
   - "Wi-Fi" - Wireless Fidelity
   - "BT/BLE" - Bluetooth / Bluetooth Low Energy
   - "ZigBee" - ZigBee protocol
   
   IMPORTANT: 
   - If the protocol does NOT belong to any of these nine categories, you MUST return "Not Protocol-Related" in Judgment
   - If multiple protocols are involved, choose the primary one from these nine categories
   - DO NOT use any other protocol names outside these nine categories

3. Explanation: Provide detailed reasoning for your judgment and protocol identification.

Final output MUST be a valid JSON object.
You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
Only return this line:

### Example Output:
Final Answer: {{
    "CVE_ID": "{cve_id}",
    "Judgment": "Protocol-Related",
    "Protocol_Family": "TLS/DTLS",
    "Explanation": "This vulnerability affects the SSL/TLS protocol implementation in OpenSSL, specifically the certificate validation process during the handshake phase. The description clearly indicates OpenSSL, which is a TLS/DTLS implementation library."
}}"""


def get_cve_protocol_identification_prompt(cve_id, summary):
    """
    生成CVE协议识别prompt
    
    Args:
        cve_id: CVE编号
        summary: 漏洞描述
    
    Returns:
        str: 格式化的prompt字符串
    """
    return CVE_PROTOCOL_IDENTIFICATION_PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        summary=summary
    )


if __name__ == "__main__":
    # 测试prompt生成
    test_prompt = get_cve_protocol_identification_prompt(
        cve_id="CVE-2023-1234",
        summary="OpenSSL vulnerability in SSL/TLS implementation"
    )
    print("Generated prompt:")
    print(test_prompt)

