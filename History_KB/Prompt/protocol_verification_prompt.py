#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE协议相关性验证Prompt模板
"""

# CVE协议相关性验证Prompt模板
CVE_PROTOCOL_PROMPT_TEMPLATE = """You are a network protocol security expert. Please analyze the following CVE vulnerability information and determine whether this vulnerability is related to network protocol implementation.

CVE Information:
- CVE ID: {cve_id}
- Published: {published}
- Severity: {v3_severity}
- CVSS Score: {v3_score}
- Description: {summary}
- Related Products: {cpe_list}

### Analysis Requirements

Please analyze from the following perspectives:
1. Does the vulnerability involve network protocol stack implementation (such as TCP, UDP, HTTP, HTTPS, SSL/TLS, DNS, FTP, SMTP, Bluetooth, etc.)?
2. Is the vulnerability related to data processing during network communication?
3. Does the vulnerability affect security mechanisms of network protocols?
4. Is the vulnerability related to network protocol state machines or handshake processes?
5. Can the vulnerability be discovered by black-box testing? 
6. If it can be discovered by black-box testing, what data packets need to be sent, and how to construct the data packets or the order of the data packets?

### Output Requirements

1. Conclude with `"Protocol-Related"` or `"Not Protocol-Related"` or `"Inconclusive"` in `<Judgment>`.
2. Explain reasoning in `<Explanation>`:
   - If Protocol-Related: Explain which protocol aspects are affected.
   - If Not Protocol-Related: Explain why it's not protocol-related.
   - If Inconclusive: List missing details needed for analysis.

Final output MUST be a valid JSON object.
You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
Only return this line:

### Example Output:
Final Answer: {{
    "CVE_ID": "{cve_id}",
    "Judgment": "Protocol-Related",
    "Explanation": "This vulnerability affects the SSL/TLS protocol implementation in OpenSSL, specifically the certificate validation process during the handshake phase, making it directly related to network protocol security mechanisms."
    "Black-box_Testing": Only return `"Yes"` or `"No"`
    "Data_Packets": If `"Yes"`, return the data packets need to be sent, and how to construct the sending data packets or the order of the data packets. If `"No"`, return `"Not applicable"`.
}}"""


def get_cve_protocol_prompt(cve_id, published, v3_severity, v3_score, summary, cpe_list):
    """
    生成CVE协议相关性验证prompt
    
    Args:
        cve_id: CVE编号
        published: 发布时间
        v3_severity: 严重程度
        v3_score: CVSS评分
        summary: 漏洞描述
        cpe_list: 相关产品列表
    
    Returns:
        str: 格式化的prompt字符串
    """
    return CVE_PROTOCOL_PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        published=published,
        v3_severity=v3_severity,
        v3_score=v3_score,
        summary=summary,
        cpe_list=cpe_list
    )


if __name__ == "__main__":
    # 测试prompt生成
    test_prompt = get_cve_protocol_prompt(
        cve_id="CVE-2023-1234",
        published="2023-01-01",
        v3_severity="HIGH",
        v3_score="7.5",
        summary="OpenSSL vulnerability in SSL/TLS implementation",
        cpe_list="openssl:openssl:1.1.1"
    )
    print("Generated prompt:")
    print(test_prompt)
