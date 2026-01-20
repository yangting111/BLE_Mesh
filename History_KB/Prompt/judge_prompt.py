#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Judge模型Prompt模板
"""

# Judge模型Prompt模板
JUDGE_PROMPT_TEMPLATE = """You are an expert judge. Please analyze the following three model responses to the same question:

Original Question: {prompt}

Model Responses:
{responses_text}

Please conduct the following analysis:
1. Compare the consistency and differences between the three responses
2. Evaluate the accuracy and credibility of each response
3. Identify potential errors or biases
4. Provide the final verified fact
5. Check if the three responses can be discovered by black-box testing.
6. If it can be discovered by black-box testing, what data packets need to be sent, and how to construct the data packets or the order of the data packets?

### Output Requirements

1. Return analysis results in JSON format with the following fields:
   - analysis: Detailed analysis
   - final_fact:  Only return `"Protocol-Related"` or `"Not Protocol-Related"` or `"Inconclusive"`
   - black_box_testing: Only return `"Yes"` or `"No"`
   - data_packets: If `"Yes"`, return the data packets need to be sent, and how to construct the sending data packets or the order of the data packets. If `"No"`, return `"Not applicable"`.

Final output MUST be a valid JSON object.
You MUST wrap the JSON with the prefix `Final Answer:` so the agent can recognize it.
Do NOT include any markdown formatting like ```json or extra explanation outside the JSON.
Only return this line:

### Example Output:
Final Answer: {{
    "analysis": "Response comparison: Model-A and Model-B both determined protocol-related, with consistent explanations pointing to SSL protocol implementation session reuse vulnerabilities affecting security mechanisms and state management. Model-C failed to provide valid response due to technical errors.",
    "final_fact": "Protocol-Related",
    "black_box_testing": "Yes",
    "data_packets": "Data packets need to be sent, and how to construct the sending data packets or the order of the data packets."
}}"""


def get_judge_prompt(prompt, responses_text):
    """
    Generate Judge model verification prompt
    
    Args:
        prompt: Original question
        responses_text: Model response text
    
    Returns:
        str: Formatted prompt string
    """
    return JUDGE_PROMPT_TEMPLATE.format(
        prompt=prompt,
        responses_text=responses_text
    )


if __name__ == "__main__":
    # Test prompt generation
    test_prompt = get_judge_prompt(
        prompt="Test question",
        responses_text="Model response 1\nModel response 2\nModel response 3"
    )
    print("Generated judge prompt:")
    print(test_prompt)