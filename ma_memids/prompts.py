NOTE_EXTRACTION_SYSTEM = """你是入侵检测规则分析专家。你只输出 JSON。"""

NOTE_EXTRACTION_USER = """【规则/流量文本】
{text}

【CVE 描述】
{cve_description}

【ATT&CK 详情】
{attack_description}

请输出 JSON：
{{
  "intent": "一句话描述检测意图，结合 CVE 和战术背景",
  "keywords": ["漏洞描述或流量中可用于检测的关键词"],
  "tactics": ["T1190", "..."]
}}
"""

TRAFFIC_CLASSIFICATION_SYSTEM = """你是网络流量攻防分析专家。你只输出 JSON。"""

TRAFFIC_CLASSIFICATION_USER = """请基于以下流量 Note 信息判断该流量是否为攻击。

【流量意图】
{intent}

【关键词】
{keywords}

【ATT&CK 战术技术】
{tactics}

【关联 CVE】
{cve_ids}

【流量文本片段】
{content}

输出 JSON：
{{
  "is_attack": true,
  "attack_type": "xss/sql_injection/rce/lfi/command_injection/webshell/other/benign",
  "confidence": "high/medium/low",
  "reason": "简洁说明判定依据"
}}

注意：
1) 只能输出 JSON，不要输出其他文字。
2) 如果是正常流量，is_attack=false，attack_type 填 "benign"。
"""

RULE_REPAIR_SYSTEM = """你是 Suricata 规则修复专家。只输出完整 Suricata 规则。"""

RULE_REPAIR_USER = """【已有规则】
{base_rule}

【规则意图】
{base_intent}

【流量新出现的特征】
{new_features}

请修复规则，使其同时覆盖原始攻击和该变体。
要求：保持核心逻辑不变，补充/修改匹配条件，更新 msg，rev+1。
输出：完整 Suricata 规则。
"""

RULE_GENERATE_SYSTEM = """你是 Suricata 规则生成专家。只输出完整 Suricata 规则。"""

RULE_GENERATE_USER = """【攻击意图】{intent}
【关键词】{keywords}
【网络上下文】{network_context}
【ATT&CK】{tactics}
【关联CVE】{cve_ids}
【生成约束】
{generation_constraints}
【参考结构】
{reference_rules}

要求：至少2个独立检测原语，正确设置协议/方向/端口，添加 msg/sid/rev/metadata。
输出：完整 Suricata 规则。
"""

FAILURE_ANALYSIS_USER = """当前规则验证失败。
Recall={recall:.4f}, FPR={fpr:.4f}, Score={score:.4f}
诊断：{diagnosis}

请按诊断方向改写一条新的 Suricata 规则，输出完整规则。
"""
