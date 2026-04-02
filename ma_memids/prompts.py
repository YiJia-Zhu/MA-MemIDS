RETRIEVAL_PLANNER_SYSTEM = """你是入侵检测知识检索规划专家。你只输出 JSON。"""

RETRIEVAL_PLANNER_USER = """请为以下{artifact_type}生成双路检索规划。

【原始文本】
{text}

【显式特征清单】
{feature_inventory}

【网络上下文】
{network_context}

【已知关键词提示】
{seed_keywords}

【已知 ATT&CK / 技术提示】
{seed_tactics}

要求：
1) `sparse_terms` 面向 Sparse/BM25，保留漏洞名、payload 关键片段、攻击动作词、CVE、ATT&CK 技术编号。
2) `dense_query` 面向 Dense embedding，必须改写成简洁的语义检索描述，不要直接照搬整段原始流量/规则。
3) `dense_query` 中不要保留裸 IP、临时源端口、长随机串、大段 header 噪声；只保留有语义的协议、服务、payload 信号、攻击意图。
4) `protocols` 只保留协议名，例如 HTTP / DNS / SMB。
5) `payload_signals` 只保留高信号 payload 片段，例如 `jndi ldap lookup`、`<script>`、`cmd.exe`、`union select`。
6) `network_roles` 使用抽象角色，例如 `public_to_private`、`private_to_private`、`internet_to_server`、`client_to_server`。
7) `service_ports` 只保留有业务语义的服务端口，不要保留临时高位端口。
8) `selected_features` 列出你认为真正应该进入检索的特征。
9) `discarded_features` 列出你看到但不建议直接进入检索的特征，例如裸 IP、临时端口、长噪声 header 等。
10) 如果 `feature_inventory` 里包含 `reference_evidence`，这是规则中人工维护的高可信证据，应优先保留其中的 CVE / ATT&CK / 产品或 payload 线索，双路检索只能补充，不能覆盖它。

输出 JSON：
{{
  "intent": "一句话攻击/检测意图",
  "sparse_terms": ["term1", "term2"],
  "dense_query": "一条语义化检索句子",
  "cve_ids": ["CVE-2021-44228"],
  "tech_ids": ["T1190"],
  "protocols": ["HTTP"],
  "payload_signals": ["jndi ldap lookup"],
  "network_roles": ["public_to_private"],
  "service_ports": [80, 443],
  "selected_features": ["jndi ldap lookup", "HTTP", "public_to_private"],
  "discarded_features": ["src_ip=8.8.8.8", "src_port=51515"]
}}
"""

REFERENCE_PARSE_SYSTEM = """你是安全参考网页解析器。你只输出 JSON。"""

REFERENCE_PARSE_USER = """请从以下 reference 页面内容中提取结构化证据。

【URL】
{source_url}

【页面标题】
{title}

【页面文本片段】
{reference_text}

要求：
1) 只提取高置信度安全证据，不要臆造。
2) 若能明确看到 CVE 或 ATT&CK 技术编号，直接输出规范格式。
3) `trusted_terms` 只保留后续适合做检索增强的高信号术语，如漏洞名、产品名、关键利用动作、payload 信号。
4) 输出 JSON，不要附加解释。

输出 JSON：
{{
  "reference_summary": "一句话总结这个 reference 页面在说什么",
  "cve_ids": ["CVE-2021-44228"],
  "tech_ids": ["T1190"],
  "trusted_terms": ["log4j", "jndi ldap lookup", "remote code execution"]
}}
"""

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
