# MA-MemIDS：基于多智能体记忆演化的 IDS 规则自主生成框架

## 摘要

入侵检测系统（IDS，如 Suricata / Snort）的规则维护面临三大挑战：异构多源信息的语义断层、生成规则过拟合与过泛化难以权衡、以及规则生成的滞后性与静态架构限制。本文提出 **MA-MemIDS**，以结构化记忆笔记（Note）为核心信息单元，通过双路知识检索富化 Note、邻接图 Top-k 相似检索驱动规则增修、$F_\beta$-FPR 联合评分沙盒验证闭环，实现 IDS 规则库从"被动存储"到"主动演化"的跨越。

---

## 1. 引言

### 1.1 背景

Suricata / Snort 等 IDS/IPS 的核心是**规则签名检测**——匹配数据包中的特定字段（载荷特征、IP、端口、协议）来阻断已知攻击。这一范式面临三重挑战：

**挑战 1：异构多源信息的语义断层**

原始流量的二进制载荷、结构化网络元数据与自然语言漏洞描述（CVE / ATT&CK）之间存在表义鸿沟，LLM 难以直接从流量字节推导防御逻辑。**对策**：将规则与流量统一表示为同构 Note，通过双路知识检索（关键词精确匹配 + 语义相似检索）富化外部知识后，全信息编码为同一语义向量空间，消除跨模态对齐障碍。

**挑战 2：生成规则过拟合与过泛化难权衡**

规则过窄则漏报攻击变体，过宽则误报飙升。**对策**：沙盒中引入 $Score = F_2 \times P_{fpr}$ 联合评分，$\beta=2$ 偏重召回率，FPR 超过 5% 红线后指数惩罚骤降，构建量化自适应边界。

**挑战 3：规则生成的滞后性与静态架构**

人工维护规则响应 CVE 极其缓慢，平面化规则库缺乏自主演化能力。**对策**：受 Zettelkasten 启发的 A-Mem 记忆演化系统，新 Note 存入后自动触发邻接图更新与关联笔记级联修订。

---

## 2. 系统架构

系统分为**两个阶段**，严格对应图 1：

```
══════════════════════════════════════════
阶段一：初始化（离线，执行一次）
══════════════════════════════════════════

  社区规则库 R_init
       │
       ▼
  【双路知识检索】CVE / ATT&CK / CTI
       │
       ▼
  【生成 Note】规则 + 外部知识 → 结构化笔记 m_i
       │
       ▼
  【构建邻接表】全信息 Embedding + 相似度计算
                → 稀疏邻接图 + ANNS 索引

══════════════════════════════════════════
阶段二：自动化防御规则生成（在线，持续运行）
══════════════════════════════════════════

  Suricata/Snort 未匹配流量 / PCAP
       │
       ▼
  【双路知识检索】CVE / ATT&CK / CTI
       │
       ▼
  【生成 Note】流量 + 外部知识 → 流量笔记 m_p（与规则 Note 同构）
       │
       ▼
  【人工介入（可选）】修正意图 / 战术标签
       │
       ▼
  【相似检索】邻接图 Top-k，综合权重 w_ij
       │
       ▼
  【增修规则】LLM 生成 / 修复 Suricata 规则
       │
       ▼
  【沙盒验证】全规则集回放（基线 vs 候选）
              Score = F₂ × P_fpr
       │
  ┌────┴────┐
通过         不通过
  │           │
记忆固化    失败分析 → 重生成（最多3次）
  │           └→ 仍失败 → 人工审核
  ▼
相似检索（冗余检查）→ 增修/合并规则
```

---

## 3. 核心数据结构：Note

### 3.1 形式化定义

Note 是本系统的**核心信息单元**。规则和流量都被统一表示为同构 Note，使两者在同一语义空间中直接可比：

$$
m_i = \langle c_i,\ X_i,\ K_i,\ T_i,\ \mathbf{e}_i,\ \mathcal{L}_i,\ \mathcal{A}_i,\ \tau_i \rangle
$$

| 字段 | 含义 | 来源 |
|------|------|------|
| $c_i$ | 原始规则文本 / 流量结构化摘要 | 规则库 / PCAP 解析 |
| $X_i$ | 检测攻击的意图（一句话自然语言） | LLM 提取 |
| $K_i$ | 匹配字段 / 攻击关键词集合 | 规则解析 + LLM |
| $T_i$ | ATT&CK 战术标签（如 `T1190`） | 知识检索 + LLM |
| $\mathbf{e}_i \in \mathbb{R}^d$ | **全信息语义嵌入向量** | Embedding 模型 |
| $\mathcal{L}_i$ | 链接集合 $\{(m_j,\ \ell_{ij},\ w_{ij})\}$ | 邻接图构建 |
| $\mathcal{A}_i$ | 外部知识（CVE 详情、CTI 链接、参考） | 双路知识检索 |
| $\tau_i$ | 时间戳与版本 | 系统生成 |

### 3.2 全信息 Embedding

$\mathbf{e}_i$ 编码 Note 的**全部字段**，而非仅规则文本。将各字段序列化后统一送入嵌入模型：

$$
\mathbf{e}_i = \text{Embed}\bigl(\underbrace{X_i}_{\text{意图}} \;\|\; \texttt{[KW]}\underbrace{K_i}_{\text{关键词}} \;\|\; \texttt{[TACT]}\underbrace{T_i}_{\text{战术}} \;\|\; \texttt{[CVE]}\underbrace{\mathcal{A}_i.\text{desc}}_{\text{漏洞描述}} \;\|\; \texttt{[RULE]}\underbrace{c_i}_{\text{原文}}\bigr)
$$

**字段顺序设计**：语义最丰富的 $X_i$ 放最前，利用 Transformer 对序列前段的注意力权重更高的特性；$c_i$ 放最后，因规则语法噪声较多。全信息编码使同构的规则 Note 与流量 Note 在同一向量空间可直接比较。

---

## 4. 阶段一：初始化

### 4.1 双路知识检索（Pre-Note Knowledge Retrieval）

在生成 Note 之前，对三类外部知识库执行**双路并行检索**，两路互补融合：

#### 知识库接入

| 知识库 | 当前支持输入 | 当前实现 | 说明 |
|--------|--------------|----------|------|
| CVE（CVEProject JSON） | 官方 JSON 文件或目录 | 本地标准化文档 + SQLite FTS5/BM25 + Dense 向量缓存 | 预构建后缓存到 `memory/knowledge_cache` |
| ATT&CK（MITRE STIX） | STIX bundle 文件或目录 | 本地标准化文档 + SQLite FTS5/BM25 + Dense 向量缓存 | 目录可直接指向 `cti-ATT-CK-v18.1` |
| CTI（可选） | 通用 `json/jsonl` | 本地标准化文档 + SQLite FTS5/BM25 + Dense 向量缓存 | 当前不依赖 OpenCTI 在线 API |

当前工程不会对这些知识源做实时在线查询，而是统一预处理为本地标准文档，再走同一套 `Sparse + Dense + RRF` 检索逻辑。Dense 向量默认用 `sentence-transformers/all-MiniLM-L6-v2`，并可选加载 HNSW 作为加速索引。

#### 双路检索流程

```
输入：规则原文 c_i（或流量摘要）

Step 0：显式特征清单整理
  feature_inventory =
    网络上下文（protocol / src,dst / zone / direction）
    + payload_features
    + http_features
    + observed_headers
    + explicit_ids（CVE / ATT&CK）
    + line_features

Step 1：Retrieval Planner
  输入：c_i + feature_inventory
  输出：
    sparse_query
    dense_query
    selected_features
    discarded_features
    cve_ids / tech_ids / protocols / payload_signals / network_roles / service_ports

Step 2：Sparse Retrieval（SQLite FTS5 / BM25）
  ├─ 用 planner 产出的 sparse_query
  ├─ 结合显式 CVE / ATT&CK 编号的规范化形式
  └─ 分别查询 CVE / ATT&CK / CTI 三库

Step 3：Dense Retrieval（all-MiniLM-L6-v2）
  ├─ 用 planner 产出的 dense_query
  ├─ dense_query 是语义化改写结果，不直接使用整段原始流量/规则全文
  └─ 分别查询 CVE / ATT&CK / CTI 三库的 Dense 向量缓存

Step 4：结果融合（RRF）
  ├─ 分别取 Sparse Top-5 与 Dense Top-5
  ├─ 用 `RRF(k=60)` 统一融合
  └─ 输出：A_enriched = {cve_docs, attack_docs, cti_docs, cve_ids, tech_ids, debug}
```

**双路的互补性**：Sparse 路径擅长命中结构化标识符、payload 关键片段和路径/函数名等强关键词；Dense 路径擅长对齐“攻击意图 + 协议 + payload 信号 + 网络角色”这类语义描述。当前实现不是“让 Dense 直接吃原始流量全文”，而是先由 planner 判断该搜什么，再把语义改写后的 `dense_query` 送入 embedding 检索。

### 4.2 Note 构建（Algorithm 1）

```
Algorithm 1: Note Construction
输入：规则 r_i，检索计划 P_i，外部知识 A_enriched
输出：记忆笔记 m_i

Step 1: 规则解析
  c_i = r_i
  feature_inventory_i = 提取规则中的 content / pcre / msg /
                        protocol / src,dst / CVE / ATT&CK 等显式特征

Step 2: Retrieval Planner
  输入：c_i + feature_inventory_i
  输出：
    P_i = {sparse_query, dense_query, selected_features, discarded_features, ...}

Step 3: 双路知识检索
  输入：P_i
  输出：A_enriched = {cve_docs, attack_docs, cti_docs, cve_ids, tech_ids}

Step 4: LLM 提取语义字段
  输入：c_i + A_enriched（CVE 描述、ATT&CK 详情）
  输出：
    X_i ← 检测攻击的意图（一句话）
    K_i ← 显式规则字段 + planner 派生的检索特征（sparse_terms / payload_signals / protocols / network_roles / service_ports）+ LLM 补充关键词
    T_i ← 显式 ATT&CK 技术号 + planner / LLM 归纳的战术标签

Step 5: 全信息 Embedding
  e_i = Embed(serialize(X_i, K_i, T_i, A_i.cve_desc, c_i))

Step 6: 组装笔记
  m_i = ⟨c_i, X_i, K_i, T_i, e_i, L_i=∅, A_enriched, τ=now()⟩
```

**LLM Prompt（检索规划）：**

```
你是入侵检测知识检索规划专家。

【原始文本】{text}
【显式特征清单】{feature_inventory}
【网络上下文】{network_context}

请输出 JSON：
{
  "intent": "...",
  "sparse_terms": ["..."],
  "dense_query": "...",
  "cve_ids": ["CVE-2021-44228"],
  "tech_ids": ["T1190"],
  "protocols": ["HTTP"],
  "payload_signals": ["jndi ldap lookup"],
  "network_roles": ["public_to_private"],
  "service_ports": [80, 443],
  "selected_features": ["..."],
  "discarded_features": ["..."]
}
```

**LLM Prompt（Note 构建）：**

```
你是入侵检测规则分析专家。

【规则文本】{rule_text}
【CVE 描述】{cve_description}
【ATT&CK 详情】{attack_technique_desc}

请输出 JSON：
{
  "intent":   "一句话描述检测意图，结合 CVE 和战术背景",
  "keywords": ["漏洞描述中推断的隐含攻击关键词"],
  "tactics":  ["T1190", ...]
}
```

### 4.3 邻接图构建（Algorithm 2）

#### 综合相似度（链接权重）

邻接图每条边的权重 $w_{ij}$ 综合三个维度：

$$
\boxed{w_{ij} = \alpha \cdot \underbrace{\cos(\mathbf{e}_i,\ \mathbf{e}_j)}_{\text{全信息语义}} + \beta \cdot \underbrace{\frac{|K_i \cap K_j|}{|K_i \cup K_j|}}_{\text{关键词 Jaccard}} + \gamma \cdot \underbrace{\frac{|T_i \cap T_j|}{|T_i \cup T_j|}}_{\text{战术标签重叠}}}
$$

$$\alpha=0.5,\quad \beta=0.1,\quad \gamma=0.2,\quad \delta=0.15,\quad \epsilon=0.05$$

**为何不只用 Embedding 余弦**：全信息 Embedding 是连续隐式表示，无法区分"语义相似但结构关系很弱"与"共享 CVE / 关键词包含"这类强结构关系。当前实现将余弦、关键词、战术、CVE 与包含信号统一融合到一个分数中，避免“固定赋值”和“公式打分”割裂。

#### 链接类型

| 类型 | 建立条件 | 权重 |
|------|----------|------|
| `exploit_chain` | 共享 CVE ID | 使用统一 $w_{ij}$，仅作为关系标签 |
| `tactic_group` | $\|T_i \cap T_j\| \geq 1$ | 动态 $w_{ij}$ |
| `semantic_similar` | $w_{ij} \geq \theta_w=0.60$ | 动态 $w_{ij}$ |
| `subsume` | $K_i \subseteq K_j$ | 使用统一 $w_{ij}$，仅作为关系标签 |

#### 构建算法

```
Algorithm 2: Build Adjacency Graph
参数：k=24（候选召回数），θ_w=0.40（边保留阈值）

For each pair (m_i, m_j), i < j:

  // 候选召回：向量近邻 + 结构化旁路
  C_i = HNSW_Search(e_i, top_k=24)
      ∪ SameCVE(i)
      ∪ KeywordOverlap(i)

  For each m_j in C_i:
    w_ij = 0.5*cos(e_i,e_j)
         + 0.1*|K_i∩K_j|/|K_i∪K_j|
         + 0.2*|T_i∩T_j|/|T_i∪T_j|
         + 0.15*OverlapCoeff(CVE_i,CVE_j)
         + 0.05*OverlapCoeff(K_i,K_j)

    If A_i.cve ∩ A_j.cve ≠ ∅: Mark link_type += exploit_chain
    If K_i ⊆ K_j or K_j ⊆ K_i: Mark link_type += subsume
    If T_i ∩ T_j ≠ ∅: Mark link_type += tactic_group
    If no explicit structure label: Mark link_type += semantic_similar

    If A_i.cve ∩ A_j.cve ≠ ∅ or K_i ⊆ K_j or K_j ⊆ K_i or w_ij >= θ_w:
      Add_Link(link_type, w_ij)

Build optional HNSW Index（fallback: exact cosine scan）on {e_i}
```

**当前工程实现说明**：代码已切换为“显式特征清单 + 检索规划 + 候选召回 + 统一精排打分”。embedding 默认使用 `sentence-transformers/all-MiniLM-L6-v2`（`384` 维），首次运行会自动下载并缓存。知识召回层现为统一的 Hybrid Retrieval：先整理规则/流量的显式 `feature_inventory`，再由 Retrieval Planner 生成 `sparse_query` 与 `dense_query`，并额外标记 `selected_features` / `discarded_features`，然后将 ATT&CK STIX 与 CVE 官方 JSON 预处理成标准文档，并分别执行 Sparse Retrieval（SQLite FTS5 / BM25）和 Dense Retrieval（embedding 近邻），最后使用 `RRF(k=60)` 融合两路前 `top5` 候选。Dense 查询不再直接吃整段原始流量，而是使用语义化改写后的检索描述；若环境中可用 `hnswlib`，知识库 Dense 检索会自动加载预构建 HNSW；否则回退为精确 Dense 扫描。最终建边时不再使用“同协议固定权重”或 `cos >= 0.75` 的硬门槛，而是统一使用融合分数，并保留 `exploit_chain / subsume / tactic_group / semantic_similar` 作为关系标签。

---

## 5. 阶段二：自动化防御规则生成

### 5.1 流量采集：Suricata 未匹配流量的 PCAP 保存

Suricata 作为 IPS 运行时，未匹配流量默认放行不保存。通过以下配置留存流量供 Agent 分析：

**方案 A（研究/测试环境）：内置 pcap-log**

```yaml
# suricata.yaml
outputs:
  - pcap-log:
      enabled: yes
      filename: /var/log/suricata/capture-%n.pcap
      limit: 100mb
      mode: multi
      conditional: all        # 保存所有流量（含未匹配）
  - eve-log:
      types:
        - alert:
            payload: yes      # Eve JSON 中附带 Base64 Payload
            packet: yes
        - flow:
            all: yes          # 记录全部 flow 事件（含无告警的）
```

未匹配流量识别：Eve JSON 中存在 `flow` 事件但无对应 `alert` 事件的 `flow_id`，即为未匹配流量，按 `flow_id` 从 pcap-log 中提取对应数据包。

**方案 B（生产环境）：旁路镜像**

IPS 侧零性能开销，通过端口镜像/TAP 将流量复制到独立采集节点（Arkime / Zeek），Agent 按 `flow_id` 从采集节点拉取 PCAP。两种方案对比：

| 方案 | 性能影响 | 完整性 | 适用场景 |
|------|----------|--------|----------|
| pcap-log conditional:all | +10% 延迟 | 完整 PCAP | 研究/测试 |
| Eve JSON payload 字段 | +3% | 单包 Payload | 快速原型 |
| 旁路镜像（Arkime/Zeek） | 零影响 | 完整 PCAP + 流重组 | 生产环境 |

**PCAP → Agent 输入**：LLM 无法直接消费二进制，用 `pyshark` / `scapy` 先解析为结构化摘要（协议、五元组、Payload 文本、HTTP 解析），作为流量 Note 的 $c_p$ 字段。

### 5.2 流量 Note 构建（与规则 Note 同构）

未匹配流量经 PCAP 解析后，执行与阶段一**同构**的 Note 构建流程：

```
未匹配流量 p（PCAP 解析摘要）
       │
       ▼
  显式特征清单整理
  ├─ network_context
  ├─ payload_features
  ├─ http_features
  ├─ observed_headers
  └─ explicit_ids
       │
       ▼
  Retrieval Planner
  ├─ 产出 sparse_query / dense_query
  └─ 标记 selected_features / discarded_features
       │
       ▼
  双路知识检索（Sparse BM25 + Dense + RRF）
       │
       ▼
  LLM 生成 Note（同 Algorithm 1）
  X_p ← 推断的攻击意图
  K_p ← 流量显式特征 + planner 派生的检索特征（sparse_terms / payload_signals / protocols / network_roles / service_ports）+ LLM 补充
  T_p ← planner / 外部知识 / LLM 综合得到的 ATT&CK 技术
  e_p ← 全信息 Embedding（serialize(X_p, K_p, T_p, A_p, c_p)）
```

**同构设计的价值**：规则 Note 与流量 Note 字段结构完全相同，$\mathbf{e}_i$ 与 $\mathbf{e}_p$ 处于同一语义空间，可直接用 $w_{ij}$ 公式衡量相似度，无需跨模态桥接。

### 5.3 人工介入（可选）

流量 Note 生成后、相似检索前，管理员可修正 $X_p$（LLM 推断的攻击意图）或 $T_p$（战术标签），修正后重新计算 $\mathbf{e}_p$。对首次出现的新型攻击尤为重要——人工标注可显著提升后续检索准确性。

### 5.4 相似检索（Top-k on Adjacency Graph）

对流量 Note $m_p$，在邻接图上执行 Top-k 相似检索：

```
Algorithm 3: Top-k Similarity Search
参数：k=24（ANN 粗召回），N=5（精排保留）

Step 1: ANN + 结构化候选召回
  candidates = HNSW_Search(e_p, k=24) ∪ SameCVE(p) ∪ KeywordOverlap(p)

Step 2: 精确重排
  For each m_i in candidates:
    w_pi = 0.5*cos(e_p,e_i)
          + 0.1*|K_p∩K_i|/|K_p∪K_i|
          + 0.2*|T_p∩T_i|/|T_p∪T_i|
          + 0.15*OverlapCoeff(CVE_p,CVE_i)
          + 0.05*OverlapCoeff(K_p,K_i)

Step 3: 一跳邻居扩展
  top5     = Top-5(candidates, by=w_pi)
  expanded = top5 ∪ direct_neighbors(top5)  // 捕获间接关联
  
Return Top-N(expanded, N=5, by=w_pi)
```

**不需要多路召回的原因**：邻接图的 $w_{ij}$ 已将语义、关键词、战术三维信号融合在每条边上；ANNS 基于全信息 Embedding 粗检索，精排阶段再补充精确 Jaccard 校正——无需再单独维护多条独立召回路径。

**当前工程实现说明**：代码中的 Top-k 检索已经升级为“Embedding ANN 粗召回 + 结构化候选补召回 + 统一融合精排”。ANN 只负责找向量近邻候选，不直接决定最终相似度；最终排序仍由统一公式完成，并继续支持 1-hop 邻居扩展。若未设置 `MA_MEMIDS_ENABLE_HNSW=1`，则 ANN 层自动回退为精确扫描。

### 5.5 增修规则

基于 Top-N 相似规则 Note 和流量 Note $m_p$，按相似度决定操作类型：

| 条件 | 操作 | LLM 任务 |
|------|------|----------|
| $\max(w_{pi}) \geq 0.80$ | 修复已有规则 | 在原规则基础上扩展原语，覆盖变体 |
| $0.60 \leq \max(w_{pi}) < 0.80$ | 参考生成新规则 | 借鉴相似规则结构，生成新规则 |
| $\max(w_{pi}) < 0.60$ | 从头生成新规则 | 完全基于流量 Note 特征生成 |

**规则修复 Prompt（$w \geq 0.80$）：**

```
【已有规则】{base_rule.c_i}
【规则意图】{base_rule.X_i}
【流量新出现的特征】{K_p - K_base}（流量有但规则没覆盖的关键词）

请修复规则，使其同时覆盖原始攻击和该变体。
要求：保持核心逻辑不变，补充/修改匹配条件，更新 msg，rev+1。
输出：完整 Suricata 规则
```

**新规则生成 Prompt（$w < 0.60$）：**

```
【攻击意图】{X_p}  【关键词】{K_p}
【ATT&CK】{T_p}   【关联CVE】{A_p.cve_ids}
【参考结构】{[m_i.c_i for m_i in TopN]}

要求：至少2个独立检测原语，正确设置协议/方向/端口，
      添加 msg/sid/rev/metadata。
输出：完整 Suricata 规则
```

---

## 6. 沙盒验证

### 6.1 联合评分函数

$$
\boxed{Score = F_\beta \times P_{fpr}}
$$

**有效性评分 $F_\beta$（$\beta=2$）：**

$$
F_\beta = \frac{(1+\beta^2)\times\text{Precision}\times\text{Recall}}{\beta^2\times\text{Precision}+\text{Recall}}, \quad \beta=2
$$

$\beta=2$ 使召回率权重是精确率的 **4 倍**，体现"宁可多报，绝不漏报"的安全优先原则。

**鲁棒性约束 $P_{fpr}$：**

$$
P_{fpr} = \exp\bigl(-10\times\max(0,\ \text{FPR}-0.05)\bigr)
$$

FPR 在 5% 以内不惩罚（$P_{fpr}=1.0$）；一旦超过红线，分数指数型骤降（FPR=15% 时 $P_{fpr}\approx0.37$），强制系统收缩规则匹配面。

### 6.2 验证流程

``` 
Algorithm 4: Sandbox Validation
输入：当前规则集 R_base、候选规则集 R_new，流量数据库（攻击流量 D_attack + 正常流量 D_benign）

Step 1: 语法检查
  Suricata_Syntax_Check(R_base / R_new) → 失败则直接返回错误

Step 2: 基线规则集回放（R_base）
  在 D_attack + D_benign 上回放，得到 TP_base/FP_base/TN_base/FN_base
  计算 Score_base

Step 3: 候选规则集回放（R_new）
  在同一批 D_attack + D_benign 上回放，得到 TP_new/FP_new/TN_new/FN_new
  计算 Score_new

Step 4: 指标计算（TPR / FPR）
  TP = 攻击流量中被命中的数量
  FP = 正常流量中被误报的数量
  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)   // TPR
  FPR       = FP / (FP + TN)

Step 5: 联合评分
  F2    = 5×Precision×Recall / (4×Precision + Recall)
  P_fpr = exp(-10 × max(0, FPR - 0.05))
  Score = F2 × P_fpr

Step 6: 决策（相对提升 + 容差）
  若 Score_new > Score_base + ε  → 通过，进入记忆固化
  否则                           → 失败分析 → 重生成（最多3次）
                                   → 仍失败 → 人工审核队列
```

### 6.3 失败分析

| 失败类型 | 诊断条件 | LLM 修复建议 |
|----------|----------|-------------|
| 过泛化 | $\text{FPR} > 0.10$ | 增加精确 content/pcre 原语；加 threshold 限速 |
| 过拟合 | $\text{Recall} < 0.50$ | 将硬编码特征替换为正则；补充漏报样本的新特征 |

失败分析结果连同诊断建议送回 LLM，触发规则重生成循环。3 次仍不通过则推送至管理员，由其**判断 LLM 分析是否正确并修改分析过程**（对应图中"判断LLM分析是否正确/修改分析过程"节点）。

---

## 7. 记忆固化与演化

### 7.1 沙盒通过后的写回

**规则修复（变体攻击）：**

```python
m_i.c_i  = r_repaired
m_i.X_i += f"；覆盖变体：{bypass_technique}"
m_i.K_i  = m_i.K_i | new_keywords          # 扩展关键词集合
m_i.e_i  = Embed(serialize_note(m_i))       # 全字段重新编码
m_i.τ_i  = now()

# 建立流量 Note 与规则 Note 的链接
Add_Link(m_i, m_p, l_strengthen, w=0.95)

# 级联更新：exploit_chain 邻居补充上下文
for m_j in neighbors(m_i, type=l_chain):
    m_j.A_j["context"] += f"关联规则已覆盖变体：{bypass_technique}"
    m_j.e_j = Embed(serialize_note(m_j))

# 增量更新 ANNS 索引
ANNS_Index.update(m_i)
```

**新规则生成：**

```python
m_new = build_note(r_new, A_enriched)
for m_j in Top5(m_new):                     # 在邻接图中建立链接
    if compute_w(m_new, m_j) >= θ_w:
        Add_Link(m_new, m_j, ...)
M.add(m_new)
ANNS_Index.add(m_new.e_i)                   # 增量索引，无需全量重建
```

### 7.2 相似检索（规则冗余控制）

固化完成后，对新规则执行相似检索（对应图中"相似检索"节点），检查是否与已有规则过度重叠：

$$
\text{Similar}(m_{\text{new}}) = \{m_j \mid w(m_{\text{new}},\ m_j) \geq \theta_{\text{merge}}=0.90\}
$$

若存在高度相似规则（$w \geq 0.90$），触发**增修规则**（合并为更通用的规则），避免规则库因变体累积而膨胀。

---

## 8. 完整端到端闭环

```
阶段一（离线初始化）
  规则库 → 双路知识检索 → 生成Note → 构建邻接图

阶段二（在线持续运行）
  未匹配流量（PCAP）
    ↓ 双路知识检索（CVE/ATT&CK/CTI）
    ↓ 生成流量 Note（同构，全信息 Embedding）
    ↓ [可选] 人工介入
    ↓ 相似检索（邻接图 Top-k，三维综合权重）
    ↓ 增修规则（LLM 生成/修复）
    ↓ 沙盒验证（全规则集：Score_new vs Score_base）
    ├─ Score_new > Score_base + ε → 记忆固化（更新Note+邻接图+级联）→ 相似检索（冗余控制）→ 增修规则
    └─ 未提升                     → 失败分析 → 重生成（≤3次）→ 仍失败 → 人工审核
```

---

## 9. 超参数汇总

| 参数 | 符号 | 默认值 | 含义 |
|------|------|--------|------|
| 规则修复阈值 | $\theta_{\text{high}}$ | 0.80 | $w \geq$ 此值触发修复已有规则 |
| 新规则参考阈值 | $\theta_{\text{med}}$ | 0.60 | $w <$ 此值从头生成新规则 |
| 语义初筛阈值 | $\theta_{\text{sem}}$ | 0.75 | 进入精排的最低余弦相似度 |
| 邻接图保留阈值 | $\theta_w$ | 0.60 | 邻接图边权重最低值 |
| 分数提升容差 | $\varepsilon$ | $10^{-6}$ | 仅当 `Score_new > Score_base + ε` 才通过 |
| 沙盒通过阈值（兼容） | $\theta_{\text{pass}}$ | 0.70 | 保留在通用单规则评估接口中，在线主流程不直接使用 |
| FPR 容差红线 | $\theta_{\text{fpr}}$ | 0.05 | 超过此值开始指数惩罚 |
| ANNS 粗检索数 | $k$ | 20 | 向量检索返回候选数 |
| 精排保留数 | $N$ | 5 | 进入增修的候选规则数 |
| 语义权重 | $\alpha$ | 0.5 | $w_{ij}$ 中 Embedding 余弦系数 |
| 关键词权重 | $\beta$ | 0.3 | $w_{ij}$ 中关键词 Jaccard 系数 |
| 战术权重 | $\gamma$ | 0.2 | $w_{ij}$ 中 ATT&CK 重叠系数 |
| $F_\beta$ 的 $\beta$ | $\beta$ | 2 | 召回率权重是精确率的 4 倍 |
| 规则合并阈值 | $\theta_{\text{merge}}$ | 0.90 | $w >$ 此值提示合并规则 |

---

## 10. 当前工程实现逻辑（与代码对齐，2026-03）

本节描述 `MA_MemIDS` 目录下当前代码的**实际执行逻辑**（以实现为准）。

### 10.1 关键模块映射

- `ma_memids/pipeline.py`：阶段一/阶段二主编排、重试、记忆固化、状态持久化。
- `ma_memids/note_builder.py`：规则/流量 Note 构建、LLM 语义提取、重嵌入。
- `ma_memids/validation.py`：Suricata 语法检查、单规则与规则集回放评估。
- `ma_memids/rule_engine.py`：规则生成与修复逻辑。
- `demo_server.py`：Demo API、默认路径解析、异步任务、trace 汇总。

### 10.2 阶段一（初始化）实际行为

1. 输入支持规则**文件或目录**，目录会递归读取 `.rules/.rule/.txt`。
2. 逐条规则构建规则 Note（显式特征清单整理 -> Retrieval Planner -> 双路检索 -> LLM 抽取 -> embedding）。
3. 写入 Note 图并自动重建相关链接。
4. 支持 `max_rules` 限流，避免一次初始化过大。
5. 初始化结束后写入 `memory/state.json`。

### 10.3 阶段二（在线）实际执行序列

1. 输入：`pcap_path` 或 `traffic_text`（至少一个）。
2. 若提供 PCAP：先解析为结构化文本（协议、五元组、HTTP、payload 预览）。
3. 若提供 PCAP：先用“当前全量规则集”做一次预检回放。
   - 若已有规则已确认命中（有真实 alert 详情），提前返回 `mode=already_covered`，不再进入 LLM 增修。
4. 仅在“未命中”时，执行“显式特征清单整理 → Retrieval Planner → 双路检索 → 流量 Note 构建 → Top-k 相似检索 → 规则提案”。
5. 根据主分析 PCAP（若有）做自动 attack/benign 标注，解析沙盒攻击/正常集合。
6. 若沙盒集合为空：走“仅语法检查”分支，不做回放评分。
7. 若沙盒集合非空：进入“全规则集前后对比”沙盒闭环（见 10.5）。
8. 失败时进入诊断与重生成回路（最多 3 次）。

### 10.4 主分析 PCAP 自动标注与沙盒集合构建

1. 主分析 PCAP 被视为未知标签样本。
2. 系统先基于流量 Note 调用 LLM 输出：
   - `is_attack`
   - `attack_type`
   - `confidence`
   - `reason`
3. 解析失败或调用失败时，降级为 `benign` 兜底。
4. 将主分析 PCAP 并入对应集合（attack/benign）前，按文件哈希去重。
5. 若同一文件已在另一集合中，会先移除再加入目标集合（覆盖迁移）。

### 10.5 沙盒验证：全规则集前后对比（当前准入标准）

1. 构建当前规则集 `R_base`（来自当前图中的全部规则 Note）。
2. 构建候选规则集 `R_new`：
   - `repair`：替换目标 base rule；
   - `scratch_generate`：在 `R_base` 基础上追加候选规则。
3. 在同一批 `D_attack + D_benign` 上分别评估 `R_base` 与 `R_new`。
4. 两侧都使用统一评分：
   - `F2 = 5PR / (4P + R)`
   - `P_fpr = exp(-10 * max(0, FPR - 0.05))`
   - `Score = F2 * P_fpr`
5. 准入条件（当前主流程）：
   - `Score_new > Score_base + ε`
   - 其中 `ε` 来自环境变量 `MA_MEMIDS_SCORE_IMPROVE_EPSILON`，默认 `1e-6`。
6. 通过后：
   - 执行记忆固化（更新/新增规则 Note、建立链接、重嵌入）；
   - 更新基线缓存为“已接受规则集”的最新指标；
   - 保存状态。

### 10.6 失败分析与重生成回路

1. 若候选未提升（或语法/回放异常），进入失败诊断：
   - `Recall = 0 且 FN > 0` → `coverage_gap`（优先提示检查规则头方向/网段变量）
   - `FPR > 0.10` → `overgeneralization`
   - `Recall < 0.50` → `overfitting`
   - 其他 → `low_score`
2. 诊断、分数差、Precision/Recall/FPR 会拼入反馈块。
3. 下一轮会把反馈块注入流量文本，再次执行“显式特征清单整理 → Retrieval Planner → 双路检索 → Note → 提案”。
4. 最多 3 次；仍不通过则返回失败，等待人工审核。

### 10.7 基线缓存机制（避免重复计算）

1. 缓存键由两部分组成：
   - `dataset_signature`：沙盒攻击/正常 PCAP 集合签名（基于文件 hash）。
   - `ruleset_signature`：当前全规则集文本签名。
2. 两者都一致时，复用上次 `Score_base`（缓存命中）。
3. 任一变化（数据集变化或规则集变化）都会触发基线重算。
4. 缓存字段保存在 `state.json` 的 `sandbox_baseline` 下：
   - `dataset_signature`
   - `ruleset_signature`
   - `ruleset_size`
   - `metrics`
   - `updated_at`

### 10.8 Demo 端默认输入与三类 PCAP 角色

1. 主分析流量 `pcap_file`：未知标签，先判别再并入沙盒集。
2. 沙盒攻击样本 `attack_pcap`：用于计算 TP/FN。
3. 沙盒正常样本 `benign_pcap`：用于计算 FP/TN。
4. 若未上传沙盒样本，默认读取：
   - `sandbox_samples/attack`
   - `sandbox_samples/benign`

### 10.9 当前实现与理论描述的关键差异

1. 理论版常用“绝对阈值 `θ_pass`”决策。
2. 当前工程主流程采用“**相对提升 + 容差**”决策：
   - `Score_new > Score_base + ε`
3. `θ_pass` 仍保留在通用评估接口中，用于兼容单规则评估场景，但不是在线主闭环的准入门槛。
