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
  【沙盒验证】流量数据库回放 → TPR / FPR
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

| 知识库 | 数据量 | 接入方式 | 更新频率 |
|--------|--------|----------|----------|
| CVE（NVD / CVEProject） | 20 万+ 条，持续增长 | 本地向量库（FAISS）+ BM25 索引 | 每日增量同步 |
| ATT&CK（MITRE） | ~600 个 Technique | 全量内存加载（< 10MB） | 季度更新 |
| CTI（OpenCTI） | 动态 | GraphQL API 按需查询 | 实时 |

CVE 数量庞大，不适合实时在线查询，需**本地向量化存储**，并监听 CVEProject GitHub 的每日 delta 文件做增量更新。ATT&CK 数量少，全量加载进内存后同样构建双路索引。

#### 双路检索流程

```
输入：规则原文 c_i（或流量摘要）

路径1：关键词精确匹配（BM25）
  ├─ 正则提取结构化标识符：CVE-\d{4}-\d+，T\d{4}(\.\d{3})?
  ├─ NLP 提取协议字段名、函数名、路径等攻击原语
  └─ BM25 精确查询三库 → 召回精确命中结果（权重=1.0）

路径2：语义相似度检索（FAISS）
  ├─ e_query = Embed(c_i)
  └─ FAISS Top-k 查询三库 → 召回语义相似结果（权重=cos_score）

融合规则：
  同一结果两路都命中 → 取最高分（互补，不惩罚重复）
  仅关键词命中       → 权重 = 1.0（精确信号，强置信）
  仅语义命中         → 权重 = cos_score（语义强度）

输出：A_enriched = {cve_docs, attack_docs, cti_docs, cve_ids, tech_ids}
```

**双路的互补性**：关键词路径擅长精确 CVE 编号、Technique ID 等结构化标识符的命中，但遇到描述性语言或近义词就失效；语义路径擅长跨词汇的意图对齐，但 CVE 编号在 Embedding 空间无特殊位置。两路融合既不漏精确信号，又能捕获语义变体关联。

### 4.2 Note 构建（Algorithm 1）

```
Algorithm 1: Note Construction
输入：规则 r_i，外部知识 A_enriched
输出：记忆笔记 m_i

Step 1: 规则解析
  c_i = r_i
  K_i = 提取 Suricata 规则中的 content、pcre、protocol、
        src/dst ip/port 等所有匹配字段

Step 2: LLM 提取语义字段
  输入：c_i + A_enriched（CVE 描述、ATT&CK 详情）
  输出：
    X_i ← 检测攻击的意图（一句话）
    K_i += 补充隐含攻击关键词（LLM 从漏洞描述中推断）
    T_i ← ATT&CK 战术标签列表

Step 3: 全信息 Embedding
  e_i = Embed(serialize(X_i, K_i, T_i, A_i.cve_desc, c_i))

Step 4: 组装笔记
  m_i = ⟨c_i, X_i, K_i, T_i, e_i, L_i=∅, A_enriched, τ=now()⟩
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

$$\alpha=0.5,\quad \beta=0.3,\quad \gamma=0.2$$

**为何不只用 Embedding 余弦**：全信息 Embedding 是连续隐式表示，无法区分"语义相似但关键词不重叠"（可能不同攻击家族）与"关键词高度重叠"（变体检测的强信号）。$s_\text{prim}$ 和 $s_\text{tactic}$ 是对 Embedding 的**显式结构化补充**，三者融合比单独余弦相似度更精确可靠。

#### 链接类型

| 类型 | 建立条件 | 权重 |
|------|----------|------|
| `exploit_chain` | 共享 CVE ID | 强制 $w=1.0$ |
| `protocol_family` | 协议类型相同 | 固定 $w=0.8$ |
| `tactic_group` | $\|T_i \cap T_j\| \geq 1$ | 动态 $w_{ij}$ |
| `semantic_similar` | $w_{ij} \geq \theta_w=0.60$ | 动态 $w_{ij}$ |
| `subsume` | $K_i \subseteq K_j$ | 固定 $w=0.9$ |

#### 构建算法

```
Algorithm 2: Build Adjacency Graph
参数：θ_sem=0.75（语义初筛），θ_w=0.60（权重保留阈值）

For each pair (m_i, m_j), i < j:

  // 强制链接（无需阈值）
  If A_i.cve ∩ A_j.cve ≠ ∅ → Add_Link(l_chain, w=1.0)
  If protocol(i)==protocol(j)  → Add_Link(l_proto, w=0.8)
  If K_i ⊆ K_j               → Add_Link(l_sub,   w=0.9)

  // 综合权重链接
  If cos(e_i, e_j) >= θ_sem:          // 语义初筛，跳过明显不相关对
    w_ij = 0.5*cos(e_i,e_j)
          + 0.3*|K_i∩K_j|/|K_i∪K_j|
          + 0.2*|T_i∩T_j|/|T_i∪T_j|
    If w_ij >= θ_w:
      Add_Link(l_tactic or l_sim, w_ij)

Build ANNS Index（FAISS / Hnswlib）on {e_i}
```

**实现优化**：全量 $O(N^2)$ 配对可通过协议+战术一级字母分桶降低约 70% 计算量；最终以稀疏邻接矩阵存储，图密度约 3~8%。

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

未匹配流量经 PCAP 解析后，执行与阶段一**完全一致**的 Note 构建流程：

```
未匹配流量 p（PCAP 解析摘要）
       │
       ▼
  双路知识检索（Algorithm 0）
  ├─ 关键词路径：提取 Payload 中的 CVE 编号、函数名、路径
  └─ 语义路径：对流量摘要 Embed → FAISS Top-k 查询 CVE/ATT&CK
       │
       ▼
  LLM 生成 Note（同 Algorithm 1）
  X_p ← 推断的攻击意图
  K_p ← 流量关键词 + LLM 补充
  T_p ← 推断的 ATT&CK 战术
  e_p ← 全信息 Embedding（serialize(X_p, K_p, T_p, A_p, c_p)）
```

**同构设计的价值**：规则 Note 与流量 Note 字段结构完全相同，$\mathbf{e}_i$ 与 $\mathbf{e}_p$ 处于同一语义空间，可直接用 $w_{ij}$ 公式衡量相似度，无需跨模态桥接。

### 5.3 人工介入（可选）

流量 Note 生成后、相似检索前，管理员可修正 $X_p$（LLM 推断的攻击意图）或 $T_p$（战术标签），修正后重新计算 $\mathbf{e}_p$。对首次出现的新型攻击尤为重要——人工标注可显著提升后续检索准确性。

### 5.4 相似检索（Top-k on Adjacency Graph）

对流量 Note $m_p$，在邻接图上执行 Top-k 相似检索：

```
Algorithm 3: Top-k Similarity Search
参数：k=20（ANNS 粗检索），N=5（精排保留）

Step 1: ANNS 粗检索
  candidates = ANNS_Search(e_p, k=20)   // 基于全信息 Embedding

Step 2: 精确重排
  For each m_i in candidates:
    w_pi = 0.5*cos(e_p,e_i)
          + 0.3*|K_p∩K_i|/|K_p∪K_i|
          + 0.2*|T_p∩T_i|/|T_p∪T_i|

Step 3: 一跳邻居扩展
  top5     = Top-5(candidates, by=w_pi)
  expanded = top5 ∪ direct_neighbors(top5)  // 捕获间接关联
  
Return Top-N(expanded, N=5, by=w_pi)
```

**不需要多路召回的原因**：邻接图的 $w_{ij}$ 已将语义、关键词、战术三维信号融合在每条边上；ANNS 基于全信息 Embedding 粗检索，精排阶段再补充精确 Jaccard 校正——无需再单独维护多条独立召回路径。

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
输入：规则 r_new，流量数据库（攻击流量 D_attack + 正常流量 D_benign）

Step 1: 语法检查
  Suricata_Syntax_Check(r_new) → 失败则直接返回错误

Step 2: 流量回放（TPR / FPR 计算）
  TP = 攻击流量中被命中的数量
  FP = 正常流量中被误报的数量
  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)   // TPR
  FPR       = FP / (FP + TN)

Step 3: 联合评分
  F2    = 5×Precision×Recall / (4×Precision + Recall)
  P_fpr = exp(-10 × max(0, FPR - 0.05))
  Score = F2 × P_fpr

Step 4: 决策（θ_pass = 0.70）
  Score >= θ_pass → 通过，进入记忆固化
  Score <  θ_pass → 失败分析 → 重生成（最多3次）
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
    ↓ 沙盒验证（F₂ × P_fpr，TPR/FPR）
    ├─ 通过 → 记忆固化（更新Note+邻接图+级联）→ 相似检索（冗余控制）→ 增修规则
    └─ 不通过 → 失败分析 → 重生成（≤3次）→ 仍失败 → 人工审核
```

---

## 9. 超参数汇总

| 参数 | 符号 | 默认值 | 含义 |
|------|------|--------|------|
| 规则修复阈值 | $\theta_{\text{high}}$ | 0.80 | $w \geq$ 此值触发修复已有规则 |
| 新规则参考阈值 | $\theta_{\text{med}}$ | 0.60 | $w <$ 此值从头生成新规则 |
| 语义初筛阈值 | $\theta_{\text{sem}}$ | 0.75 | 进入精排的最低余弦相似度 |
| 邻接图保留阈值 | $\theta_w$ | 0.60 | 邻接图边权重最低值 |
| 沙盒通过阈值 | $\theta_{\text{pass}}$ | 0.70 | Score ≥ 此值通过沙盒验证 |
| FPR 容差红线 | $\theta_{\text{fpr}}$ | 0.05 | 超过此值开始指数惩罚 |
| ANNS 粗检索数 | $k$ | 20 | 向量检索返回候选数 |
| 精排保留数 | $N$ | 5 | 进入增修的候选规则数 |
| 语义权重 | $\alpha$ | 0.5 | $w_{ij}$ 中 Embedding 余弦系数 |
| 关键词权重 | $\beta$ | 0.3 | $w_{ij}$ 中关键词 Jaccard 系数 |
| 战术权重 | $\gamma$ | 0.2 | $w_{ij}$ 中 ATT&CK 重叠系数 |
| $F_\beta$ 的 $\beta$ | $\beta$ | 2 | 召回率权重是精确率的 4 倍 |
| 规则合并阈值 | $\theta_{\text{merge}}$ | 0.90 | $w >$ 此值提示合并规则 |
