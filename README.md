# MA-MemIDS

基于你的 `MA_MemIDS.md` 落地的可运行工程版，核心实现了：

- 阶段一初始化：规则 -> 显式特征清单整理 -> `reference:*` 可信证据解析（结构化 ID + URL best-effort 网页解析/缓存；init 会批量有界并发预抓取）-> 检索规划（Planner 产 `sparse_query` / `dense_query`，并标记 `selected_features` / `discarded_features`）-> 混合知识检索（Sparse BM25 + Dense + RRF，并对 reference 中的可信 CVE / ATT&CK ID 做 exact pin）-> Note 构建 -> 邻接图
- 阶段二在线：流量 -> 现有规则预检（若已命中则提前结束）-> 显式特征清单整理 -> 检索规划（Planner 产 `sparse_query` / `dense_query`，并标记 `selected_features` / `discarded_features`）-> 混合知识检索 -> 流量 Note -> Note 相似性 Top-k -> 规则增修 -> 沙盒验证 -> 失败分析 -> 回到检索规划
- 沙盒评分：`Score = F2 * P_fpr`，并采用“全规则集前后对比”准入（仅 `Score_new > Score_base` 通过）
- 记忆固化与演化：写回、级联、冗余检查

---

## 1. 快速开始

```bash
cd /mnt/8T/xgr/zhuyijia/MA_MemIDS
pip install -r requirements.txt

# `hnswlib` 对图谱候选召回仍是可选加速依赖；只有设置 `MA_MEMIDS_ENABLE_HNSW=1` 时图谱层才会启用
# 知识检索层若检测到 `hnswlib` 可用，会在预构建阶段自动为知识库生成 HNSW 缓存，否则回退为精确 Dense 扫描
# embedding 默认使用 `sentence-transformers/all-MiniLM-L6-v2`，首次运行会自动下载模型

# 查看状态
python main.py stats

# 阶段一：从基础规则初始化
python main.py init --rules /path/to/base.rules

# 阶段一：从规则目录初始化（可限制数量）
python main.py init --rules /mnt/8T/xgr/zhuyijia/MA_MemIDS/rules --max-rules 200

# 阶段二：处理未匹配流量
python main.py process --pcap /path/to/sample.pcap --attack-pcaps /path/to/sample.pcap

# 导出规则
python main.py export --output ./output/rules.rules
```

---

## 2. 代码结构（每个文件做什么）

```text
MA_MemIDS/
├── main.py                      # CLI 入口：init/process/export/stats
├── self_check.py                # 一键自检：模块/API/验证器/流程烟测
├── MA_MemIDS.md                 # 你的方案文档（理论设计主来源）
├── requirements.txt             # 依赖
├── scripts/
│   ├── run_xss_from_gridai.sh   # 直接跑 GRIDAI 的 xss_sample.pcap
│   ├── generate_sandbox_pcaps.py# 生成沙盒验证用 benign/attack pcap
│   └── build_knowledge_index.py # 预构建知识检索缓存（Sparse/Dense）
├── demo/                        # 项目演示网页（交互式）
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── ma_memids/
    ├── __init__.py              # 包导出
    ├── config.py                # 超参数、阈值、运行默认配置
    ├── models.py                # 数据结构：Note/Link/ValidationResult/ProcessResult...
    ├── utils.py                 # 通用函数：tokenize/jaccard/cosine/time
    ├── embedding.py             # 全信息 embedding（Sentence-Transformers / all-MiniLM-L6-v2）
    ├── knowledge.py             # 混合知识检索：BM25(FTS5)+Dense+RRF，含 ATT&CK/CVE 预处理与缓存
    ├── prompts.py               # 所有 prompt 模板集中管理
    ├── llm_client.py            # API 客户端工厂（OpenAI/DeepSeek/GLM）
    ├── rule_parser.py           # Suricata 规则字段解析（sid/rev/protocol/content...）
    ├── reference_resolver.py    # 解析规则中的 reference:*，网页抓取/缓存/结构化摘要
    ├── pcap_parser.py           # PCAP -> 结构化文本摘要（流式采样、限包、限 payload、跳过二进制下载 body）
    ├── note_builder.py          # 规则Note/流量Note同构构建 + 重嵌入
    ├── graph.py                 # 邻接图构建、统一相似度、ANN候选召回、Top-k检索、冗余合并候选
    ├── validation.py            # Suricata语法/回放验证 + F2*P_fpr + 失败诊断
    ├── rule_engine.py           # 修复/参考生成/从头生成 + 失败重生成
    └── pipeline.py              # 总编排：初始化、在线处理、固化、导出、统计
```

---

## 3. Prompt 在哪里？谁在调用？

Prompt 全在：

- `ma_memids/prompts.py`

当前包含这些模板：

- `RETRIEVAL_PLANNER_SYSTEM`
- `RETRIEVAL_PLANNER_USER`
- `REFERENCE_PARSE_SYSTEM`
- `REFERENCE_PARSE_USER`
- `NOTE_EXTRACTION_SYSTEM`
- `NOTE_EXTRACTION_USER`
- `RULE_REPAIR_SYSTEM`
- `RULE_REPAIR_USER`
- `RULE_GENERATE_SYSTEM`
- `RULE_GENERATE_USER`
- `FAILURE_ANALYSIS_USER`

调用关系：

- `note_builder.py` 调用 `REFERENCE_PARSE_*`（仅规则初始化侧：当规则里有 `reference:url,...` 时，对网页做独立结构化解析，并把结果压成可信证据）
- `note_builder.py` 调用 `RETRIEVAL_PLANNER_*`（先基于显式 `feature_inventory` + `reference_evidence` 生成 `sparse_query` / `dense_query`，并标记 `selected_features` / `discarded_features`）
- `note_builder.py` 调用 `NOTE_EXTRACTION_*`（用于从规则/流量文本提取 `intent/keywords/tactics`）
- `rule_engine.py` 调用 `RULE_REPAIR_*`、`RULE_GENERATE_*`、`FAILURE_ANALYSIS_USER`（用于增修规则与失败重试）

你后续改 prompt 时，只需要改 `ma_memids/prompts.py`，其余模块无需改动。

---

## 4. 主流程入口说明

### 4.1 CLI 入口

- `main.py init`
  - 输入规则文件或目录，构建规则 Note 和邻接图（支持 `--max-rules`）
- `main.py process`
  - 输入 `--pcap` 或 `--traffic-text`，执行阶段二在线流程
- `main.py export`
  - 导出当前规则库
- `main.py stats`
  - 查看当前 Note 数、规则数、模型名、阈值

### 4.2 核心编排

主编排在 `ma_memids/pipeline.py`：

- 初始化组件：retriever/embedder/LLM/graph/validator
- 初始化规则：规则解析 -> 显式特征清单整理 -> `reference:*` 可信证据解析（结构化 ID 直接吸收；URL 页面抓取失败则自动降级；init 内会先批量并发预抓取 reference）-> 检索规划 -> 混合检索（reference 给出的可信 CVE / ATT&CK ID 会被 exact pin 到检索结果前列）-> 规则 Note
- 处理流量：PCAP 解析（流式采样、限包、限 payload、对大文件下载/二进制 body 自动跳过）-> 现有规则集预检（已触发则不再生成新规则）-> 显式特征清单整理 -> 检索规划（Sparse 用关键词查询，Dense 用语义查询，并记录 `selected_features` / `discarded_features`）-> 混合检索（Sparse BM25 + Dense + RRF）-> 流量 Note -> Note 相似性 Top-k -> 规则提案
- 沙盒循环：先计算当前全规则集基线分数，再对“修改后全规则集”回放验证；仅当 `Score_new > Score_base` 才通过并固化（基线指标会缓存并在通过后更新）-> 失败分析（语法报错 / 召回不足 / FPR 过高）-> 回到“显式特征清单整理 + 检索规划 + 混合检索”重建 Note 与提案（最多 `max 3` 次）
- 通过后固化：更新图、写回 state、检查合并候选

---

## 5. 环境与配置

### 5.1 .env

项目根目录的 `.env` 用于 API 密钥：

- `LLM_MODEL`（例如 `deepseek-chat`）
- `DEEPSEEK_API_KEY`
- `OPENAI_API_KEY`
- `ZHIPU_API_KEY`
- `MA_MEMIDS_DEFAULT_RULES_PATH`（demo 未上传规则时的默认规则文件/目录）
- `MA_MEMIDS_DEFAULT_ATTACK_SANDBOX_DIR`（demo 未上传攻击样本时的默认目录）
- `MA_MEMIDS_DEFAULT_BENIGN_SANDBOX_DIR`（demo 未上传正常样本时的默认目录）
- `MA_MEMIDS_SCORE_IMPROVE_EPSILON`（全规则集对比的最小提升容差，默认 `1e-6`）
- `MA_MEMIDS_PCAP_MAX_PACKETS` / `MA_MEMIDS_PCAP_MAX_PAYLOAD_BYTES`（PCAP 解析的限包与 payload 预览上限）

也支持通过命令行覆盖模型：

```bash
python main.py --model gpt-4.1 stats
```

### 5.2 知识库（可选）

你可以传本地知识库：

```bash
python main.py \
  --cve-kb ./knowledge/cves \
  --attack-kb ./knowledge/cti-ATT-CK-v18.1 \
  --cti-kb ./knowledge/cti.jsonl \
  init --rules /path/to/base.rules
```

支持以下输入：

- `--attack-kb`：MITRE ATT&CK STIX 文件或目录（例如 `enterprise/mobile/ics` bundle 目录）
- `--cve-kb`：CVE Project 官方 JSON 文件或目录（例如 `cves/` 根目录）
- `--cti-kb`：通用 `json/jsonl` 扁平知识库

运行时会自动做源数据预处理，并在 `memory/knowledge_cache` 下缓存：

- 标准化文档
- Sparse 索引：SQLite FTS5 / BM25
- Dense 向量缓存：`all-MiniLM-L6-v2`
- 候选融合：RRF，`k=60`

查询侧不会直接把整段原始规则/流量全文送进 Dense 检索。当前实现会先整理显式 `feature_inventory`，再由 Retrieval Planner 生成：

- `sparse_query`
- `dense_query`
- `selected_features`
- `discarded_features`

ATT&CK 和 CVE 虽然原始格式不同，但进入检索层后共用同一套 `Sparse + Dense + RRF` 搜索逻辑。
若规则本身包含 `reference:*`：

- `reference:cve,...`、显式 `Txxxx` 等结构化线索会直接进入可信证据集合
- `reference:url,...` 会先进入独立 `Reference Resolver`，抓取网页并抽取 `trusted_cve_ids / trusted_tech_ids / trusted_terms / reference_summary`
- `ReferenceParse LLM` 只在“文本页且 heuristic 未直接抽到 `CVE / ATT&CK ID`，并且页面长度达到阈值”时才触发，避免普通网页一律进 LLM
- 初始化时会先对全部规则的 `reference:*` 做一轮有界并发预抓取，再按原顺序串行构建 Note；默认并发度为 `4`
- 若 `reference:url,...` 没写协议头，系统会自动补全，优先尝试 `https://`，必要时回退 `http://`
- 页面抓取失败、403/404、超时、内容过大或解析异常时，不会中断 init；系统会回退到结构化 reference + 当前 Hybrid Retrieval 主流程
- 网页解析缓存默认存放在 `memory/reference_cache`，并会自动清理：默认保留 14 天、最多 2000 个文件、总大小最多 256MB
- 如需调整，可设置 `MA_MEMIDS_REFERENCE_CACHE_MAX_AGE_DAYS`、`MA_MEMIDS_REFERENCE_CACHE_MAX_FILES`、`MA_MEMIDS_REFERENCE_CACHE_MAX_SIZE_BYTES`、`MA_MEMIDS_REFERENCE_MAX_WORKERS`、`MA_MEMIDS_REFERENCE_LLM_MIN_TEXT_CHARS`
- 对 reference 给出的可信 CVE / ATT&CK ID，检索层会在 CVE / ATT&CK 索引中做 exact pin，避免普通双路检索把高可信人工参考覆盖掉

下载地址：
ATT&CK：https://github.com/mitre/cti/releases
CVE：https://github.com/CVEProject/cvelistV5/releases

也可以提前手动预构建缓存：

```bash
python scripts/build_knowledge_index.py \
  --attack-kb ./knowledge/cti-ATT-CK-v18.1 \
  --cve-kb ./knowledge/cves
```

### 5.3 Embedding 模型

当前默认 embedding 模型是 `sentence-transformers/all-MiniLM-L6-v2`，输出维度为 `384`。若仓库内存在 `./huggingface_models/all-MiniLM-L6-v2`，代码会优先直接从该本地目录加载；也可以通过 `MA_MEMIDS_EMBEDDING_MODEL_DIR` 指定本地模型目录。如无本地目录，才回退到 Hugging Face 名称加载。知识检索层会离线缓存 Dense 向量；若环境中可用 `hnswlib`，还会自动为知识库构建 HNSW 索引，否则回退为精确 Dense 扫描。

---

## 6. 自检（强烈建议先跑）

```bash
# 完整自检（含真实 API 调用）
python self_check.py

# 仅本地模块检查（跳过 API）
python self_check.py --skip-api

# 指定 pcap
python self_check.py --pcap /path/to/sample.pcap
```

自检覆盖：环境变量、网络连通、模块导入、检索/图、PCAP解析、验证器、pipeline 烟测、API 调用。

---

## 7. 直接跑 GRIDAI 的 XSS 样本

```bash
# 一键运行
bash scripts/run_xss_from_gridai.sh

# 等价手动运行
python main.py process \
  --pcap /mnt/8T/xgr/zhuyijia/GRIDAI/samples/xss_sample.pcap \
  --attack-pcaps /mnt/8T/xgr/zhuyijia/GRIDAI/samples/xss_sample.pcap
python main.py export --output ./output/rules.rules
```

---

## 8. 生成沙盒验证流量（正常 + 攻击）

```bash
python scripts/generate_sandbox_pcaps.py
```

输出目录：

- `sandbox_samples/benign/*.pcap`
- `sandbox_samples/attack/*.pcap`
- `sandbox_samples/manifest.json`

可直接把这些 pcap 上传到 demo 的 `attack_pcap / benign_pcap` 做沙盒验证。

---

## 9. Demo 网页（交互式）

### 9.1 启动方式

```bash
cd /mnt/8T/xgr/zhuyijia/MA_MemIDS
pip install -r requirements.txt
python demo_server.py
# 浏览器访问 http://127.0.0.1:8090/
```

### 9.2 支持能力

- `Init`：上传初始规则文件（可选）；若不上传，默认使用 `/mnt/8T/xgr/zhuyijia/MA_MemIDS/rules`
- `Init`：支持 `max_rules` 限制初始化规模（避免一次跑完整社区规则导致耗时/成本过高）
- `Process`：上传主分析流量 `pcap`（未知标签）或直接粘贴 `traffic_text`
- `Process`：区分“主分析流量”与“沙盒攻击/正常样本集”，其中沙盒样本支持多文件
- `Process`：若未上传沙盒样本，默认自动读取 `sandbox_samples/attack` 和 `sandbox_samples/benign`（攻击集默认目录为空时再回退主分析流量）
- `Process`：主分析 `pcap` 会先用“当前全量规则集”做一次预检；若已触发告警（确认命中）则直接返回 `mode=already_covered`，不再走 LLM 增修流程
- `Process`：会先通过 LLM 对主分析 `pcap` 做攻击/正常判别，并将其并入对应沙盒集合；并入时按文件哈希去重，同文件可覆盖迁移到正确集合
- 异步任务模式：不再卡在 `Running...`，会实时显示进度事件
- 展示每一步 trace（PCAP 解析、Note、Top-k、提案、验证、诊断、重生成）
- 展示 LLM 调用明细（messages + response + latency）
- 结果区支持折叠（`details`）查看长输出
- 支持 Note 图谱管理：摘要/分页预览/单条详情/清空（自动备份 `state.json`）

### 9.3 后端接口

- `GET /api/status`：当前状态与统计
- `POST /api/init`：上传规则或使用默认规则路径并执行初始化
- `POST /api/process`：上传流量并执行在线流程
- `POST /api/init_async`：异步初始化（返回 `job_id`）
- `POST /api/process_async`：异步在线处理（返回 `job_id`）
- `GET /api/job/<job_id>`：轮询任务状态、事件和最终结果
- `GET /api/graph/summary`：图谱摘要（notes/links/最近 notes）
- `GET /api/graph/notes`：分页查看 notes（支持 `note_type/q/limit/offset`）
- `GET /api/graph/note/<note_id>`：单条 note 详情
- `POST /api/graph/clear`：清空图谱（`confirm=CLEAR`，会备份 state）

后端实现文件：

- `demo_server.py`
