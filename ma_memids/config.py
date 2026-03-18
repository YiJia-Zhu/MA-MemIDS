from dataclasses import dataclass


@dataclass(frozen=True)
class SimilarityWeights:
    alpha: float = 0.5
    beta: float = 0.1
    gamma: float = 0.2
    delta: float = 0.15
    epsilon: float = 0.05


@dataclass(frozen=True)
class Thresholds:
    high: float = 0.68
    med: float = 0.40
    sem: float = 0.0
    w: float = 0.40
    merge: float = 0.78
    pass_score: float = 0.70
    fpr_redline: float = 0.05
    ann_k: int = 24
    rerank_n: int = 5
    max_regen: int = 3
    graph_candidate_k: int = 24
    merge_candidate_k: int = 32
    keyword_bucket_cap: int = 64
    hnsw_m: int = 16
    hnsw_ef_construction: int = 120
    hnsw_ef_search: int = 64


@dataclass(frozen=True)
class RuntimeConfig:
    sid_start: int = 1_200_000
    embedding_dim: int = 256
    knowledge_top_k: int = 5
