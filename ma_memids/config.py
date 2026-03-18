from dataclasses import dataclass


@dataclass(frozen=True)
class SimilarityWeights:
    alpha: float = 0.5
    beta: float = 0.3
    gamma: float = 0.2


@dataclass(frozen=True)
class Thresholds:
    high: float = 0.80
    med: float = 0.60
    sem: float = 0.75
    w: float = 0.60
    merge: float = 0.90
    pass_score: float = 0.70
    fpr_redline: float = 0.05
    ann_k: int = 20
    rerank_n: int = 5
    max_regen: int = 3


@dataclass(frozen=True)
class RuntimeConfig:
    sid_start: int = 1_200_000
    embedding_dim: int = 256
    knowledge_top_k: int = 5
