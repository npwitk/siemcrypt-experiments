"""Data model: normalized events (eq:event), configuration, correlation contexts
(eq:correlation-context), and attack profiles (eq:attack-profile)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


@dataclass
class Event:
    """L_i = (s_i, u_i, r_i, c_i, x_i, p_i, t_i), eq:event.

    ``label`` is ground truth for evaluation only; no party reads it.
    """

    src: str
    user: str
    res: str
    cat: str
    feats: dict[str, float]
    payload: bytes
    ts: float
    label: str | None = None


class Policy(str, Enum):
    VALUE = "VALUE"
    DECISION = "DECISION"
    HIDE = "HIDE"


@dataclass
class Context:
    """chi_q = (a_q, U_q, R_q, C_q, S_q, Delta_q, J_q, Pi_q, vartheta_q).

    Empty predicate sets mean the dimension is unspecified. Delta_q is the whole epoch
    in this prototype. ``source_weights`` holds eta per plaintext source (eq:multisource-aggregate).
    """

    qid: str
    attack: str
    users: frozenset[str] = frozenset()
    resources: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    feats: tuple[str, ...] = ()
    policy: Policy = Policy.VALUE
    threshold: float = 0.0
    source_weights: dict[str, int] = field(default_factory=dict)


@dataclass
class AttackProfile:
    """P_a = (M_a, F_a, J_a^hist, omega_a). M_a is given as plaintext categories that
    the EE tokenizes per epoch; F_a sums released values per context slot."""

    name: str
    categories: frozenset[str]
    lambda0: float = 0.3
    lambda_min: float = 0.05
    lambda_max: float = 2.0
    alpha: float = 0.5
    beta: float = 0.2
    theta_g: tuple[float, ...] = (0.0, 0.0, 0.0, 0.0, 0.0)  # weights over GRAPH_FEATURES
    theta_y: tuple[float, ...] = ()                       # one weight per context slot
    theta_h: float = 1.0
    theta_r: tuple[float, ...] | None = None  # r(h) = theta_r . h; None: reuse (theta_g, theta_y)
    Theta: float = 1.0
    kappa: float = 1.0


GRAPH_FEATURES = ("weighted_degree", "resource_diversity", "source_diversity", "relations", "temporal_dispersion")


@dataclass
class Config:
    epoch_len: float = 3600.0          # Delta_e (seconds)
    bucket_len: float = 300.0          # temporal bucket width
    gamma: float = 1.0                 # tier parameter; <= 1 disables padding (default: no decoys)
    k_min: int = 3                     # minimum real support for VALUE release
    paillier_bits: int = 2048
    frac_bits: int = 0                 # fixed-point precision (0: integer features)
    agg_features: tuple[str, ...] = ("count",)  # J_AGG
    eps_h: float = 0.05                # evidence-contribution threshold (eq:effective-horizon)
    screening: bool = True             # label-free screening path (Phase 5, Step 6)
    alpha_fp: float = 0.001            # nominal significance level of screening
    cms_eps: float = 0.001
    cms_delta: float = 0.01
    screen_decay: float = 0.5          # lambda-bar of the baseline sketch
    default_lookback: int = 3          # L-bar for unclassified alerts
    precompute_workers: int = 1        # offline randomizer workers; 0 = compute randomizers online
    # variants (DS2): SD gamma=2 (decoys), A3 screening=False, A5 k_min=0
    history: bool = True               # A2 when False: one-epoch window, no trusted history
    persistent_tokens: bool = False    # A4 when True: U/R/C/S token keys do not rotate per epoch
    full_he: bool = False              # B3 when True: no search scoping; every record carries
                                       # Enc(w * x_f * 1[record matches q]) for every context q and
                                       # feature f, and the cloud aggregates over the whole epoch
    # journal version (siemcrypt/laph.py, siemcrypt/lineage.py)
    padding: str = "dummy"             # with gamma > 1: "dummy" single-use dummy tokens (SD);
                                       # "fixed": uniform gamma over real values (FP); "laph": LAPH
    laph_w: tuple[float, float, float] = (0.5, 0.25, 0.25)  # (w_f, w_s, w_h)
    laph_theta: tuple[float, float] = (0.35, 0.65)          # (theta_1, theta_2)
    laph_gamma: tuple[float, float] = (1.5, 2.0)            # (gamma_1, gamma_2)
    laph_hist: int = 6                 # epochs of EE history for L_stab
    laph_scope: str = "bucket"         # real-value padding scope: "bucket" (journal draft) or "epoch" (D26)
    acl: bool = False                  # authenticated EPII + ACL + graph/state lineage
    acl_level: str = "full"            # journal v2 Exp 5: "full" ACL, "retrieval" (EPII proofs and
                                       # candidate set only), "none" (accept cloud results)
    fixed_decay: bool = False          # FixedDecay ablation: lambda = lambda0 (no drift / risk terms)
    contract: bool = True              # NoContract ablation when False: explicit per-epoch history
    # journal v2: AQRS (siemcrypt/aqrs.py) for hunting queries
    aqrs: str = "adaptive"             # "direct" | "fixed" | "adaptive"
    aqrs_k: tuple[int, int, int] = (1, 3, 5)                # cohort size of pi_0, pi_1, pi_2
    aqrs_fixed_k: int = 5              # Fixed-k
    aqrs_theta: tuple[float, float] = (0.3, 0.6)
    aqrs_alpha: tuple[float, float, float] = (0.4, 0.3, 0.3)  # (rep, vol, time)
    aqrs_rmax: int = 4                 # repetitions at which rep saturates
    aqrs_hist: int = 6                 # epochs of query history for the time term
    aqrs_select: str = "nearest"       # cover choice: "nearest" (eq:cover-distance), "random", "near-random"
    aqrs_compat: str = "tier"          # cover pool: same sigma and volume "tier" (journal), or "sigma" (D28)
    aqrs_dynamic: bool = False         # Dynamic-Cover ablation: redraw covers on every issue
    aqrs_sticky: bool = False          # D28: profile/cohort fixed at first issue, from history only
    aqrs_graph: str = "cloud"          # hunting evidence contracted by the "cloud" (journal) or the "ee"
    aqrs_slot: float = 300.0           # dispatch slot of pi_2
    seed: int | None = None
