# E1 results (synthetic data, development laptop)

Seeds [1, 2]; target benign FPR 0.005 per (entity, epoch) on development streams.

## Part A: per-class detection (mean ± sd over seeds)

| System | Class | Precision | Recall | F1 | Delay (epochs) |
|---|---|---|---|---|---|
| S | cred_access | 0.583 ± 0.118 | 0.500 ± 0.000 | 0.536 ± 0.051 | 0.000 ± 0.000 |
| S | exfil | 0.417 ± 0.118 | 1.000 ± 0.000 | 0.583 ± 0.118 | 0.000 ± 0.000 |
| S | multi_source | 0.310 ± 0.034 | 1.000 ± 0.000 | 0.472 ± 0.039 | 0.000 ± 0.000 |
| B2 | cred_access | 0.667 ± 0.000 | 0.500 ± 0.000 | 0.571 ± 0.000 | 0.000 ± 0.000 |
| B2 | exfil | 0.417 ± 0.118 | 1.000 ± 0.000 | 0.583 ± 0.118 | 0.000 ± 0.000 |
| B2 | multi_source | 0.667 ± 0.000 | 1.000 ± 0.000 | 0.800 ± 0.000 | 0.000 ± 0.000 |
| A1 | cred_access | 0.667 ± 0.000 | 0.500 ± 0.000 | 0.571 ± 0.000 | 0.000 ± 0.000 |
| A1 | exfil | 0.417 ± 0.118 | 1.000 ± 0.000 | 0.583 ± 0.118 | 0.000 ± 0.000 |
| A1 | multi_source | 0.667 ± 0.000 | 1.000 ± 0.000 | 0.800 ± 0.000 | 0.000 ± 0.000 |
| A2 | cred_access | 0.667 ± 0.000 | 0.500 ± 0.000 | 0.571 ± 0.000 | 0.000 ± 0.000 |
| A2 | exfil | 0.417 ± 0.118 | 1.000 ± 0.000 | 0.583 ± 0.118 | 0.000 ± 0.000 |
| A2 | multi_source | 0.500 ± 0.000 | 0.500 ± 0.000 | 0.500 ± 0.000 | 0.000 ± 0.000 |
| A3 | cred_access | 0.583 ± 0.118 | 0.500 ± 0.000 | 0.536 ± 0.051 | 0.000 ± 0.000 |
| A3 | exfil | 0.417 ± 0.118 | 1.000 ± 0.000 | 0.583 ± 0.118 | 0.000 ± 0.000 |
| A3 | multi_source | 0.310 ± 0.034 | 1.000 ± 0.000 | 0.472 ± 0.039 | 0.000 ± 0.000 |
| B1-default | cred_access | 1.000 ± 0.000 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.000 ± 0.000 |
| B1-default | exfil | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | n/a |
| B1-default | multi_source | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | n/a |
| B1-tuned | cred_access | 0.800 ± 0.000 | 1.000 ± 0.000 | 0.889 ± 0.000 | 1.375 ± 0.177 |
| B1-tuned | exfil | 1.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 |
| B1-tuned | multi_source | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | n/a |

| System | Macro F1 |
|---|---|
| S | 0.530 ± 0.009 |
| B2 | 0.652 ± 0.039 |
| A1 | 0.652 ± 0.039 |
| A2 | 0.552 ± 0.039 |
| A3 | 0.530 ± 0.009 |
| B1-default | 0.222 ± 0.000 |
| B1-tuned | 0.630 ± 0.000 |

## McNemar (exact) of S vs. each system on identical incidents, Holm-adjusted

| System | S only | system only | p | p (Holm) |
|---|---|---|---|---|
| A1 | 0 | 0 | 1 | 1 |
| A2 | 2 | 0 | 0.5 | 1 |
| A3 | 0 | 0 | 1 | 1 |
| B1-default | 6 | 0 | 0.0312 | 0.188 |
| B1-tuned | 4 | 4 | 1 | 1 |
| B2 | 0 | 0 | 1 | 1 |

## Screening path (S has screening; A3 does not)

| System | Unclassified alerts / run | Entities / run | Attacker entities / run | Incidents hit by screening | Found only by screening |
|---|---|---|---|---|---|
| S | 25.0 | 16.0 | 2.5 | 5/14 | 0 |
| A3 | 0.0 | 0.0 | 0.0 | 0/14 | 0 |

## Part B: low-and-slow recall (mean over seeds) by rate r per epoch


Span 6 epochs

| System | r=2 | r=8 | r=16 |
|---|---|---|---|
| S | 0.00 | 1.00 | 1.00 |
| B2 | 0.00 | 1.00 | 1.00 |
| A2 | 0.00 | 1.00 | 1.00 |
| B1-default | 0.00 | 0.00 | 0.00 |
| B1-tuned | 0.00 | 1.00 | 1.00 |

Total time 56s
