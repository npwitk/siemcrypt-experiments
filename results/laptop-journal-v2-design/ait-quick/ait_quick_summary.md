# AIT-LDSv2 results (Nonprawichs-MacBook-Pro-Max-2.local, macOS-27.2-arm64-arm-64bit-Mach-O)

Development: russellmitchell, santos, fox; test: harrison; first 24 epochs only (quick); alert budget 2 benign alerts per class per day.

## E1-A: real attack chains (pooled over test scenarios)

| System | Class | Incidents | Detected | False entities | AUC | Recall@FP2 |
|---|---|---|---|---|---|---|
| S | recon | 0 | 0 | 1 | n/a | n/a |
| S | web_attack | 0 | 0 | 2 | n/a | n/a |
| S | priv_esc | 0 | 0 | 0 | n/a | n/a |
| S | dns_exfil | 1 | 1 | 1 | 0.949 | 1.000 |
| J2 | recon | 0 | 0 | 2 | n/a | n/a |
| J2 | web_attack | 0 | 0 | 3 | n/a | n/a |
| J2 | priv_esc | 0 | 0 | 2 | n/a | n/a |
| J2 | dns_exfil | 1 | 1 | 1 | 0.939 | 1.000 |
| J2R | recon | 0 | 0 | 1 | n/a | n/a |
| J2R | web_attack | 0 | 0 | 2 | n/a | n/a |
| J2R | priv_esc | 0 | 0 | 0 | n/a | n/a |
| J2R | dns_exfil | 1 | 1 | 1 | 0.949 | 1.000 |

## E1-B: injected low-and-slow attacks on harrison background, recall at the calibrated threshold


dns_exfil, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 0.00 | 0.00 | 1.00 |
| J2 | 1.00 | 0.00 | 0.00 |
| J2R | 0.00 | 0.00 | 1.00 |

recon, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 0.00 | 1.00 | 1.00 |
| J2 | 0.00 | 1.00 | 1.00 |
| J2R | 0.00 | 1.00 | 1.00 |

## E1-B: injected low-and-slow attacks on harrison background, falsely alerted benign entities


dns_exfil, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 0.00 | 0.00 | 0.00 |
| J2 | 0.00 | 0.00 | 0.00 |
| J2R | 0.00 | 0.00 | 0.00 |

recon, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 1.00 | 1.00 | 1.00 |
| J2 | 3.00 | 2.00 | 2.00 |
| J2R | 1.00 | 1.00 | 1.00 |

## E1-B: injected low-and-slow attacks on harrison background, recall@FP2 (threshold-free)


dns_exfil, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 1.00 | 1.00 | 1.00 |
| J2 | 1.00 | 1.00 | 1.00 |
| J2R | 1.00 | 1.00 | 1.00 |

recon, span 6 epochs

| System | r=2 | r=8 | r=32 |
|---|---|---|---|
| S | 0.00 | 1.00 | 1.00 |
| J2 | 0.00 | 1.00 | 1.00 |
| J2R | 0.00 | 1.00 | 1.00 |

Total time 1432s
