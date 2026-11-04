# Journal v2 Experiment 4: temporal ablations, dormancy, versioned profiles (synthetic)

Seeds [1, 2, 3, 4, 5]. cred_access (low-and-slow), 28 epochs, 4 failed logins per active epoch.

## Part A: epoch gap g between 5 active epochs, recall@FP2

| System | g=0 | g=1 | g=2 | g=3 | g=4 |
|---|---|---|---|---|---|
| S | 0.93 | 0.93 | 0.80 | 0.80 | 0.87 |
| NoGraph | 0.20 | 0.00 | 0.00 | 0.00 | 0.00 |
| FixedWindow | 1.00 | 0.93 | 0.73 | 0.73 | 0.87 |
| FixedDecay | 0.93 | 0.93 | 0.80 | 0.80 | 0.87 |
| NoHist | 0.87 | 0.80 | 0.87 | 0.87 | 0.93 |

## Part B: two bursts of 3 epochs, D dormant epochs between, recall@FP2

| System | D=2 | D=4 | D=8 |
|---|---|---|---|
| S | 1.00 | 1.00 | 1.00 |
| NoGraph | 0.07 | 0.00 | 0.00 |
| FixedWindow | 1.00 | 1.00 | 1.00 |
| FixedDecay | 1.00 | 1.00 | 0.93 |
| NoHist | 0.80 | 0.93 | 0.80 |

## Part A: epoch gap g between 5 active epochs, AUC

| System | g=0 | g=1 | g=2 | g=3 | g=4 |
|---|---|---|---|---|---|
| S | 0.92 | 0.92 | 0.91 | 0.91 | 0.91 |
| NoGraph | 0.71 | 0.61 | 0.57 | 0.49 | 0.41 |
| FixedWindow | 0.94 | 0.93 | 0.91 | 0.91 | 0.91 |
| FixedDecay | 0.92 | 0.92 | 0.91 | 0.91 | 0.91 |
| NoHist | 0.95 | 0.95 | 0.95 | 0.95 | 0.95 |

## Part B: two bursts of 3 epochs, D dormant epochs between, AUC

| System | D=2 | D=4 | D=8 |
|---|---|---|---|
| S | 0.93 | 0.92 | 0.92 |
| NoGraph | 0.67 | 0.65 | 0.58 |
| FixedWindow | 0.93 | 0.93 | 0.93 |
| FixedDecay | 0.93 | 0.92 | 0.92 |
| NoHist | 0.95 | 0.95 | 0.95 |

## Part C: profile redeployed as version 2 at epoch 8 (Theta x 0.8)

| System | cred_access alerts after change | mixed-lineage alerts | alerts with pre-change provenance | benign entities alerted | attackers detected | attackers active | lineages retired |
|---|---|---|---|---|---|---|---|
| S | 14.200 ± 2.950 | 0.000 ± 0.000 | 0.000 ± 0.000 | 1.400 ± 0.548 | 3.000 ± 1.000 | 4.000 ± 0.000 | 35.200 ± 2.588 |
| NoProfileBind | 19.200 ± 3.962 | 19.200 ± 3.962 | 18.800 ± 3.564 | 1.400 ± 0.548 | 3.800 ± 0.447 | 4.000 ± 0.000 | 0.000 ± 0.000 |

## Part D: state dynamics of S (Part A streams)

| g | attacker rho | attacker ell | attacker prov | benign rho | benign ell | benign prov | C_empty per epoch |
|---|---|---|---|---|---|---|---|
| 0 | 0.710 ± 0.013 | 9.552 ± 0.412 | 9.336 ± 0.429 | 0.708 ± 0.005 | 9.403 ± 0.190 | 9.047 ± 0.088 | 103.443 ± 5.507 |
| 1 | 0.704 ± 0.015 | 9.404 ± 0.504 | 9.689 ± 0.738 | 0.706 ± 0.013 | 9.351 ± 0.424 | 8.926 ± 0.203 | 103.707 ± 5.659 |
| 2 | 0.700 ± 0.016 | 9.202 ± 0.521 | 8.966 ± 0.881 | 0.703 ± 0.009 | 9.231 ± 0.255 | 8.870 ± 0.323 | 103.136 ± 5.129 |
| 3 | 0.701 ± 0.020 | 9.186 ± 0.647 | 8.141 ± 0.602 | 0.702 ± 0.014 | 9.193 ± 0.459 | 8.980 ± 0.309 | 103.386 ± 4.553 |
| 4 | 0.702 ± 0.017 | 9.225 ± 0.538 | 7.373 ± 0.599 | 0.707 ± 0.008 | 9.381 ± 0.229 | 9.059 ± 0.241 | 104.743 ± 5.397 |

Total time 647s
