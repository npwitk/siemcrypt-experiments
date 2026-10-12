"""Re-implementations of published schemes compared with SIEMCrypt (DS2, Table "Systems").

Each scheme is reimplemented from its paper behind the common interface of the DS2
evaluation (ingest, search, verify); equation numbers in comments refer to the paper.
Blockchains are modelled by an append-only, trusted store, and smart contracts by local
function calls, so measured costs cover the cryptographic and indexing work only.

  evseb   B7  Fugkeaw et al., EVSEB, IEEE Access 13 (2025)
  mktree  B8  Saengthong et al., MK-Tree, IEEE OJ-CS 7 (2026)
  prisiem B5  Coppolino et al., PriSIEM, JNCA 203 (2022): TFHE gate-count cost model
"""
