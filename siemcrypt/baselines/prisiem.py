"""B5: PriSIEM, privacy-preserving managed SIEM with SGX enclaves and TFHE
(Coppolino, D'Antonio, Mazzeo, Romano, Sgaglione, JNCA 203, 2022).

PriSIEM evaluates SIEM rules as TFHE Boolean circuits over 16-bit operands; every gate is a
TFHE gate bootstrapping, so a rule's cost is its gate count times the gate time. The
paper's Table 4 (elementary operators) and Table 5 (compound operators over a tuple set T)
give the gate counts reproduced below. Intel SGX is not available on the evaluation VM;
the enclave work (encryption at the customer, decryption of filtered tuples) is cheap
next to the circuits and is not counted, which favours PriSIEM.

A SIEMCrypt correlation context (count, per entity and epoch, the events that satisfy a
predicate, then compare with a threshold) maps to PriSIEM's Filter on the predicate field,
T-Count (count in a time window) per tuple, and one Gt per entity and epoch. Grouping by
entity is not charged (it would need Eq or Join per pair), so the estimate is a lower bound.
"""

from __future__ import annotations

# Table 4: elementary operators on 16-bit inputs -> number of gates
ELEMENTARY = {"Sum": 40, "Sub": 56, "Mul": 128, "Div": 144, "Eq": 23, "Gt": 48, "Gte": 54}
# Table 5: compound operators, gates per tuple of T
COMPOUND = {"MaxMin": 32, "Mean": 184, "WMean": 234, "Count": 196, "TCount": 295, "Filter": 256,
            "Join": 312, "Strcmp": 191}
# Section 7.2.2, Rule-1 (Filter + Count): reported throughput in tuples/s with 1, 4, 8 threads
REPORTED_RULE1_TPS = {1: 1.0, 4: 2.0, 8: 4.0}


def gates_per_event(contexts: int) -> int:
    """Gates per ingested event when every event is evaluated by every context."""
    return contexts * (COMPOUND["Filter"] + COMPOUND["TCount"])


def gates_per_entity_epoch(contexts: int) -> int:
    return contexts * ELEMENTARY["Gt"]


def cost(events: int, entities: int, epochs: int, contexts: int, t_gate_us: float) -> dict:
    """Predicted gates and seconds for a stream (t_gate_us: one bootstrapped gate)."""
    gates = events * gates_per_event(contexts) + entities * epochs * gates_per_entity_epoch(contexts)
    seconds = gates * t_gate_us / 1e6
    return dict(gates=gates, seconds=seconds, events_per_s=events / seconds if seconds else None,
                gates_per_event=gates / events if events else None)
