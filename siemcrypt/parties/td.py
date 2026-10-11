"""Token Directory (TD): (e, T_u^(e)) <-> u mappings (eq:token-mapping) for authorized
identity resolution (eq:identity-resolution). Dummy tokens are never registered."""

from __future__ import annotations


class TokenDirectory:
    def __init__(self) -> None:
        self._map: dict[tuple[int, bytes], str] = {}

    def register(self, epoch: int, token: bytes, user: str) -> None:
        self._map[(epoch, token)] = user

    def resolve(self, epoch: int, token: bytes) -> str | None:
        return self._map.get((epoch, token))
