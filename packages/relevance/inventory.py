from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InventoryMatch:
    matched: bool
    matched_assets: tuple[str, ...]
    score: float


class DemoInventoryAdapter:
    def __init__(self, assets: tuple[str, ...]) -> None:
        self.assets = assets
        self._normalized = {self._normalize(item): item for item in assets}

    def match(self, affected_names: tuple[str, ...]) -> InventoryMatch:
        matched = tuple(
            sorted(
                {
                    self._normalized[self._normalize(name)]
                    for name in affected_names
                    if self._normalize(name) in self._normalized
                }
            )
        )
        return InventoryMatch(bool(matched), matched, 6.0 if matched else 0.0)

    @staticmethod
    def _normalize(value: str) -> str:
        return " ".join(value.strip().lower().split())
