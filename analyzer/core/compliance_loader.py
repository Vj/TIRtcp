from pathlib import Path
from typing import List
import yaml
from analyzer.core.schema import ComplianceRef, ComplianceRelation


class ComplianceMapper:
    def __init__(self, map_path: Path, profile: str = "general") -> None:
        self.profile = profile.lower()
        data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
        self.last_verified: str = data["metadata"]["last_verified"]
        self.checks: dict = data.get("checks", {})

    def resolve(self, check_id: str) -> List[ComplianceRef]:
        entry = self.checks.get(check_id, {})
        refs: List[ComplianceRef] = []
        for m in entry.get("mappings", []):
            item_scope = m.get("scope", "general").lower()
            # Include 'general' always; include 'bfsi' only when profile == 'bfsi'
            if item_scope == "general" or item_scope == self.profile:
                refs.append(
                    ComplianceRef(
                        framework=m["framework"],
                        version=str(m["version"]),
                        control_id=m["control_id"],
                        control_title=m["control_title"],
                        relation=ComplianceRelation(m["relation"]),
                        scope=item_scope,
                    )
                )
        return refs