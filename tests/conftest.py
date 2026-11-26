import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture(scope="session")
def mapper():
    from analyzer.core.compliance_loader import ComplianceMapper
    return ComplianceMapper(ROOT / "tests" / "fixtures" / "compliance_map.test.yaml", profile="bfsi")


@pytest.fixture(scope="session")
def demo(tmp_path_factory):
    import create_demo_target
    out = tmp_path_factory.mktemp("demo"); create_demo_target.build(out); return out
