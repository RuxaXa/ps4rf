from pathlib import Path
from core.experiment.compiler import compile_experiment
def test_roundtrip_compile():
    ir=compile_experiment(Path('experiments/mock-roundtrip.yaml').read_text());assert '_canonical_sha256' in ir
