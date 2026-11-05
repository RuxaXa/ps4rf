"""W17F: rehearsal tapes -- the recorded console answers the offline end-to-end run replays.

The offline rehearsal (``tools/experiments/rehearsal.py``) drives the *frozen* experiments through
the real RPC path against a host build of the agent whose platform layers are replaced by
``tests/harness/ps4rf_recipe_sim.c``. That object does not pretend to simulate a console: it
replays a **tape** recorded from the experiment layer's own simulated console, so what the agent
reads and what the device answers come from exactly the model the oracle classification was
derived on.

A tape is per scenario and carries

* the simulated kernel base the reads were composed against,
* every bounded read in the order the walk made it (VA + the bytes the console returned),
* every device call in order (command, the argument block with the policy's pointer field masked
  out, the pointer field offset, rc, errno and the response bytes).

The recorder asserts the property that makes the tape meaningful: the pointer field the caller
sends is zero in every recorded request, so the field the device sees in the rehearsal can only
come from the provider.
"""
from __future__ import annotations

import hashlib
import pathlib

from tools.experiments import q6
from tools.experiments.device import IMAGE_LO, SCENARIOS, SimulatedConsole, load_policy

TAPE_VERSION = 1
#: offset of the user pointer field inside the argument block, per command. The authority is the
#: target's generated policy (native/target/ps4rf_ioctl_policy_data.h); tests/test_w17_rpc_rehearsal.py
#: pins the two against each other. W18: the submit family's field is the block's FIRST u64 (the
#: driver reads it as the cpuaddr it pins and maps); 8 was the request size, and tapping it was the
#: deterministic EINVAL of the earlier live runs.
POINTER_FIELD = {0xC0184401: 0, 0xC0184404: 8}
#: the caller-side tokens, in the order the frozen experiment submits them: the first submit
#: presents the A buffer, the second the B buffer (the same order the scenario effect tables use)
SUBMIT_TOKENS = (q6.host_buffers()['A'], q6.host_buffers()['B'])
HOST_BUFFER_LEN = q6.BUFFER_LEN


class RecordingConsole(SimulatedConsole):
    """The experiment layer's simulated console, recording every answer it gives."""

    def __init__(self, scenario: str, host_buffers: dict) -> None:
        super().__init__(scenario, host_buffers)
        self.reads: list[tuple] = []
        self.ioctls: list[tuple] = []

    def read_va(self, va: int, length: int) -> bytes:
        data = super().read_va(va, length)
        self.reads.append((int(va), int(length), bytes(data)))
        return data

    def ioctl(self, device: str, command: int, blob: bytes, mode: int | None = None) -> tuple:
        result = super().ioctl(device, command, blob, mode)
        field = POINTER_FIELD.get(int(command))
        if field is not None:
            present = int.from_bytes(bytes(blob)[field:field + 8], 'little')
            if present != 0:
                raise AssertionError('the recorded request carries a pointer value: '
                                     f'{command:#x} field {present:#x}')
        self.ioctls.append((int(command), bytes(blob), tuple(result)))
        return result


def record(scenario: str, experiment: str) -> tuple:
    """Run one experiment against its simulated console and return (report, recording console)."""
    module = {'q6': q6, 'own1': __import__('tools.experiments.own1', fromlist=['own1'])}[experiment]
    buffers = q6.host_buffers() if hasattr(module, 'host_buffers') else {'A': b'', 'B': b''}
    console = RecordingConsole(scenario, buffers)
    report = module.run(console)
    return report, console


def render(scenario: str, experiment: str, console: RecordingConsole) -> str:
    lines = [f'# PS4RF rehearsal tape v{TAPE_VERSION}',
             f'scenario {scenario}',
             f'experiment {experiment}',
             f'kbase {IMAGE_LO:#x}']
    for va, _length, data in console.reads:
        if not data:
            raise AssertionError(f'empty recorded read at {va:#x}')
        lines.append(f'read {va:#x} {data.hex()}')
    for command, blob, result in console.ioctls:
        rc, errno, out = result
        field = POINTER_FIELD.get(command)
        masked = bytearray(blob)
        if field is not None:
            masked[field:field + 8] = b'\x00' * 8
        where = f'{field}' if field is not None else 'none'
        lines.append(f'ioctl {command:#x} {bytes(masked).hex()} {where} {int(rc)} {int(errno)} '
                     f'{bytes(out).hex() or "-"}')
    return '\n'.join(lines) + '\n'


def write(scenario: str, experiment: str, out_dir: pathlib.Path) -> dict:
    report, console = record(scenario, experiment)
    text = render(scenario, experiment, console)
    path = pathlib.Path(out_dir) / f'rpc-tape-{scenario}.tape'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return {'scenario': scenario, 'experiment': experiment, 'path': str(path),
            'sha256': hashlib.sha256(text.encode()).hexdigest(),
            'reads': len(console.reads), 'ioctls': len(console.ioctls),
            'oracle_classification': report.classification,
            'report': report.as_dict()}


#: the scenario names of each experiment, in fixture order
EXPERIMENT_PREFIX = {'q6': 'q6_', 'own1': 'on1_'}

#: scenarios that validate the reading instrumentation (positive/negative controls, delayed
#: free) rather than pin an oracle verdict; the fixed expectation lives here so the rehearsal
#: still drives them over the full RPC path. tests/test_own1_controls.py pins the behaviour.
CONTROL_EXPECTED = {'on1_ctrl_outside': 'FULL_ROLLBACK', 'on1_delayed': 'STALE_TRANSLATION'}


def scenarios(experiment: str) -> tuple:
    prefix = EXPERIMENT_PREFIX[experiment]
    return tuple(name for name in SCENARIOS if name.startswith(prefix))


def expected_classifications(path=None) -> dict:
    """The oracle expectation per scenario, read from the parity fixture."""
    import json
    fixture = pathlib.Path(path) if path else (
        pathlib.Path(__file__).resolve().parents[2] / 'tests' / 'fixtures' / 'experiments'
        / 'vectors-v1.json')
    doc = json.loads(pathlib.Path(fixture).read_text())
    return {v['scenario']: v['expected_classification'] for v in doc['vectors']}
