#!/usr/bin/env python3
"""PS4RF P4/W6 differential harness CLI.

    python -m tools.differential.cli diff profiles  <before.json> <after.json>
    python -m tools.differential.cli diff artifacts <before> <after>
    python -m tools.differential.cli diff operations <before.json> <after.json>
    python -m tools.differential.cli report <run.json> [--md]

Deterministic JSON on stdout (or ``--out``); ``--md`` adds a human-readable report.
``--timestamp`` pins the run timestamp for byte-identical output; ``--expect-before`` /
``--expect-after`` bind an input to a declared hash (mismatch = fail closed).

Exit codes: 0 = run produced (differences or not), 1 = refused (fail-closed), 2 = usage.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential import candidates as CG  # noqa: E402
from tools.differential import compare as CP  # noqa: E402
from tools.differential import schema as SC  # noqa: E402
from tools.differential.normalize import (  # noqa: E402
    DEFAULT_CONFIG, NormalizationError, canonical_dump,
)

USAGE = (__doc__ or '').strip()


def _default_timestamp() -> str:
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch and epoch.isdigit():
        import datetime  # noqa: PLC0415

        return datetime.datetime.fromtimestamp(int(epoch), datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    import datetime  # noqa: PLC0415

    return datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def render_markdown(report: dict) -> str:
    lines = [f'# Differential report {report["run_id"]}', '']
    lines.append(f'* command: `diff {report["command"]}`')
    lines.append(f'* timestamp: {report["timestamp"]}')
    lines.append(f'* tool: {report["tool"]["name"]} {report["tool"]["version"]}')
    lines.append(f'* normalization: {report["normalization_version"]}')
    lines.append(f'* config sha256: `{report["config_sha256"][:16]}…`')
    lines.append(f'* output sha256: `{report["output_sha256"]}`')
    lines.append('')
    lines.append('## Inputs')
    for item in report['inputs']:
        state = 'missing' if item.get('missing') else (item['sha256'] or '')[:16] + '…'
        lines.append(f'* {item["role"]}: `{item["path"]}` ({item["kind"]}, {state})')
    lines.append('')
    lines.append(f'## Findings ({len(report["findings"])})')
    if not report['findings']:
        lines.append('* none — inputs are equal under the current normalization')
    for finding in report['findings']:
        subject = finding['subject']
        lines.append(f'* **{finding["id"]} {finding["class"]}** ({finding["confidence"]}) '
                     f'[{finding["layer"]}] {subject}')
        lines.append(f'  * before: `{json.dumps(finding["before"], sort_keys=True)}`')
        lines.append(f'  * after: `{json.dumps(finding["after"], sort_keys=True)}`')
    lines.append('')
    lines.append(f'## Candidates ({len(report["candidates"])})')
    if not report['candidates']:
        lines.append('* none')
    for candidate in report['candidates']:
        lines.append(f'* {candidate["id"]} {candidate["kind"]} '
                     f'({candidate["status"]}, {candidate["confidence"]}): {candidate["subject"]}')
        lines.append(f'  * requires: {" → ".join(candidate["requires"])}')
        lines.append(f'  * W4 impact: {candidate["impact"]["w4"]}')
    lines.append('')
    lines.append('## Summary')
    for name, value in sorted(report['summary']['counts'].items()):
        lines.append(f'* {name}: {value}')
    for note in report['summary']['notes']:
        lines.append(f'* note: {note}')
    lines.append('')
    lines.append('A difference is not a verdict: findings carry a class and a confidence, '
                 'candidates stay OBSERVATION, and nothing here authorizes anything (W4).')
    return '\n'.join(lines) + '\n'


def _parse_kv(pairs: list[str]) -> dict:
    out = {}
    for pair in pairs:
        key, _, value = pair.partition('=')
        out[key.strip()] = value.strip()
    return out


def main(argv: list[str]) -> int:
    if '--self-test' in argv:
        failures = CP._self_test() + CG._self_test()
        if failures:
            print(f'cli self-test: {len(failures)} FAILED')
            return 1
        print('cli self-test: OK')
        return 0
    if len(argv) < 2 or argv[0] not in ('diff', 'report'):
        print(USAGE)
        return 2

    if argv[0] == 'report':
        path = pathlib.Path(argv[1])
        try:
            report = json.loads(path.read_text(encoding='utf-8'))
        except Exception as exc:  # noqa: BLE001
            print(f'REPORT REFUSED: {path}: {exc}')
            return 1
        errors = SC.validate_report(report)
        if errors:
            print(f'REPORT REFUSED ({len(errors)})')
            for err in errors:
                print(f'  - {err}')
            return 1
        print(render_markdown(report) if '--md' in argv else canonical_dump(report), end='')
        return 0

    kind = argv[1]
    if kind not in ('profiles', 'artifacts', 'operations') or len(argv) < 4:
        print(USAGE)
        return 2
    before, after = argv[2], argv[3]
    flags = argv[4:]
    expect = _parse_kv([v for v in flags if v.startswith('--expect-')])
    expect_hashes = {'before': expect.get('--expect-before', ''), 'after': expect.get('--expect-after', '')}
    expects = {k: v for k, v in expect_hashes.items() if v}
    external = None
    ext_a = ext_b = None
    for index, flag in enumerate(flags):
        nxt = flags[index + 1] if index + 1 < len(flags) else None
        if flag == '--external-before' and nxt:
            ext_a = json.loads(pathlib.Path(nxt).read_text(encoding='utf-8'))
        if flag == '--external-after' and nxt:
            ext_b = json.loads(pathlib.Path(nxt).read_text(encoding='utf-8'))
    if ext_a is not None or ext_b is not None:
        if ext_a is None or ext_b is None:
            print('REFUSED: an external analysis input requires both sides (fail closed)')
            return 1
        external = (ext_a, ext_b)

    timestamp = _default_timestamp()
    for index, flag in enumerate(flags):
        if flag == '--timestamp' and index + 1 < len(flags):
            timestamp = flags[index + 1]

    config = DEFAULT_CONFIG
    if '--strip-common-root' in flags:
        from tools.differential.normalize import RunConfig  # noqa: PLC0415

        config = RunConfig(layers=DEFAULT_CONFIG.layers, strip_common_root=True,
                           confidence_cap=DEFAULT_CONFIG.confidence_cap)
    try:
        report = CP.run_diff(kind, before, after, config=config, timestamp=timestamp,
                             expect_hashes=expects, external=external)
        report = CP.attach_candidates(report, CG.generate(report['findings'], report['inputs']))
    except (NormalizationError, CP.DifferentialRunError) as exc:
        print(f'REFUSED (fail closed): {exc}')
        return 1

    text = canonical_dump(report)
    out_path = None
    for index, flag in enumerate(flags):
        if flag == '--out' and index + 1 < len(flags):
            out_path = pathlib.Path(flags[index + 1])
    if out_path is not None:
        out_path.write_text(text, encoding='utf-8')
        print(f'run {report["run_id"]}: findings={len(report["findings"])} '
              f'candidates={len(report["candidates"])} -> {out_path}')
        print(f'output_sha256 {report["output_sha256"]}')
    else:
        sys.stdout.write(text)
    if '--md' in flags:
        md_path = (out_path.with_suffix('.md') if out_path is not None
                   else pathlib.Path(f'{report["run_id"]}.md'))
        md_path.write_text(render_markdown(report), encoding='utf-8')
        print(f'markdown report: {md_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
