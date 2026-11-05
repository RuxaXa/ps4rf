"""Orchestrate one sealed blind run.

The pieces exist separately — ``seal`` refuses the answer directories, ``predict`` turns a
queue into scorable claims, ``blindscore`` scores them — and this module is the single
place that puts them in the right order for a run that may be quoted.

Order matters and is not cosmetic: the seal goes in **first**, so any later stage that
tries to read the corpus fails loudly; the run is finished before the process does
anything else, because an audit hook cannot be taken back out.
"""
from __future__ import annotations

import json
import pathlib
from typing import List, Optional, Sequence

from . import predict as predict_mod
from . import seal as seal_mod


def sealed_roots(data_root: pathlib.Path,
                 subdirs: Sequence[str] = seal_mod.DEFAULT_SEALED) -> List[pathlib.Path]:
    """The answer directories that exist under ``data_root`` (missing ones are skipped)."""
    root = pathlib.Path(data_root)
    return [root / name for name in subdirs if (root / name).exists()]


def blind_run(queue_document: dict, *, data_root: pathlib.Path,
              seal_first: bool = True,
              subdirs: Sequence[str] = seal_mod.DEFAULT_SEALED) -> dict:
    """Seal, predict, and return a bundle that says what was sealed.

    ``seal_first=False`` exists for tests that need to observe an unsealed run; a
    production caller has no reason to use it and the bundle records which mode ran.
    """
    roots = sealed_roots(data_root, subdirs)
    sealed = seal_mod.seal(roots) if seal_first else []
    bundle = predict_mod.from_queue(queue_document)
    bundle["run"] = {
        "sealed": seal_first,
        "sealed_roots": sealed,
        "sealed_absent": [name for name in subdirs if not (pathlib.Path(data_root) / name).exists()],
    }
    return bundle


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="sealed blind run: queue -> predictions")
    ap.add_argument("--queue", required=True)
    ap.add_argument("--data-root", default=None,
                    help="the discovery data root whose answer directories get sealed")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    data_root = pathlib.Path(args.data_root) if args.data_root else (
        pathlib.Path(__file__).resolve().parent / "data")
    document = json.loads(pathlib.Path(args.queue).read_text(encoding="utf-8"))
    bundle = blind_run(document, data_root=data_root)
    text = json.dumps(bundle, indent=2, sort_keys=True)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
