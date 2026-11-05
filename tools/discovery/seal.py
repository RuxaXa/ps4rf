"""Make "the blind run never read the labels" a mechanism instead of a promise.

Python's audit hooks fire on every ``open``/``os.listdir``/``os.scandir``, so a sealed run
can refuse to touch the directories that hold the answer key while it is running.  The
guard is deliberately blunt: it covers the corpus, the held-back cases and the negative
priors, and it raises instead of logging, because a blind run that read the answer key and
merely mentioned it is still a contaminated run.

The hook cannot be removed once installed (that is a CPython property, not a design
choice), so a sealed run must be the last thing a process does with the pipeline.  That is
stated here so nobody tries to seal, score and then continue training in one interpreter.
"""
from __future__ import annotations

import pathlib
import sys
from typing import Iterable, List, Optional, Sequence

#: Directories a blind run must never read.  Relative to the data root.
DEFAULT_SEALED = ("corpus", "blind", "negative")

_READ_EVENTS = ("open", "os.listdir", "os.scandir", "os.stat")


class SealViolation(RuntimeError):
    """A sealed path was read while the seal was active."""


def _normalise(roots: Iterable[pathlib.Path]) -> List[str]:
    return [str(pathlib.Path(root).resolve()) for root in roots]


def _matches(path_text: str, sealed: Sequence[str]) -> bool:
    try:
        resolved = str(pathlib.Path(path_text).resolve())
    except (OSError, ValueError):
        return False
    return any(resolved == root or resolved.startswith(root + "/") for root in sealed)


def seal(roots: Iterable[pathlib.Path], *, events: Optional[Sequence[str]] = None,
         recorder: Optional[List[str]] = None) -> List[str]:
    """Install an audit hook that refuses reads under ``roots``.

    Returns the normalised roots so a caller can report exactly what was sealed.  When
    ``recorder`` is given, every allowed read path is appended, which lets a test show
    what the run did touch.
    """
    sealed = _normalise(roots)
    monitored = tuple(events) if events is not None else _READ_EVENTS

    def _hook(event: str, args) -> None:
        if event not in monitored or not args:
            return
        target = args[0]
        if isinstance(target, bytes):
            try:
                target = target.decode()
            except UnicodeDecodeError:
                return
        if not isinstance(target, str):
            try:
                target = str(target)
            except Exception:
                return
        if _matches(target, sealed):
            raise SealViolation(
                f"a sealed path was read during a blind run: {target}\n"
                f"sealed roots: {', '.join(sealed)}")
        if recorder is not None and event == "open" and target.startswith("/"):
            recorder.append(target)

    sys.addaudithook(_hook)
    return sealed


def is_sealed(path: pathlib.Path, sealed: Sequence[str]) -> bool:
    """Was this path inside one of the normalised roots?"""
    return _matches(str(path), sealed)


class SealNotRemovable(RuntimeError):
    """Documented failure mode: an audit hook cannot be uninstalled."""


def unseal() -> None:
    raise SealNotRemovable(
        "audit hooks cannot be removed; run the sealed part last, in its own process")
