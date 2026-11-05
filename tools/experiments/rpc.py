"""W17F: the experiment target that speaks the real RPC path.

The frozen experiments (``q6.py``, ``own1.py``) are written against
:class:`tools.experiments.device.Target`. This module implements the same surface over a live
``HostSession``, so every call the experiment makes becomes exactly one request to the agent:

    experiment -> host RPC -> ps4rfd -> provider -> response -> classifier

Nothing is called directly: no provider, no classifier, no recipe walk, no device. What the
requests carry is the frozen request surface -- a recipe name, an optional bounded index list, an
allowlisted command, the argument block, an optional mode word and the caller's write payload
(content the caller presents; the caller never names an address, and no address is ever sent).

The write payload matters for the device family: the payload's driver copies from a user pointer
into its shared window, so the bytes the caller presents are what distinguish one submit from the
next. That content is a property of the call environment (the experiment's own tokens), so it is
supplied here by the caller of this class -- never by the agent.
"""
from __future__ import annotations

from tools.experiments import contracts as C
from tools.experiments.device import Cell, Snapshot, Target, load_policy, load_recipe

#: commands whose argument block carries the user pointer the driver copies from
POINTER_COMMANDS = (0xC0184401, 0xC0184404)

# mirrors native/target/gen_recipe.py INDEX_NAMES (the frozen positional contract)
INDEX_ENUM = {"idx_bitmap_word": 1, "idx_ptslot": 2}


class RpcError(RuntimeError):
    """The agent answered the request with an error status."""


def index_order(recipe_id: str) -> tuple:
    """The declared index sources of a recipe, in the order the fixture lists them.

    The request carries the index values positionally, so the order is the recipe's own declared
    order -- not a convention of this module.
    """
    order: list[str] = []
    for entry in load_recipe(recipe_id)["entries"]:
        src = entry.get("index_source")
        if src and src not in order:
            order.append(src)
    return tuple(order)


class RpcTarget(Target):
    """A :class:`Target` that reaches the console through the agent's RPC surface."""

    def __init__(self, session, policy=None, *, submit_payloads=(), kbase: int = 0,
                 max_payload: int = 0x10000) -> None:
        super().__init__(policy or load_policy())
        self.session = session
        self.submit_payloads = [bytes(p) for p in submit_payloads]
        self.kbase = int(kbase)
        self.max_payload = int(max_payload)
        self.submit_index = 0
        #: the exact requests and responses, for the evidence file
        self.exchanges: list[dict] = []

    # -- plumbing ------------------------------------------------------------------------------
    def _call(self, op: str, arguments: dict) -> dict:
        C.assert_no_raw_address(arguments)
        response = self.session.request(op, arguments)
        status = response.get('status')
        self.exchanges.append({'request': {'operation': op, 'arguments': arguments},
                               'response': response})
        if status != 'OK':
            error = response.get('error') or {}
            raise RpcError(f'{op} answered {status}: {error.get("code")} {error.get("detail")}')
        return response.get('result') or {}

    # -- Target surface -----------------------------------------------------------------------
    def run_recipe(self, recipe_id: str, indices: dict | None = None,
                   kbase: int | None = None, indices_full: bool = False) -> Snapshot:
        arguments: dict = {'recipe_ref': recipe_id}
        if indices:
            order = index_order(recipe_id)
            if indices_full:
                # positional contract: index_source N reads indices[N-1]. Recipes whose only
                # source is a later slot need the EARLIER slots padded (left), so the named
                # value lands exactly at its enum position (e.g. idx_ptslot -> position 1).
                args_list = [int(indices.get(name, 0)) for name in order]
                srcs = sorted(int(INDEX_ENUM[n]) for n in order)
                need = max(srcs) if srcs else 0
                arguments['indices'] = [0] * (need - len(args_list)) + args_list
            else:
                arguments['indices'] = [int(indices[name]) for name in order if name in indices]
        result = self._call('kernel.snapshot.recipe', arguments)
        cells: dict[str, Cell] = {}
        attach = 0
        for raw in result.get('cells') or []:
            cell = Cell(name=raw.get('name', ''),
                        status=int(raw.get('status', 0)),
                        why=raw.get('why_name') or 'NONE',
                        length=int(raw.get('length', 0)),
                        addr=int(raw.get('addr', 0)),
                        root_value=int(raw.get('root_value', 0)),
                        data=bytes.fromhex(raw.get('data') or ''))
            cells[cell.name] = cell
            if int(raw.get('attach') or 0):
                attach = 1
        return Snapshot(cells=cells, attach=attach)

    def ioctl(self, device: str, command: int, blob: bytes, mode: int | None = None) -> tuple:
        payload = self._next_payload(command)
        arguments: dict = {'command': int(command), 'blob': bytes(blob).hex()}
        if mode is not None:
            arguments['mode'] = int(mode)
        if payload:
            arguments['data'] = payload.hex()
        result = self._call('ioctl.invoke', arguments)
        return (int(result.get('rc', 0)), int(result.get('errno', 0)),
                bytes.fromhex(result.get('output') or ''))

    def _next_payload(self, command: int) -> bytes:
        """The bytes the caller presents in its own transfer buffer for this submit.

        Only a command that copies from a user pointer needs content; the read-only status command
        does not, and a payload for it would be refused by the target. The k-th submit presents the
        k-th payload the caller handed over (the experiment's own A/B tokens), which is exactly the
        caller-side change the device family is being asked about.
        """
        if command not in POINTER_COMMANDS or self.policy.command(command).out_len != 0:
            return b''
        if not self.submit_payloads:
            return b''
        index = min(self.submit_index, len(self.submit_payloads) - 1)
        self.submit_index += 1
        payload = self.submit_payloads[index][:self.max_payload]
        return payload
