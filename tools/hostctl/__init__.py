"""PS4RF P4/W8 -- host controller (``ps4rfctl``).

The host side of a W8 session: it listens (or connects, in the offline self test), runs the
*frozen* host handshake, accepts exactly one sealed READY attestation, drives the approved
W8 smoke sequence, records evidence and closes the session.

Every protocol primitive comes from the frozen core (``core.rpc``): the host controller has
no wire variant of its own and does not relax a single frozen rule. The one documented W8
addition is the READY frame, which the frozen wire specification reserved for exactly this
case ("shape, encryption status, capability content and state transition fully specified");
see ``docs/P4-W8-LIVE-BRINGUP.md``.
"""

from . import smoke  # noqa: F401
from .session import HostSession, SessionError  # noqa: F401
from .endpoint import SocketEndpoint, connect_localhost, listen  # noqa: F401

__all__ = ['HostSession', 'SessionError', 'SocketEndpoint', 'connect_localhost', 'listen', 'smoke']
