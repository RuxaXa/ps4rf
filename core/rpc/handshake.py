from __future__ import annotations
import hashlib,hmac,json,os
from dataclasses import dataclass
from enum import Enum
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305,AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from core.canonical import canonical_bytes
HANDSHAKE_LABEL='ps4rf-handshake-v1'; MAX_HANDSHAKE_BYTES=65536; TAG_LEN=16; LAST_SEQ=2**64-2
# W0/D8 (Core/Wire Revision R1): the AAD carries `sequence` as a JCS JSON integer, so the
# effective usable ceiling is the safe-number limit -- not the 8-byte header space. Enforced
# in seal()/open(); reaching it closes the session (SequenceExhausted), never wraps around.
EFFECTIVE_LAST_SEQ=2**53-1
class ProtocolError(Exception):pass
class ReplayDetected(ProtocolError):pass
class SequenceExhausted(ProtocolError):pass
class FrameLimitExceeded(ProtocolError):pass
class AuthenticationFailed(ProtocolError):pass

def open_authenticated(aead,nonce,ct,aad):
    """W0/D9 (R1): the ONE place AEAD failures are mapped to a PS4RF protocol exception.

    Mock and native must behave identically here: no library-specific exception
    (cryptography's ``InvalidTag``) may escape the RPC layer.
    """
    try:
        return aead.decrypt(nonce,ct,aad)
    except InvalidTag:
        raise AuthenticationFailed('frame authentication failed') from None
class Direction(str,Enum): AGENT_TO_HOST='agent-to-host'; HOST_TO_AGENT='host-to-agent'
@dataclass(frozen=True)
class HandshakeKeys: k_hs:bytes; k_agent_to_host:bytes; k_host_to_agent:bytes
def new_nonce():return os.urandom(16)
def _hkdf(secret,salt,info,n=32):return HKDF(algorithm=hashes.SHA256(),length=n,salt=salt,info=info).derive(secret)
def transcript_hash(agent_hello,host_ack): return hashlib.sha256(canonical_bytes(agent_hello)+canonical_bytes(host_ack)).digest()
def derive_keys(secret,an,hn,th):
    if len(secret)!=32 or len(an)!=16 or len(hn)!=16:raise ProtocolError('bad key/nonce length')
    salt=an+hn
    return HandshakeKeys(_hkdf(secret,salt,b'ps4rf/handshake/v1'+th),_hkdf(secret,salt,b'ps4rf/aead/agent-to-host/v1'+th),_hkdf(secret,salt,b'ps4rf/aead/host-to-agent/v1'+th))
def proof(k,role,th):return hmac.new(k,f'ps4rf/proof/{role}/v1'.encode()+th,hashlib.sha256).digest()
def nonce_prefix(secret,an,hn,th,direction):return _hkdf(secret,an+hn,f'ps4rf/nonce-prefix/{direction}/v1'.encode()+th,4)
def build_aad(pv,sid,seq,direction,mtype):return canonical_bytes({'protocol_version':pv,'session_id':sid,'sequence':seq,'direction':str(direction),'message_type':mtype})
class DirectionChannel:
    def __init__(self,key,prefix,session_id,direction,suite='AEAD_CHACHA20_POLY1305',max_frame_bytes=1048576,protocol_version=1):
        if len(key)!=32 or len(prefix)!=4:raise ProtocolError('bad channel parameters')
        if suite=='AEAD_CHACHA20_POLY1305':self._aead=ChaCha20Poly1305(key)
        elif suite=='AES_256_GCM':self._aead=AESGCM(key)
        else:raise ProtocolError('unknown AEAD suite')
        self._prefix=prefix;self._sid=session_id;self._dir=direction;self._max=max_frame_bytes;self._pv=protocol_version;self._send=0;self._recv=0
    def _nonce(self,seq):return self._prefix+seq.to_bytes(8,'big')
    def _aad(self,seq,t):return build_aad(self._pv,self._sid,seq,self._dir,t)
    def seal(self,t,pt):
        if len(pt)+TAG_LEN>self._max:raise FrameLimitExceeded()
        if self._send>EFFECTIVE_LAST_SEQ:raise SequenceExhausted()
        seq=self._send;ct=self._aead.encrypt(self._nonce(seq),pt,self._aad(seq,t));self._send+=1;return seq,ct
    def open(self,t,seq,ct):
        if self._recv>EFFECTIVE_LAST_SEQ:raise SequenceExhausted()
        if seq!=self._recv:raise ReplayDetected()
        if len(ct)>self._max:raise FrameLimitExceeded()
        pt=open_authenticated(self._aead,self._nonce(seq),ct,self._aad(seq,t));self._recv+=1;return pt

def _send_hs(ep,obj):
    d=canonical_bytes(obj)
    if len(d)>MAX_HANDSHAKE_BYTES:raise ProtocolError('handshake too large')
    ep.send_all(len(d).to_bytes(4,'big')+d)
def _recv_hs(ep):
    n=int.from_bytes(ep.recv_exact(4),'big')
    if n>MAX_HANDSHAKE_BYTES:raise ProtocolError('handshake too large')
    return json.loads(ep.recv_exact(n))
def agent_handshake(ep,secret,agent_hello):
    _send_hs(ep,agent_hello);ack=_recv_hs(ep);th=transcript_hash(agent_hello,ack);keys=derive_keys(secret,bytes.fromhex(agent_hello['nonce']),bytes.fromhex(ack['nonce']),th);_send_hs(ep,{'msg':'AUTH','mac':proof(keys.k_hs,'agent',th).hex()});aa=_recv_hs(ep)
    if aa.get('mac')!=proof(keys.k_hs,'host',th).hex():raise ProtocolError('host proof')
    return keys,ack
def host_handshake(ep,secret,host_hello_ack):
    hello=_recv_hs(ep);_send_hs(ep,host_hello_ack);th=transcript_hash(hello,host_hello_ack);keys=derive_keys(secret,bytes.fromhex(hello['nonce']),bytes.fromhex(host_hello_ack['nonce']),th);auth=_recv_hs(ep)
    if auth.get('mac')!=proof(keys.k_hs,'agent',th).hex():raise ProtocolError('agent proof')
    _send_hs(ep,{'msg':'AUTH_ACK','mac':proof(keys.k_hs,'host',th).hex()});return keys,hello
