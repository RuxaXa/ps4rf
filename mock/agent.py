from __future__ import annotations
import threading
from core.rpc.hang import MockHangReleased
from core.rpc.pool import BoundedPool
from core.rpc.requests import RequestIdRegistry
from core.resources.manager import ResourceManager
from core.sync.gate import Gate,Barrier
class MockAgent:
    AGENT_CAP=8
    def __init__(self):
        self._transport_dead=False;self._send_lock=threading.Lock();self._agent_lock=threading.RLock();self._reqs=RequestIdRegistry();self.resources=ResourceManager();self._gates={};self._barriers={};self._evidence=[];self.hang_event=threading.Event();self._pool=None
    def _respond_now(self,rid,op,resp):
        # In the full socket mock this writes an authenticated RESPONSE frame.
        return None
    def _on_canceled(self,rid,op):
        try:
            if not self._transport_dead:self._respond_now(rid,op,{'status':'ERROR','error':{'code':'SESSION_RECOVERY_REQUIRED'}})
        finally:self._reqs.complete(rid)
    def _on_worker_crash(self,rid,op,exc_name):self._evidence.append({'request_id':rid,'operation':op,'result':'WORKER_CRASH','exception':exc_name})
    def configure_pool(self,workers=4,max_inflight=8):self._pool=BoundedPool(workers,max_inflight,self._on_canceled,self._on_worker_crash)
    def _make_sync_cleanup(self,ref,registry,obj):
        def cleanup():
            with self._agent_lock: registry.pop(ref,None);obj.destroy();return True
        return cleanup
    def create_gate(self,parties):
        gate=Gate(parties);ref=self.resources.acquire('gate');self.resources.attach_cleanup(ref,self._make_sync_cleanup(ref,self._gates,gate))
        with self._agent_lock:self._gates[ref]=gate
        return ref
    def create_barrier(self,parties):
        obj=Barrier(parties);ref=self.resources.acquire('barrier');self.resources.attach_cleanup(ref,self._make_sync_cleanup(ref,self._barriers,obj))
        with self._agent_lock:self._barriers[ref]=obj
        return ref
