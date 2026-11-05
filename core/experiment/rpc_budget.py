import threading
from .budget import BudgetExceeded
class RpcByteBudgetExceeded(BudgetExceeded):pass
class RpcByteCounter:
    def __init__(self,max_rpc_bytes,max_frame_bytes):self.max_rpc_bytes=max_rpc_bytes;self.max_frame_bytes=max_frame_bytes;self.used=0;self._lock=threading.Lock()
    def charge(self,pt,direction=''):
        if len(pt)>self.max_frame_bytes:raise RpcByteBudgetExceeded('frame')
        with self._lock:
            self.used+=len(pt)
            if self.used>self.max_rpc_bytes:raise RpcByteBudgetExceeded('rpc')
        return self.used
