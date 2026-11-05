import collections,re,threading
class RequestIdRegistry:
    RE=re.compile(r'^REQ-[0-9a-f]{32}$')
    def __init__(self,completed_cache_size=4096): self._lock=threading.Lock(); self._pending=set(); self._completed=collections.OrderedDict(); self._n=completed_cache_size
    def register(self,rid):
        with self._lock:
            if not self.RE.fullmatch(rid): raise ValueError('bad request id')
            if rid in self._pending or rid in self._completed: raise ValueError('duplicate request id')
            self._pending.add(rid)
    def complete(self,rid):
        with self._lock:
            self._pending.discard(rid); self._completed[rid]=None
            while len(self._completed)>self._n:self._completed.popitem(last=False)
    def respond_once(self,rid):
        with self._lock:
            if rid not in self._pending:return False
            self._pending.remove(rid); self._completed[rid]=None; return True
    def pending_count(self):
        with self._lock:return len(self._pending)
