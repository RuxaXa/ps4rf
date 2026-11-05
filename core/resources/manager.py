from __future__ import annotations
import os,threading
from dataclasses import dataclass,field
from enum import Enum
class ResourceStateInvalid(Exception):pass
class CleanupResult(str,Enum): FREED='FREED'; FAILED='CLEANUP_FAILED'; UNCERTAIN='UNCERTAIN'
@dataclass
class ManagedResource:
    ref:str;kind:str;recoverable:bool=True;out_of_band_cleanup_safe:bool=False;force_cleanup_failure:bool=False;cleanup:object=None;cleanup_attempted:bool=False;cleanup_result:CleanupResult|None=None
    def do_cleanup(self):
        self.cleanup_attempted=True
        if self.force_cleanup_failure:return CleanupResult.FAILED
        if self.cleanup is None:return CleanupResult.FREED
        try:return CleanupResult.FREED if self.cleanup() else CleanupResult.FAILED
        except Exception:return CleanupResult.FAILED
@dataclass
class CleanupReport: state:str;resources:list=field(default_factory=list);console_dirty:bool=False
class ResourceManager:
    def __init__(self):self._lock=threading.RLock();self._held={};self._leaked={}
    def acquire(self,kind,*,recoverable=True,force_cleanup_failure=False,out_of_band_safe=False):
        with self._lock:
            ref=f'{kind}:{os.urandom(8).hex().upper()}';self._held[ref]=ManagedResource(ref,kind,recoverable,out_of_band_safe,force_cleanup_failure);return ref
    def attach_cleanup(self,ref,callback):
        with self._lock:
            if ref not in self._held:raise ResourceStateInvalid(ref)
            self._held[ref].cleanup=callback
    def release(self,ref):
        with self._lock:
            r=self._held.get(ref)
            if not r:return False
            res=r.do_cleanup();r.cleanup_result=res
            if res is CleanupResult.FREED:del self._held[ref];return True
            self._leaked[ref]=self._held.pop(ref);return False
    def cleanup_all(self):
        with self._lock:
            for ref in list(self._held):self.release(ref)
            return self._report()
    def cleanup_after_hang(self):
        with self._lock:
            for ref,r in list(self._held.items()):
                if r.out_of_band_cleanup_safe:
                    res=r.do_cleanup();r.cleanup_result=res
                    if res is CleanupResult.FREED:del self._held[ref]
                    else:self._leaked[ref]=self._held.pop(ref)
                else:
                    r.cleanup_attempted=False;r.cleanup_result=CleanupResult.UNCERTAIN;self._leaked[ref]=self._held.pop(ref)
            return self._report()
    def _report(self):
        resources=[{'ref':r.ref,'kind':r.kind,'cleanup_attempted':r.cleanup_attempted,'cleanup_result':r.cleanup_result.value if r.cleanup_result else 'NOT_ATTEMPTED','recoverable':r.recoverable,'out_of_band_safe':r.out_of_band_cleanup_safe} for r in self._leaked.values()]
        return CleanupReport('PARTIAL' if resources else 'COMPLETE',resources,bool(resources))
