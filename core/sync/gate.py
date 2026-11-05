from __future__ import annotations
import threading,time
from enum import Enum
class GateWaitResult(str,Enum): RELEASED='RELEASED'; DESTROYED='DESTROYED'; TIMEOUT='TIMEOUT'
class ResourceStateInvalid(Exception):pass
class Gate:
    def __init__(self,expected):self._cond=threading.Condition();self._participants=set();self._expected=expected;self._released=False;self._destroyed=False
    def arrive(self,pid):
        with self._cond:
            if self._destroyed:raise ResourceStateInvalid('destroyed')
            if pid in self._participants:raise ResourceStateInvalid('duplicate participant')
            self._participants.add(pid);self._cond.notify_all();return len(self._participants)
    def status(self):
        with self._cond:return {'arrived_count':len(self._participants),'expected':self._expected,'released':self._released,'destroyed':self._destroyed,'participants':sorted(self._participants)}
    def wait(self,timeout_ms):
        end=time.monotonic()+timeout_ms/1000
        with self._cond:
            while not(self._released or self._destroyed):
                rem=end-time.monotonic()
                if rem<=0:return GateWaitResult.TIMEOUT
                self._cond.wait(rem)
            return GateWaitResult.DESTROYED if self._destroyed else GateWaitResult.RELEASED
    def release(self):
        with self._cond:self._released=True;self._cond.notify_all()
    def destroy(self):
        with self._cond:self._destroyed=True;self._cond.notify_all()
    def destroy_and_confirm(self):self.destroy();return True
class Barrier(Gate):
    def arrive(self,pid):
        n=super().arrive(pid)
        if n>=self._expected:self.release()
        return n
