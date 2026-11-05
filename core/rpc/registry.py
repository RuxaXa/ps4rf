from dataclasses import dataclass
@dataclass(frozen=True)
class OperationSpec:
    name:str; requires_capability:str|None=None; mutating:bool=True; recovery_safe:bool=False
class OperationRegistry:
    def __init__(self): self._specs={}
    def register(self,s): self._specs[s.name]=s
    def has(self,n): return n in self._specs
    def spec(self,n):
        if n not in self._specs: raise KeyError(n)
        return self._specs[n]
def default_registry():
    r=OperationRegistry()
    for n,c in [('memory.alloc','memory.alloc'),('memory.free','memory.free'),('gpuvm.map','gpuvm.map'),('gpuvm.unmap','gpuvm.unmap'),('gpuvm.lookup','gpuvm.lookup'),('keymgr.claim','keymgr.claim'),('keymgr.release','keymgr.release'),('keymgr.snapshot','keymgr.snapshot'),('ccp.submit','ccp.submit'),('kernel.snapshot','kernel.read'),('kernel.read','kernel.read'),('kernel.snapshot.recipe','kernel.read'),('kernel.dump.full','kernel.dump.full'),('ioctl.invoke','ioctl.invoke')]: r.register(OperationSpec(n,c))
    for n in ('session.ping','session.status','telemetry.read'): r.register(OperationSpec(n,None,False,True))
    # W14 §15 (wire catalogue revision R4): the authenticated admin shutdown. Read-only (it changes
    # no target state -- it releases the session's resources and ends the agent's lifetime) and
    # recovery-safe by policy: a boot in recovery is exactly where a controller needs it.
    # It carries *no* capability on purpose: capability-bearing operations are the privileged ones
    # and are never wired on the target agent (a frozen invariant this wave does not weaken). Its
    # wire contract instead requires one argument, `capability`, whose only admitted value is
    # "session.admin" -- the caller's declaration, checked by the provider.
    r.register(OperationSpec('session.shutdown',None,False,True))
    for n in ('sync.barrier.create','sync.barrier.wait','sync.barrier.release','sync.barrier.destroy','sync.gate.create','sync.gate.arrive','sync.gate.wait','sync.gate.status','sync.gate.release','sync.gate.destroy','experiment.load','mock.hang','mock.block','mock.leak','mock.free_fail'): r.register(OperationSpec(n))
    for n in ('verify.userland.exec','verify.kernel.read','verify.kernel.exec','verify.kernel.copyout','verify.samu.access'): r.register(OperationSpec(n,None,False,False))
    return r
