CAPS={'max_expanded_steps':100000,'max_parallel_tasks':64,'max_nesting_depth':8,'max_runtime_budget_ms':3600000,'max_snapshot_bytes':268435456,'max_rpc_bytes':1073741824}
class BudgetExceeded(ValueError):pass
def _steps(x):return x if isinstance(x,list) else []
def _branches(s):return list((s.get('branches') or {}).values())
def expanded_steps(steps):
    t=0
    for s in steps:
        op=s.get('op')
        if op=='REPEAT_BOUNDED':t+=s['count']*expanded_steps(_steps(s.get('body')))
        elif op=='IF':t+=max(expanded_steps(_steps(s.get('then'))),expanded_steps(_steps(s.get('else'))))
        elif op=='PARALLEL':t+=sum(expanded_steps(_steps(b)) for b in _branches(s))
        else:t+=1
    return t
def peak_tasks(steps):
    p=1
    for s in steps:
        op=s.get('op')
        if op=='PARALLEL':p=max(p,sum(peak_tasks(_steps(b)) for b in _branches(s)))
        elif op=='IF':p=max(p,peak_tasks(_steps(s.get('then'))),peak_tasks(_steps(s.get('else'))))
        elif op=='REPEAT_BOUNDED':p=max(p,peak_tasks(_steps(s.get('body'))))
    return p
def nesting_depth(steps,d=1):
    best=d
    for s in steps:
        subs=_branches(s) if s.get('op')=='PARALLEL' else [_steps(s.get('then')),_steps(s.get('else'))] if s.get('op')=='IF' else [_steps(s.get('body'))] if s.get('op')=='REPEAT_BOUNDED' else []
        for b in subs:best=max(best,nesting_depth(_steps(b),d+1))
    return best
def runtime_bound_ms(steps,default):
    t=0
    for s in steps:
        op=s.get('op')
        if op=='REPEAT_BOUNDED':t+=s['count']*runtime_bound_ms(_steps(s.get('body')),default)
        elif op=='IF':t+=max(runtime_bound_ms(_steps(s.get('then')),default),runtime_bound_ms(_steps(s.get('else')),default))
        elif op=='PARALLEL':t+=max([runtime_bound_ms(_steps(b),default) for b in _branches(s)] or [0])
        elif op=='SLEEP_BOUNDED':t+=s.get('ms',0)
        elif op=='WAIT_BARRIER':t+=s.get('timeout_ms',default)
        else:t+=default
    return t
def snapshot_bytes(steps):
    t=0
    for s in steps:
        op=s.get('op')
        if op=='REPEAT_BOUNDED':t+=s['count']*snapshot_bytes(_steps(s.get('body')))
        elif op=='IF':t+=max(snapshot_bytes(_steps(s.get('then'))),snapshot_bytes(_steps(s.get('else'))))
        elif op=='PARALLEL':t+=sum(snapshot_bytes(_steps(b)) for b in _branches(s))
        elif op=='SNAPSHOT':t+=sum(int(r.get('explicit',{}).get('size',0)) for r in s.get('targets',[]))
    return t
def check_budget(ir):
    c={'max_expanded_steps':expanded_steps(ir.get('steps',[])),'max_parallel_tasks':peak_tasks(ir.get('steps',[])),'max_nesting_depth':nesting_depth(ir.get('steps',[])),'max_runtime_budget_ms':runtime_bound_ms(ir.get('steps',[]),ir.get('timeouts',{}).get('default_step_ms',1000)),'max_snapshot_bytes':snapshot_bytes(ir.get('steps',[]))}
    if c['max_runtime_budget_ms']>ir.get('timeouts',{}).get('global_ms',CAPS['max_runtime_budget_ms']):raise BudgetExceeded('global_ms')
    dec=ir.get('budget',{})
    for k,v in c.items():
        if v>CAPS[k] or (k in dec and v>dec[k]):raise BudgetExceeded(k)
    if dec.get('max_rpc_bytes',CAPS['max_rpc_bytes'])>CAPS['max_rpc_bytes']:raise BudgetExceeded('max_rpc_bytes')
    return c
