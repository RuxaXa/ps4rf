from core.experiment.rpc_budget import RpcByteCounter,RpcByteBudgetExceeded
def test_rpc_budget():
    c=RpcByteCounter(5,10);c.charge(b'abc')
    try:c.charge(b'abc');assert False
    except RpcByteBudgetExceeded:pass
