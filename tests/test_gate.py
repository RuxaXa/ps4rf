from core.sync.gate import Gate,GateWaitResult,ResourceStateInvalid
def test_gate_manual_release():
    g=Gate(1);g.arrive('A');assert g.status()['released'] is False;assert g.wait(1) is GateWaitResult.TIMEOUT;g.release();assert g.wait(1) is GateWaitResult.RELEASED
def test_duplicate_participant():
    g=Gate(2);g.arrive('A')
    try:g.arrive('A');assert False
    except ResourceStateInvalid:pass
