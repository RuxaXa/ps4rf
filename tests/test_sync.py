from mock.agent import MockAgent
def test_sync_cleanup_removes_registry():
    a=MockAgent();r=a.create_gate(1);assert r in a._gates;a.resources.release(r);assert r not in a._gates
