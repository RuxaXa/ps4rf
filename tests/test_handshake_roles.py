from core.rpc.handshake import agent_handshake,host_handshake
def test_roles_exist(): assert callable(agent_handshake) and callable(host_handshake)
