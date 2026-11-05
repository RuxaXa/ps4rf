from core.rpc.handshake import *
def test_oversized_does_not_consume_sequence():
    k=b'x'*32;p=b'abcd';a=DirectionChannel(k,p,'SES-'+'1'*16,Direction.AGENT_TO_HOST,max_frame_bytes=64);b=DirectionChannel(k,p,'SES-'+'1'*16,Direction.AGENT_TO_HOST,max_frame_bytes=64)
    try:a.seal('REQUEST',b'x'*49);assert False
    except FrameLimitExceeded:pass
    seq,ct=a.seal('REQUEST',b'ok');assert seq==0;assert b.open('REQUEST',seq,ct)==b'ok'
