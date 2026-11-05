import time
from core.rpc.pool import BoundedPool
def test_submit_after_poison_no_token_leak():
    p=BoundedPool(1,2);p.poison('x');assert p.submit('REQ-'+'0'*32,'memory.alloc',lambda r,o:None)=='POISONED';assert p.available_tokens==2;p.shutdown(wait_running=True)
def test_cancel_callback():
    seen=[];p=BoundedPool(1,2,on_canceled=lambda r,o:seen.append(r));p.submit('REQ-'+'1'*32,'x',lambda r,o:time.sleep(.2));p.submit('REQ-'+'2'*32,'x',lambda r,o:None);p.poison('x');time.sleep(.3);p.shutdown(wait_running=True);assert 'REQ-'+'2'*32 in seen
