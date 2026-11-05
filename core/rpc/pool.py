from __future__ import annotations
import queue, threading
from enum import Enum
class TaskState(str,Enum): QUEUED='QUEUED'; RUNNING='RUNNING'; COMPLETED='COMPLETED'; CANCELED_AT_RECOVERY='CANCELED_AT_RECOVERY'
class BoundedPool:
    SENTINEL=object()
    def __init__(self,size,max_inflight,on_canceled=None,on_worker_crash=None):
        self._queue=queue.Queue(); self._lock=threading.Lock(); self._tokens=threading.BoundedSemaphore(max_inflight); self._max_inflight=max_inflight; self._tasks={}; self._poisoned=False; self._on_canceled=on_canceled; self._on_worker_crash=on_worker_crash
        self._threads=[threading.Thread(target=self._worker,name=f'ps4rf-worker-{i}',daemon=False) for i in range(size)]
        for t in self._threads:t.start()
    @property
    def poisoned(self):
        with self._lock:return self._poisoned
    @property
    def available_tokens(self):
        n=0
        while self._tokens.acquire(blocking=False): n+=1
        for _ in range(n): self._tokens.release()
        return n
    def submit(self,rid,op,fn):
        if not self._tokens.acquire(blocking=False): return 'TOO_MANY_INFLIGHT'
        with self._lock:
            if self._poisoned:
                self._tokens.release(); return 'POISONED'
            self._tasks[rid]={'state':TaskState.QUEUED,'op':op}
        self._queue.put((rid,op,fn)); return 'OK'
    def _finalize(self,rid):
        with self._lock:
            if self._tasks.pop(rid,None) is not None:
                self._tokens.release(); return True
            return False
    def finish(self,rid): self._finalize(rid)
    def poison(self,reason):
        with self._lock:
            self._poisoned=True
            infl=[{'request_id':rid,'operation':t['op'],'status':'IN_FLIGHT_AT_RECOVERY'} for rid,t in self._tasks.items() if t['state'] is TaskState.RUNNING]
            queued=[rid for rid,t in self._tasks.items() if t['state'] is TaskState.QUEUED]
            for rid in queued:self._tasks[rid]['state']=TaskState.CANCELED_AT_RECOVERY
            return infl,queued
    def _worker(self):
        while True:
            item=self._queue.get()
            try:
                if item is self.SENTINEL:return
                rid,op,fn=item
                with self._lock:
                    task=self._tasks.get(rid); canceled=False if task is None else task['state'] is TaskState.CANCELED_AT_RECOVERY
                    if task is not None and not canceled: task['state']=TaskState.RUNNING
                if task is None: continue
                if canceled:
                    if self._finalize(rid) and self._on_canceled:
                        try:self._on_canceled(rid,op)
                        except BaseException as e:
                            if self._on_worker_crash:self._on_worker_crash(rid,op,type(e).__name__)
                    continue
                try: fn(rid,op)
                except BaseException as e:
                    if self._on_worker_crash:self._on_worker_crash(rid,op,type(e).__name__)
            finally:self._queue.task_done()
    def has_pending(self):
        with self._lock:return bool(self._tasks)
    def shutdown(self,cancel_queued=True,wait_running=False,cancel_cb=None):
        if cancel_queued:
            while True:
                try:item=self._queue.get_nowait()
                except queue.Empty:break
                try:
                    if item is self.SENTINEL:continue
                    rid,op,_=item
                    if self._finalize(rid) and cancel_cb:
                        try:cancel_cb(rid,op)
                        except BaseException as e:
                            if self._on_worker_crash:self._on_worker_crash(rid,op,type(e).__name__)
                finally:self._queue.task_done()
        for _ in self._threads:self._queue.put(self.SENTINEL)
        if wait_running:
            for t in self._threads:t.join(timeout=5)
