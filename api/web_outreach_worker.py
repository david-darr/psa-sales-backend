"""Opt-in reuse of the web host for the existing durable mail worker.

No work starts on import or while handling a request synchronously. Workers
share the existing database leases, approval guards and uncertainty handling.
A sleeping web host cannot provide continuously scheduled delivery.
"""
import atexit
import os
import threading
import uuid


def worker_mode():
    mode=os.getenv('OUTREACH_WORKER_MODE','external').strip().lower()
    if mode not in ('external','web'):
        raise ValueError('OUTREACH_WORKER_MODE must be external or web')
    return mode


class WebOutreachWorker:
    def __init__(self,app,db,svc,poll_seconds=10):
        if type(poll_seconds) is not int or not 1<=poll_seconds<=60:
            raise ValueError('Use a worker polling interval from 1 to 60 seconds')
        self.app,self.db,self.svc,self.poll_seconds=app,db,svc,poll_seconds
        self.pid=os.getpid()
        self.lock=threading.Lock()
        self.stop_event=threading.Event()
        self.thread=None
        self.worker_id=None

    def start(self):
        # Gunicorn can preload then fork. No parent thread/lock is reused.
        if self.pid!=os.getpid():
            self.pid=os.getpid();self.lock=threading.Lock()
            self.stop_event=threading.Event();self.thread=None;self.worker_id=None
        with self.lock:
            if self.stop_event.is_set() or self.thread and self.thread.is_alive():return False
            self.worker_id=str(uuid.uuid4())
            self.thread=threading.Thread(target=self._run,name='psa-outreach',daemon=True)
            self.thread.start()
            return True

    def _run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    with self.app.app_context():
                        try:
                            # Same fenced durable worker, one bounded batch turn.
                            self.svc.run_outreach_cycle(self.worker_id,max_jobs=1)
                        finally:
                            self.db.session.remove()
                except Exception:
                    self.app.logger.exception('Web-host outreach cycle failed; saved jobs remain in the database')
                if self.stop_event.wait(self.poll_seconds):break
        finally:
            try:
                with self.app.app_context():
                    try:
                        row=self.db.session.get(self.svc.OutreachWorkerHeartbeat,self.worker_id)
                        if row:
                            row.status='stopped';self.db.session.commit()
                    finally:
                        self.db.session.remove()
            except Exception:
                # A killed process is recovered through its persisted leases.
                self.app.logger.warning('Web-host worker shutdown could not update its heartbeat')

    def stop(self,wait_seconds=0):
        self.stop_event.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=wait_seconds)


def register_web_worker(app,db,svc):
    existing=app.extensions.get('psa_web_outreach_worker')
    if existing:return existing
    mode=worker_mode()
    app.config['OUTREACH_WORKER_MODE']=mode
    if mode!='web':return None
    try:poll_seconds=int(os.getenv('OUTREACH_POLL_SECONDS','10'))
    except ValueError:raise ValueError('OUTREACH_POLL_SECONDS must be a whole number') from None
    worker=WebOutreachWorker(app,db,svc,poll_seconds)
    app.extensions['psa_web_outreach_worker']=worker

    @app.before_request
    def ensure_outreach_worker():
        # Starts once per active web process, including after a host wakes up.
        # The request itself never runs SMTP or waits for a worker cycle.
        worker.start()

    atexit.register(worker.stop)
    return worker
