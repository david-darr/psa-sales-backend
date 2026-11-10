import os
import threading
import types
import unittest
from unittest.mock import Mock,patch
from flask import Flask
from api.web_outreach_worker import WebOutreachWorker,register_web_worker,worker_mode


class WebWorkerTests(unittest.TestCase):
    def fixture(self,cycle):
        app=Flask(__name__)
        app.add_url_rule('/ping','ping',lambda:'ok')
        session=types.SimpleNamespace(remove=Mock(),get=Mock(return_value=None),commit=Mock())
        db=types.SimpleNamespace(session=session)
        svc=types.SimpleNamespace(run_outreach_cycle=cycle,OutreachWorkerHeartbeat=object())
        return app,db,svc

    def test_default_external_and_invalid_modes(self):
        with patch.dict(os.environ,{},clear=True):self.assertEqual(worker_mode(),'external')
        with patch.dict(os.environ,{'OUTREACH_WORKER_MODE':'typo'}):
            with self.assertRaises(ValueError):worker_mode()

    def test_external_registration_does_not_start_any_thread(self):
        cycle=Mock();app,db,svc=self.fixture(cycle)
        with patch.dict(os.environ,{'OUTREACH_WORKER_MODE':'external'}),patch('threading.Thread') as thread:
            self.assertIsNone(register_web_worker(app,db,svc))
            self.assertEqual(app.test_client().get('/ping').status_code,200)
            thread.assert_not_called();cycle.assert_not_called()

    def test_opt_in_starts_once_per_process_without_blocking_requests(self):
        entered,release=threading.Event(),threading.Event()
        def cycle(*args,**kwargs):entered.set();release.wait(2)
        app,db,svc=self.fixture(Mock(side_effect=cycle))
        with patch.dict(os.environ,{'OUTREACH_WORKER_MODE':'web','OUTREACH_POLL_SECONDS':'60'}):worker=register_web_worker(app,db,svc)
        try:
            self.assertIsNone(worker.thread)
            self.assertEqual(app.test_client().get('/ping').status_code,200)
            self.assertTrue(entered.wait(1))
            self.assertFalse(release.is_set())
            for _ in range(4):self.assertEqual(app.test_client().get('/ping').status_code,200)
            self.assertEqual(svc.run_outreach_cycle.call_count,1)
            self.assertEqual(svc.run_outreach_cycle.call_args.kwargs,{'max_jobs':1})
            self.assertIs(register_web_worker(app,db,svc),worker)
        finally:worker.stop();release.set();worker.stop(2)
        self.assertFalse(worker.thread.is_alive())
        db.session.remove.assert_called()
        self.assertFalse(worker.start())

    def test_concurrent_start_calls_share_one_thread(self):
        entered,release=threading.Event(),threading.Event()
        def cycle(*args,**kwargs):entered.set();release.wait(2)
        app,db,svc=self.fixture(Mock(side_effect=cycle));worker=WebOutreachWorker(app,db,svc,60)
        from concurrent.futures import ThreadPoolExecutor
        try:
            with ThreadPoolExecutor(8) as pool:started=list(pool.map(lambda _:worker.start(),range(16)))
            self.assertEqual(sum(started),1);self.assertTrue(entered.wait(1))
        finally:worker.stop();release.set();worker.stop(2)
        self.assertEqual(svc.run_outreach_cycle.call_count,1)

    def test_a_failed_cycle_retries_without_losing_process(self):
        recovered=threading.Event()
        def cycle(*args,**kwargs):
            if cycle.calls==0:cycle.calls+=1;raise RuntimeError('local failure')
            recovered.set()
        cycle.calls=0
        app,db,svc=self.fixture(cycle);app.logger=Mock();worker=WebOutreachWorker(app,db,svc,1)
        try:worker.start();self.assertTrue(recovered.wait(3))
        finally:worker.stop(2)
        app.logger.exception.assert_called_once()
        self.assertGreaterEqual(db.session.remove.call_count,3)

    def test_fork_reinitializes_parent_stop_state(self):
        app,db,svc=self.fixture(Mock());worker=WebOutreachWorker(app,db,svc,60)
        worker.pid=-1;worker.stop_event.set()
        try:self.assertTrue(worker.start())
        finally:worker.stop(2)
        self.assertEqual(worker.pid,os.getpid())

    def test_invalid_polling_configuration_is_rejected(self):
        app,db,svc=self.fixture(Mock())
        for interval in ('zero','0','61'):
            with patch.dict(os.environ,{'OUTREACH_WORKER_MODE':'web','OUTREACH_POLL_SECONDS':interval}):
                with self.assertRaises(ValueError):register_web_worker(app,db,svc)
