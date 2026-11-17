"""Single owned dispatcher; long work runs outside its polling loop."""
from __future__ import annotations
import json
import signal
import threading
import time
import uuid
from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import atomic_write
from core.supervisor import Supervisor, boot_id, read_gate, write_gate

class Controller:
    def __init__(self, context, *, store=None, application=None, supervisor=None):
        self.context = context
        if store is None:
            from core.state import OperationsStore
            store = OperationsStore(context)
        self.store = store
        self.application = application
        self.supervisor = supervisor or Supervisor(ConfigManager(context), context)
        self.shutdown = threading.Event()
        self.epoch = uuid.uuid4().hex
        self._workers = set()

    def _heartbeat(self):
        atomic_write(self.context.root / "state" / "controller-epoch.json",
                     json.dumps({"epoch": self.epoch, "boot_id": boot_id(),
                                 "heartbeat": time.monotonic()}).encode())
        with FileLock(self.context.root / "locks" / "gate-controller.lock"):
            gate = read_gate(self.context, "controller")
            if gate.get("epoch") != self.epoch:
                gate.update(epoch=self.epoch)
                write_gate(self.context, "controller", gate)

    def _execute(self, operation):
        try:
            if self.application is None:
                from core.application import Application
                self.application = Application(self.context)
            result = self.application.execute_operation(operation)
            self.store.finish(operation["id"], result=result)
        except PocketError as exc:
            self.store.finish(operation["id"], error={"code": exc.code, "message": exc.message})
        except Exception:
            self.store.finish(operation["id"], error={"code": "operation_failed", "message": "Operation failed; inspect local diagnostics"})

    def run(self):
        self.context.ensure_mutable()
        with FileLock(self.context.root / "locks" / "controller.lock", timeout=0):
            self.store.interrupt_running()
            if self.application is None:
                from core.application import Application
                self.application = Application(self.context)
            self.application.jobs.reconcile_interrupted()
            self._heartbeat()
            self.supervisor.reconcile()
            previous_handlers = {}
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGTERM, signal.SIGINT):
                    previous_handlers[signum] = signal.signal(signum, lambda *args: self.shutdown.set())
            # A bounded executor keeps dispatch/cancellation/reconciliation responsive.
            # Core lifecycle operations still serialize through operation.lock.
            try:
                next_reconcile = 0
                next_heartbeat = 0
                while not self.shutdown.is_set():
                    if time.monotonic() >= next_heartbeat:
                        self._heartbeat()
                        next_heartbeat = time.monotonic() + 2
                    self._workers = {worker for worker in self._workers if worker.is_alive()}
                    if len(self._workers) < 2:
                        operation = self.store.claim_next()
                        if operation:
                            worker = threading.Thread(target=self._execute, args=(operation,),
                                                      name="pocket-operation", daemon=True)
                            self._workers.add(worker)
                            worker.start()
                    if time.monotonic() >= next_reconcile:
                        # Reconciliation must not stop a fresh explicit publication.
                        self.supervisor._wake()
                        self.application.tunnel.reconcile()
                        next_reconcile = time.monotonic() + 5
                    self.shutdown.wait(0.1)
            finally:
                self.application.jobs.shutdown_owned()
                self.store.interrupt_running()
                # Epoch invalidation makes every future payload gate fail closed.
                atomic_write(self.context.root / "state" / "controller-epoch.json", b"{}")
                deadline = time.monotonic() + 2
                for worker in self._workers:
                    worker.join(max(0, deadline - time.monotonic()))
                for signum, handler in previous_handlers.items():
                    signal.signal(signum, handler)

