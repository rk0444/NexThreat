"""
NexThreat Phase 6.3 — API Server & Lifecycle Manager.

Provides the server lifecycle wrapper managing ThreadingHTTPServer instantiation,
port binding, background execution, and clean shutdown for NexThreatAPIHandler.
"""
from __future__ import annotations

import logging
import threading
from http.server import ThreadingHTTPServer
from typing import Any, Optional

from src.api.handlers import NexThreatAPIHandler
from src.application import orchestrator

logger = logging.getLogger(__name__)


class NexThreatAPIServer:
    """
    Server lifecycle manager wrapping ThreadingHTTPServer and NexThreatAPIHandler.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        engine: Optional[Any] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.engine = engine if engine is not None else getattr(orchestrator, "ApplicationInferenceEngine")()
        self.engine_lock = threading.Lock()
        self.server: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None

    @property
    def actual_port(self) -> int:
        """Return the actual bound port (useful when port 0 is used for dynamic allocation)."""
        if self.server is not None:
            return self.server.server_address[1]
        return self.port

    def start(self, daemon: bool = True) -> None:
        """Start the HTTP server in a background thread."""
        handler_cls = NexThreatAPIHandler
        handler_cls.engine = self.engine
        handler_cls.engine_lock = self.engine_lock

        self.server = ThreadingHTTPServer((self.host, self.port), handler_cls)
        logger.info("NexThreat API Server started at http://%s:%d", self.host, self.actual_port)

        self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=daemon)
        self._server_thread.start()

    def stop(self) -> None:
        """Stop the HTTP server cleanly."""
        if self.server is not None:
            logger.info("Stopping NexThreat API Server...")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self._server_thread is not None and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
            self._server_thread = None
        logger.info("NexThreat API Server stopped.")

    def __enter__(self) -> NexThreatAPIServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
