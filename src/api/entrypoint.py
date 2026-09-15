"""
NexThreat Phase 6.5 — Production Container Entrypoint Runner.

Wraps the frozen NexThreatAPIServer lifecycle, parses environment variables,
registers OS signal listeners (SIGTERM/SIGINT), and orchestrates clean server termination.
Grounded strictly in the existing repository architecture (Phase 6.3/6.4).
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from typing import Any

from src.api.server import NexThreatAPIServer

# Standard logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("NexThreat.Entrypoint")


def parse_environment_configuration() -> tuple[str, int, str]:
    """
    Parse and validate operational environment variables.
    Defaults conform to the Phase 6.5 specification:
      NEXTHREAT_HOST: 0.0.0.0
      NEXTHREAT_PORT: 8000
      NEXTHREAT_LOG_LEVEL: INFO
    """
    host = os.environ.get("NEXTHREAT_HOST", "0.0.0.0")
    
    port_str = os.environ.get("NEXTHREAT_PORT", "8000")
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            logger.warning("NEXTHREAT_PORT %d out of valid range (1-65535). Falling back to 8000.", port)
            port = 8000
    except ValueError:
        logger.warning("Invalid NEXTHREAT_PORT '%s'. Falling back to 8000.", port_str)
        port = 8000

    log_level = os.environ.get("NEXTHREAT_LOG_LEVEL", "INFO").upper()
    valid_levels = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}
    if log_level in valid_levels:
        logging.getLogger().setLevel(valid_levels[log_level])
        logger.setLevel(valid_levels[log_level])
    else:
        logger.warning("Invalid NEXTHREAT_LOG_LEVEL '%s'. Falling back to INFO.", log_level)
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
        log_level = "INFO"

    return host, port, log_level


def main() -> int:
    """
    Main container lifecycle runner:
    1. Parses environment configuration.
    2. Instantiates NexThreatAPIServer (relying on default engine=None initialization).
    3. Registers SIGTERM/SIGINT signal handlers.
    4. Starts server thread.
    5. Awaits termination signal and executes graceful shutdown.
    """
    host, port, log_level = parse_environment_configuration()
    logger.info("Initializing NexThreat Production Container Entrypoint...")
    logger.info("Configuration: Host=%s, Port=%d, LogLevel=%s", host, port, log_level)

    stop_event = threading.Event()

    def signal_handler(signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received termination signal (%s). Initiating graceful shutdown...", sig_name)
        stop_event.set()

    # Register termination signals
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except (ValueError, AttributeError) as e:
        logger.debug("Could not bind SIGTERM (platform specific): %s", e)

    try:
        signal.signal(signal.SIGINT, signal_handler)
    except (ValueError, AttributeError) as e:
        logger.debug("Could not bind SIGINT (platform specific): %s", e)

    server = None
    try:
        # Grounded in frozen src/api/server.py: engine=None internally instantiates ApplicationInferenceEngine
        server = NexThreatAPIServer(host=host, port=port)
        server.start(daemon=True)
        logger.info("NexThreat API server running at http://%s:%d", host, server.actual_port)

        # Wait loop allowing signal delivery
        while not stop_event.is_set():
            stop_event.wait(timeout=0.5)

    except Exception as exc:
        logger.error("Fatal error in NexThreat server lifecycle: %s", exc, exc_info=True)
        return 1
    finally:
        if server is not None:
            logger.info("Shutting down HTTP transport...")
            server.stop()
            logger.info("NexThreat container shutdown complete.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
