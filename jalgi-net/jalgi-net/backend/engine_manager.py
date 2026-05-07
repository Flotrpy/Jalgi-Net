"""
JalgiNet – Engine Manager
========================
Handles global lifecycle of the detection engines to avoid circular imports.
"""

import threading
import time
import config

# Global engine storage
engines = {
    "capture":     None,
    "dos_engine":  None,
    "ids_engine":  None,
    "corr_engine": None
}


def start_engines():
    """Initialise and start all detection background threads."""
    from modules.packet_capture import PacketCapture
    from modules.dos_detector   import DoSDetector
    from modules.ids_parser     import IDSParser
    from modules.correlation    import CorrelationEngine

    engines["capture"]     = PacketCapture()
    engines["dos_engine"]  = DoSDetector(engines["capture"])
    engines["ids_engine"]  = IDSParser()
    engines["corr_engine"] = CorrelationEngine()

    engines["capture"].start()
    engines["dos_engine"].start()
    engines["ids_engine"].start()
    engines["corr_engine"].start()

    print(f"[EngineManager] All engines running (Mode: {'Simulation' if config.SIMULATION_MODE else 'Live'})")


def stop_engines():
    """Stop all running detection threads."""
    if engines["capture"]:     engines["capture"].stop()
    if engines["dos_engine"]:  engines["dos_engine"].stop()
    if engines["ids_engine"]:  engines["ids_engine"].stop()
    if engines["corr_engine"]: engines["corr_engine"].stop()
    print("[EngineManager] All engines stopped.")


def restart_engines():
    """Toggle mode and restart all engines."""
    stop_engines()
    # Give threads a moment to exit
    time.sleep(1)
    start_engines()
