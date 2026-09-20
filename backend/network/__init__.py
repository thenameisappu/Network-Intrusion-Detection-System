"""
Real-time Network Traffic Capture and Flow Analysis module.
Provides:
- Windows network interface discovery
- Npcap/Driver capability detection
- 5-tuple bidirectional flow aggregation
- 77-feature extraction aligned with CIC-IDS2017
- Background CaptureService with thread safety and event streaming
"""
from backend.network.interfaces import get_network_interfaces, check_capture_capability
from backend.network.flow import NetworkFlow
from backend.network.aggregator import FlowAggregator
from backend.network.capture_service import get_capture_service
from backend.network.policy import get_detection_policy

__all__ = [
    "get_network_interfaces",
    "check_capture_capability",
    "NetworkFlow",
    "FlowAggregator",
    "get_capture_service",
    "get_detection_policy",
]
