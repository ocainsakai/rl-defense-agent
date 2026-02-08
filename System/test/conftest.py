"""
conftest.py - Shared pytest configuration and fixtures.

This replaces the duplicated sys.path.insert(), setUp() methods,
and helper functions across all 13 test files.
"""

import sys
import os
import pytest

# Path setup - replaces sys.path.insert() in every test file
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_test_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _project_root)
sys.path.insert(0, _test_dir)  # So "from helpers import ..." works

# Dataset directory
DATASET_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'dataset'
)


# ============================================================================
# CORE FIXTURES
# ============================================================================

@pytest.fixture
def parser():
    """PacketLayerExtractor with realtime timestamps."""
    from core.packet_parser import PacketLayerExtractor
    return PacketLayerExtractor(use_packet_time=False)


@pytest.fixture
def parser_pcap():
    """PacketLayerExtractor with PCAP timestamps."""
    from core.packet_parser import PacketLayerExtractor
    return PacketLayerExtractor(use_packet_time=True)


@pytest.fixture
def parser_http():
    """PacketLayerExtractor with HTTP parsing enabled."""
    from core.packet_parser import PacketLayerExtractor
    return PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)


@pytest.fixture
def parser_full():
    """PacketLayerExtractor with PCAP timestamps + HTTP parsing."""
    from core.packet_parser import PacketLayerExtractor
    return PacketLayerExtractor(use_packet_time=True, enable_http_parsing=True)


@pytest.fixture
def flow_manager():
    """FlowManager with generous timeouts for testing."""
    from core.flow_manager import FlowManager
    return FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)


@pytest.fixture
def feature_calc():
    """FlowFeatureCalculator instance."""
    from feature.feature_flow import FlowFeatureCalculator
    return FlowFeatureCalculator()


@pytest.fixture
def pipeline():
    """Full pipeline: parser + flow_manager + feature_calc."""
    from core.packet_parser import PacketLayerExtractor
    from core.flow_manager import FlowManager
    from feature.feature_flow import FlowFeatureCalculator
    return {
        'parser': PacketLayerExtractor(use_packet_time=True, enable_http_parsing=True),
        'fm': FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000),
        'calc': FlowFeatureCalculator(),
    }


# ============================================================================
# DATASET FIXTURES
# ============================================================================

@pytest.fixture
def sqli_csv_path():
    """Path to sqli.csv dataset. Skips test if not found."""
    path = os.path.join(DATASET_DIR, 'sqli.csv')
    if not os.path.exists(path):
        pytest.skip("sqli.csv not found in dataset/")
    return path


@pytest.fixture
def csic_csv_path():
    """Path to csic_database.csv dataset. Skips test if not found."""
    path = os.path.join(DATASET_DIR, 'csic_database.csv')
    if not os.path.exists(path):
        pytest.skip("csic_database.csv not found in dataset/")
    return path
