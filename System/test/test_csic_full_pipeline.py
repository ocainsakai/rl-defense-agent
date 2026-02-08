"""
Test CSIC Dataset qua FULL PIPELINE.

Pipeline: PacketLayerExtractor -> FlowManager -> FlowState -> Feature Calculators
"""

import pytest

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.feature_flow import (
    FlowFeatureCalculator,
    FlowFeature11_SqliKeyword,
    FlowFeature12_SqlSpecialChar,
    FlowFeature13_XssKeyword,
    FlowFeature14_XssSpecialChar,
)


@pytest.mark.integration
@pytest.mark.dataset
class TestCSICFullPipeline:
    """Test CSIC dataset through the full pipeline."""

    def test_pipeline_features(self, csic_csv_path):
        """Process CSIC records through pipeline, verify 14 features."""
        from helpers import load_csic_csv, reconstruct_http_packet

        records = load_csic_csv(csic_csv_path, limit=100)
        assert len(records) > 0

        parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)

        for i, record in enumerate(records):
            pkt = reconstruct_http_packet(
                method=record.method,
                url=record.url,
                content=record.content,
                seq_num=i,
            )
            info = parser.extract(pkt, packet_number=i)
            fm.process_packet(info)

        all_flows = fm.get_all_flows()
        assert len(all_flows) > 0

        calc = FlowFeatureCalculator()
        features = calc.calculate_all(all_flows)
        assert len(features) == 14

    def test_sqli_xss_detection(self, csic_csv_path):
        """Verify SQLi/XSS features are non-zero for attack traffic."""
        from helpers import load_csic_csv, reconstruct_http_packet

        records = load_csic_csv(csic_csv_path, limit=100, balanced=True)
        attack_records = [r for r in records if r.is_attack]
        assert len(attack_records) > 0, "No attack records in balanced sample"

        parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)

        for i, record in enumerate(attack_records[:50]):
            pkt = reconstruct_http_packet(
                method=record.method,
                url=record.url,
                content=record.content,
                seq_num=i,
            )
            info = parser.extract(pkt, packet_number=i)
            fm.process_packet(info)

        all_flows = fm.get_all_flows()

        sqli_score = FlowFeature11_SqliKeyword().calculate(all_flows)
        sqli_char = FlowFeature12_SqlSpecialChar().calculate(all_flows)
        xss_score = FlowFeature13_XssKeyword().calculate(all_flows)
        xss_char = FlowFeature14_XssSpecialChar().calculate(all_flows)

        total_indicators = sqli_score + sqli_char + xss_score + xss_char
        assert total_indicators > 0, "No SQLi/XSS indicators detected in attack flows"
