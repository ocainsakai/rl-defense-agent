"""
Test SQLi Dataset qua FULL PIPELINE.

Pipeline: PacketLayerExtractor -> FlowManager -> FlowState -> Feature Calculators
"""

import pytest

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculators.payload_features import F11_SqliKeyword


@pytest.mark.integration
@pytest.mark.sqli
@pytest.mark.dataset
class TestSqliFullPipeline:
    """Test SQLi detection through the full pipeline."""

    def test_pipeline_metrics(self, sqli_csv_path):
        """Test full pipeline: packet creation -> feature extraction -> detection."""
        from helpers import load_sqli_csv, make_http_packet

        records = load_sqli_csv(sqli_csv_path, limit=200)
        assert len(records) > 0

        parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
        f11_calc = F11_SqliKeyword()

        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0

        attack_records = sum(1 for _, label in records if label == 1)

        for i, (sentence, label) in enumerate(records):
            fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
            pkt = make_http_packet(sentence, seq_num=i)
            info = parser.extract(pkt, packet_number=i)
            fm.process_packet(info)

            flows = fm.get_all_flows()
            sqli_score = f11_calc.calculate(flows)

            predicted_attack = sqli_score > 0
            actual_attack = label == 1

            if actual_attack and predicted_attack:
                true_positives += 1
            elif not actual_attack and not predicted_attack:
                true_negatives += 1
            elif not actual_attack and predicted_attack:
                false_positives += 1
            else:
                false_negatives += 1

        total = true_positives + true_negatives + false_positives + false_negatives
        assert total == len(records)

        if attack_records > 0:
            recall = true_positives / (true_positives + false_negatives)
            assert recall >= 0.3, f"Pipeline recall too low: {recall:.2%}"
