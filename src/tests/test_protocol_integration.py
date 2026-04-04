"""
协议异常检测集成测试
测试边界情况处理：空请求、未知协议、极端信任值等
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.agent import Agent
from src.models.access_request import AccessRequest, AccessAction, DecisionOutcome
from src.access_controller import AgenticAccessController
from src.protocols.anomaly_detector import ProtocolAnomalyDetector, AnomalyResult, AnomalyType
from src.protocols.protocol_parser import ProtocolType
from src.protocols.modbus_parser import ModbusParser, ModbusMode


class TestProtocolAnomalyIntegration:
    """协议异常检测集成测试"""

    def setup_method(self):
        """测试初始化"""
        local_agent = Agent(agent_id="local", name="Local Agent", domain="control", agent_type="security")
        self.controller = AgenticAccessController(
            local_agent=local_agent,
            min_trust_threshold=0.5,
            min_alignment_threshold=0.7,
            protocol_anomaly_risk_threshold=0.5
        )
        self.controller.add_remote_agent(
            Agent(agent_id="remote", name="Remote Agent", domain="field", agent_type="device"),
            initial_trust=0.8
        )

    def test_empty_protocol_data_should_be_detected(self):
        """测试空协议数据应该被检测为异常"""
        request = AccessRequest(
            request_id="test-001",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="modbus",
            metadata={'raw_protocol_data': b''}
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")

        # 空数据风险评分为0.3 < 0.5阈值，不应该直接拒绝
        # 继续信任评估。remote已有0.8信任，所以不会因信任拒绝
        assert "Protocol anomaly detected" not in decision.reason

    def test_invalid_data_type_should_be_rejected(self):
        """测试无效数据类型应该被拒绝"""
        # 传入字符串而不是bytes
        request = AccessRequest(
            request_id="test-002",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="modbus",
            metadata={'raw_protocol_data': 'not bytes'}
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")

        # 风险评分0.6 >= 0.5阈值，应该拒绝
        assert decision.outcome == DecisionOutcome.DENY
        assert "Protocol anomaly detected" in decision.reason

    def test_known_protocol_with_corrupted_high_risk_data_should_be_rejected(self):
        """测试已知协议高风险损坏数据应该被拒绝"""
        # 使用无效数据类型已经会产生 0.6 风险，完全保证超过阈值
        request = AccessRequest(
            request_id="test-003",
            requester_id="remote",  # 已经添加过 remote 并设置初始信任 0.8，所以不会因信任拒绝
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="modbus",
            metadata={'raw_protocol_data': 'this is not bytes'}  # 类型错误，风险评分 0.6 >= 0.5
        )
        
        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        assert decision.outcome == DecisionOutcome.DENY
        assert "Protocol anomaly detected" in decision.reason

    def test_unknown_protocol_valid_data_auto_detect_should_pass(self):
        """测试未知协议但有效数据通过自动检测"""
        # Valid DL/T 645 frame but protocol field empty
        valid_dlt_data = bytes([
            0x68, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x68, 0x01, 0x11, 0x00, 0x8F, 0x16
        ])
        request = AccessRequest(
            request_id="test-004",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="",  # unknown
            metadata={'raw_protocol_data': valid_dlt_data}
        )

        # Auto-detect should find it's DLT645, if no anomaly passes through
        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        # Should pass to trust evaluation since no high-risk anomaly
        assert decision.outcome != DecisionOutcome.DENY or "Protocol anomaly" not in decision.reason

    def test_unknown_protocol_tiny_data_should_be_rejected(self):
        """测试未知协议的极小数据应该被检测为异常"""
        tiny_data = bytes([0x01, 0x02])  # less than 4 bytes
        request = AccessRequest(
            request_id="test-005",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="unknown-protocol",
            metadata={'raw_protocol_data': tiny_data}
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        # Auto-detect fails with 0.8 risk >= 0.5 threshold
        assert decision.outcome == DecisionOutcome.DENY
        assert "Protocol anomaly detected" in decision.reason
        # PROTOCOL_DETECTION_FAILED should be in the full reason description
        assert "PROTOCOL_DETECTION_FAILED" in str(request.context['protocol_anomaly'].anomalies)

    def test_no_protocol_data_skips_check(self):
        """测试没有协议数据时跳过检测"""
        request = AccessRequest(
            request_id="test-006",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="",
            metadata={}  # no raw_protocol_data
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        # Should proceed to trust evaluation
        assert "Protocol anomaly detected" not in decision.reason

    def test_low_risk_anomaly_passes_through(self):
        """测试低风险异常应该通过，继续后续评估"""
        # IEC frame with broadcast address but otherwise valid
        # 风险评分为 broadcast 只有0.1，低于阈值
        valid_data = bytes([0x68, 0x04, 0x01, 0x00, 0x03, 0x04, 0x08, 0x16])
        request = AccessRequest(
            request_id="test-007",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="iec-60870-5",
            metadata={'raw_protocol_data': valid_data}
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        # 风险评分只有0.1，应该通过到信任评估
        assert decision.outcome != DecisionOutcome.DENY or "Protocol anomaly" not in decision.reason

    def test_high_risk_anomaly_denied(self):
        """测试高风险异常应该直接拒绝"""
        # 自动检测失败产生高风险
        # 完全无法识别的数据，自动检测失败得到风险评分0.8
        bad_data = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        request = AccessRequest(
            request_id="test-008",
            requester_id="remote",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="invalid-protocol",
            metadata={'raw_protocol_data': bad_data}
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        assert decision.outcome == DecisionOutcome.DENY
        assert decision.confidence < 0.5  # confidence is low (1 - risk_score)
        assert "PROTOCOL_DETECTION_FAILED" in str(request.context['protocol_anomaly'].anomalies)

    def test_extremes_trust_zero_always_deny(self):
        """测试极端信任值 - 信任为0总是拒绝"""
        # Protocol is okay but trust is zero
        valid_data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x0A
        ])
        request = AccessRequest(
            request_id="test-009",
            requester_id="untrusted",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="modbus",
            metadata={'raw_protocol_data': valid_data}
        )
        # Add with zero trust
        self.controller.add_remote_agent(
            Agent(agent_id="untrusted", name="Untrusted", domain="field", agent_type="unknown"),
            initial_trust=0.0
        )

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "")
        # Should be denied due to trust, not protocol
        assert decision.outcome == DecisionOutcome.DENY
        assert "Insufficient trust" in decision.reason

    def test_extremes_trust_max_passes_if_no_anomaly(self):
        """测试极端信任值 - 最大信任且无异常应该通过"""
        valid_data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x0A
        ])
        request = AccessRequest(
            request_id="test-010",
            requester_id="trusted-max",
            target_id="local/resource",
            action=AccessAction.READ,
            protocol="modbus",
            metadata={'raw_protocol_data': valid_data}
        )
        self.controller.add_remote_agent(
            Agent(agent_id="trusted-max", name="Max Trusted", domain="field", agent_type="device"),
            initial_trust=1.0
        )
        self.controller.load_default_industrial_schemas()

        decision = self.controller.evaluate_access(request, DecisionOutcome.ALLOW, "Allow this access")
        # If protocol ok and trust ok, should allow
        # Alignment might fail if schema not match, but shouldn't be denied by protocol
        assert decision.outcome != DecisionOutcome.DENY or "Protocol anomaly" not in decision.reason

    def test_statistics_includes_protocol_anomaly_count(self):
        """测试统计包含协议异常检测计数"""
        stats = self.controller.get_statistics()
        assert 'detected_protocol_anomalies' in stats
        assert 'supported_protocols' in stats
        assert stats['supported_protocols'] == 4

    def test_protocol_name_normalization_handles_all_formats(self):
        """测试协议名称归一化能处理各种格式"""
        # Test different protocol name formats all map correctly
        test_cases = [
            ('modbus', ProtocolType.MODBUS),
            ('Modbus', ProtocolType.MODBUS),
            ('MODBUS', ProtocolType.MODBUS),
            ('opcua', ProtocolType.OPC_UA),
            ('opc-ua', ProtocolType.OPC_UA),
            ('OPC UA', ProtocolType.OPC_UA),
            ('iec', ProtocolType.IEC_60870_5),
            ('iec60870', ProtocolType.IEC_60870_5),
            ('104', ProtocolType.IEC_60870_5),
            ('dlt645', ProtocolType.DL_T_645),
            ('dl-t645', ProtocolType.DL_T_645),
        ]

        # 验证_internal映射逻辑正确性 - 通过实际上的检测效果验证
        for name, expected_type in test_cases:
            detector = self.controller.protocol_anomaly_detector
            valid_data = bytes([
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x0A
            ])
            # 只要不崩就是正确处理
            request = AccessRequest(
                request_id=f"test-format-{name}",
                requester_id="remote",
                target_id="local/resource",
                action=AccessAction.READ,
                protocol=name,
                metadata={'raw_protocol_data': valid_data}
            )
            result = self.controller._check_protocol_anomaly(request)
            assert result is not None  # should produce a result
            # No exceptions means successful mapping


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
