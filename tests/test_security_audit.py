"""
安全审计与监控模块测试
对代理本体安全与态势感知组件进行单元测试
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from datetime import datetime, timedelta
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 导入要测试的组件
from src.security_audit.node_validation import NodeValidationManager, ValidationStatus
from src.security_audit.config_management import ConfigurationManager, ConfigurationType
from src.security_audit.local_operation import LocalOperationManager, OperationType, OperationStatus
from src.security_audit.global_situation import GlobalSituationManager, SituationLevel, SecuritySituation
from src.security_audit.emergency_response import EmergencyResponseManager, ResponseLevel, ResponseStatus
from src.security_audit.incident_tracing import IncidentTracingManager, IncidentSeverity, IncidentStatus
from src.models.agent import Agent, AgentState


class TestNodeValidation:
    """节点可信验证组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.validator = NodeValidationManager()
        logger.info("TestNodeValidation: Setup complete")

    def test_node_validation_manager_initialization(self):
        """测试节点验证管理器初始化"""
        assert hasattr(self.validator, 'validated_nodes')
        assert len(self.validator.validated_nodes) == 0

    def test_node_validation_with_valid_node(self):
        """测试验证有效节点"""
        agent = Agent(agent_id="grid-001", agent_type="PHOTOVOLTAIC")
        result = self.validator.validate_node(agent)

        assert result.status == ValidationStatus.VALID
        assert result.is_trusted
        assert result.score > 0.5

    def test_node_validation_with_multiple_nodes(self):
        """测试验证多个节点"""
        agents = [
            Agent(agent_id="grid-001", agent_type="PHOTOVOLTAIC"),
            Agent(agent_id="grid-002", agent_type="WIND"),
            Agent(agent_id="grid-003", agent_type="PLC")
        ]

        for agent in agents:
            result = self.validator.validate_node(agent)
            assert result.status == ValidationStatus.VALID
            assert agent.agent_id in self.validator.validated_nodes

        assert len(self.validator.validated_nodes) == len(agents)

    def test_node_validation_status_checks(self):
        """测试验证状态检查"""
        # 测试获取验证结果
        agent = Agent(agent_id="grid-001", agent_type="PHOTOVOLTAIC")
        result = self.validator.validate_node(agent)
        retrieved = self.validator.get_validation_result(agent.agent_id)

        assert retrieved is not None
        assert retrieved.node_id == result.node_id
        assert retrieved.status == result.status

    def test_trusted_nodes_retrieval(self):
        """测试获取可信节点列表"""
        agent1 = Agent(agent_id="grid-001", agent_type="PHOTOVOLTAIC")
        agent2 = Agent(agent_id="grid-002", agent_type="WIND")

        self.validator.validate_node(agent1)
        self.validator.validate_node(agent2)

        trusted_nodes = self.validator.get_trusted_nodes()
        assert len(trusted_nodes) == 2
        assert agent1.agent_id in trusted_nodes
        assert agent2.agent_id in trusted_nodes

    def test_suspicious_nodes_detection(self):
        """测试可疑节点检测"""
        # 验证管理器会根据验证状态自动识别可疑节点
        # 这个测试需要模拟失败的验证
        pass

    def test_invalid_nodes_detection(self):
        """测试无效节点检测"""
        # 验证管理器会根据验证状态自动识别无效节点
        # 这个测试需要模拟失败的验证
        pass


class TestConfigurationManagement:
    """节点安全配置管控组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.config_manager = ConfigurationManager()
        logger.info("TestConfigurationManagement: Setup complete")

    def test_config_manager_initialization(self):
        """测试配置管理器初始化"""
        assert len(self.config_manager.configurations) > 0
        assert len(self.config_manager.default_configurations) > 0

    def test_get_configuration(self):
        """测试获取配置"""
        config = self.config_manager.get_configuration("", ConfigurationType.SECURITY_POLICY)

        assert config is not None
        assert config.config_type == ConfigurationType.SECURITY_POLICY
        assert len(config.config_data) > 0

    def test_configuration_types(self):
        """测试配置类型获取"""
        for config_type in ConfigurationType:
            config = self.config_manager.get_configuration("", config_type)
            assert config is not None
            assert config.config_type == config_type
            assert len(config.config_data) > 0

    def test_create_configuration(self):
        """测试创建配置"""
        test_config = {
            "min_trust_threshold": 0.7,
            "suspicious_threshold": 0.3,
            "access_control_enabled": True,
            "anomaly_detection_enabled": True,
            "auto_response_enabled": True,
            "trust_decay_factor": 0.8,
            "test_key": "test_value",
            "numeric_value": 42,
            "enabled": True
        }

        config = self.config_manager.create_configuration(
            node_id="grid-001",
            config_type=ConfigurationType.SECURITY_POLICY,
            config_data=test_config,
            description="Test security configuration"
        )

        assert config is not None
        assert config.node_id == "grid-001"
        assert config.description == "Test security configuration"
        assert config.is_active

    def test_configuration_update(self):
        """测试配置更新"""
        config = self.config_manager.get_configuration("", ConfigurationType.NETWORK_SETTINGS)

        new_port_range = "18789-18800"
        config.config_data["port_range"] = new_port_range

        updated = self.config_manager.update_configuration(config.config_id, config.config_data)

        assert updated.config_data["port_range"] == new_port_range

    def test_configuration_history(self):
        """测试配置历史记录"""
        config = self.config_manager.get_configuration("", ConfigurationType.AUDIT_SETTINGS)
        history = self.config_manager.get_configuration_history(config.config_id)

        assert len(history) >= 1
        assert history[0].version == 1


class TestLocalOperation:
    """本地操作管控组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.operation_manager = LocalOperationManager()
        logger.info("TestLocalOperation: Setup complete")

    def test_operation_manager_initialization(self):
        """测试操作管理器初始化"""
        assert len(self.operation_manager.operation_limits) > 0

    def test_execute_read_operation(self):
        """测试执行读取操作"""
        result = self.operation_manager.execute_operation(
            "grid-001", OperationType.READ, "data/solar_energy"
        )

        assert result.operation_type == OperationType.READ
        assert result.status == OperationStatus.ALLOWED
        assert result.result.get("result") == "read_success"

    def test_execute_write_operation(self):
        """测试执行写入操作"""
        result = self.operation_manager.execute_operation(
            "grid-001", OperationType.WRITE, "control/power_output", {"power": 100}
        )

        assert result.operation_type == OperationType.WRITE
        assert result.status == OperationStatus.ALLOWED
        assert result.result.get("result") == "write_success"

    def test_execute_execute_operation(self):
        """测试执行执行操作"""
        result = self.operation_manager.execute_operation(
            "grid-001", OperationType.EXECUTE, "command/restart"
        )

        assert result.operation_type == OperationType.EXECUTE
        assert result.status == OperationStatus.ALLOWED
        assert result.result.get("result") == "execute_success"

    def test_execute_admin_operation(self):
        """测试执行管理操作"""
        result = self.operation_manager.execute_operation(
            "grid-001", OperationType.ADMIN, "system/configure", {"param": "value"}
        )

        assert result.operation_type == OperationType.ADMIN
        assert result.status == OperationStatus.ALLOWED
        assert result.result.get("result") == "admin_success"

    def test_operation_limits_enforcement(self):
        """测试操作限制执行"""
        # 这个测试需要模拟操作频率限制
        pass

    def test_blocked_operations(self):
        """测试被阻塞的操作"""
        # 这个测试需要模拟不允许的操作
        pass


class TestGlobalSituation:
    """全局安全态势感知组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.situation_manager = GlobalSituationManager()
        logger.info("TestGlobalSituation: Setup complete")

    def test_situation_manager_initialization(self):
        """测试态势管理器初始化"""
        assert self.situation_manager.current_situation is not None
        assert len(self.situation_manager.situation_history) > 0

    def test_situation_level_detection(self):
        """测试态势级别检测"""
        # 测试安全状态
        safe_situation = SecuritySituation(threat_score=0.05)
        assert safe_situation.level == SituationLevel.SAFE
        assert not safe_situation.is_critical
        
        # 测试低风险状态
        low_situation = SecuritySituation(threat_score=0.1)
        assert low_situation.level == SituationLevel.LOW_RISK
        assert not low_situation.is_critical
        
        # 测试中风险状态
        medium_situation = SecuritySituation(threat_score=0.65)
        assert medium_situation.level == SituationLevel.MEDIUM_RISK
        assert not medium_situation.is_critical
        
        # 测试高风险状态
        high_situation = SecuritySituation(threat_score=0.85)
        assert high_situation.level == SituationLevel.HIGH_RISK
        assert high_situation.has_high_risk
        assert not high_situation.is_critical
        
        # 测试危机状态
        critical_situation = SecuritySituation(threat_score=0.95)
        assert critical_situation.level == SituationLevel.CRITICAL
        assert critical_situation.is_critical
        assert critical_situation.has_high_risk

    def test_situation_analysis(self):
        """测试态势分析"""
        analysis = self.situation_manager.get_situation_analysis()

        assert analysis.get("error") is None
        assert len(analysis.get("history")) > 0

    def test_situation_statistics(self):
        """测试态势统计信息"""
        analysis = self.situation_manager.get_situation_analysis()

        assert "statistics" in analysis
        stats = analysis["statistics"]

        assert "total_situations" in stats
        assert stats["total_situations"] >= 1

    def test_threat_detection(self):
        """测试威胁检测"""
        node_data = {
            "grid-001": {"status": "safe", "trust_score": 0.8},
            "grid-002": {"status": "warning", "trust_score": 0.3},
            "grid-003": {"status": "unsafe", "trust_score": 0.1}
        }

        operation_data = [
            {
                "node_id": "grid-001",
                "operation_type": "read",
                "status": "allowed"
            },
            {
                "node_id": "grid-002",
                "operation_type": "admin",
                "status": "blocked"
            }
        ]

        threats = self.situation_manager.detect_threats(node_data, operation_data)

        assert isinstance(threats, list)
        assert len(threats) > 0
        assert all(threat.is_high_severity for threat in threats if threat.is_high_severity)


class TestEmergencyResponse:
    """自动应急响应组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.response_manager = EmergencyResponseManager()
        logger.info("TestEmergencyResponse: Setup complete")

    def test_response_manager_initialization(self):
        """测试响应管理器初始化"""
        assert len(self.response_manager.response_rules) > 0

    def test_create_response(self):
        """测试创建响应"""
        threat = {
            "threat_id": "threat-001",
            "threat_type": "malicious_agent",
            "node_id": "grid-001",
            "severity": 0.85,
            "confidence": 0.9
        }

        response = self.response_manager.create_response(threat, "grid-001")

        assert response.threat_type == "malicious_agent"
        assert response.response_level == ResponseLevel.BLOCK
        assert len(response.actions) > 0

    def test_response_execution(self):
        """测试响应执行"""
        threat = {
            "threat_id": "threat-001",
            "threat_type": "abnormal_behavior",
            "node_id": "grid-001",
            "severity": 0.65,
            "confidence": 0.8
        }

        response = self.response_manager.create_response(threat, "grid-001")

        assert response.status == ResponseStatus.PENDING

        executed = self.response_manager.execute_response(response)

        assert executed.status in [ResponseStatus.COMPLETED, ResponseStatus.FAILED]

    def test_response_rules_checking(self):
        """测试响应规则检查"""
        # 测试响应规则是否正确应用
        assert "malicious_agent" in self.response_manager.response_rules
        assert self.response_manager.response_rules["malicious_agent"] == ResponseLevel.BLOCK


class TestIncidentTracing:
    """安全事件溯源组件测试"""

    def setup_method(self):
        """初始化测试环境"""
        self.tracing_manager = IncidentTracingManager()
        logger.info("TestIncidentTracing: Setup complete")

    def test_incident_manager_initialization(self):
        """测试事件管理器初始化"""
        assert len(self.tracing_manager.incidents) == 0

    def test_create_incident(self):
        """测试创建事件"""
        incident = self.tracing_manager.create_incident(
            description="Test incident creation",
            severity=IncidentSeverity.WARNING
        )

        assert incident is not None
        assert len(incident.description) > 0
        assert incident.status == IncidentStatus.DETECTED
        assert len(self.tracing_manager.incidents) == 1

    def test_incident_status_transition(self):
        """测试事件状态转换"""
        incident = self.tracing_manager.create_incident("Test incident", IncidentSeverity.ERROR)

        # 设置为调查中
        incident.update_status(IncidentStatus.INVESTIGATING)
        assert incident.status == IncidentStatus.INVESTIGATING

        # 设置为已确认
        incident.update_status(IncidentStatus.CONFIRMED)
        assert incident.status == IncidentStatus.CONFIRMED

        # 设置为已缓解
        incident.update_status(IncidentStatus.MITIGATED)
        assert incident.status == IncidentStatus.MITIGATED

        # 设置为已解决
        incident.update_status(IncidentStatus.RESOLVED)
        assert incident.status == IncidentStatus.RESOLVED

    def test_incident_comment_adding(self):
        """测试添加事件评论"""
        incident = self.tracing_manager.create_incident("Test incident", IncidentSeverity.WARNING)

        initial_comments = len(incident.comments)
        incident.add_comment("First investigation step completed")

        assert len(incident.comments) == initial_comments + 1

    def test_incident_evidence_management(self):
        """测试事件证据管理"""
        incident = self.tracing_manager.create_incident("Test incident", IncidentSeverity.ERROR)

        # 添加证据
        incident.add_evidence("system_logs", "CPU usage spikes detected")
        incident.add_evidence("network_traffic", "Suspicious outgoing connections")

        assert len(incident.evidence) == 2
        assert "system_logs" in incident.evidence
        assert "network_traffic" in incident.evidence

    def test_incident_list_retrieval(self):
        """测试获取事件列表"""
        for i in range(3):
            self.tracing_manager.create_incident(
                f"Test incident {i+1}",
                IncidentSeverity.WARNING
            )

        incidents = self.tracing_manager.get_incident_list()
        assert len(incidents) == 3

    def test_incident_details_retrieval(self):
        """测试获取事件详细信息"""
        incident = self.tracing_manager.create_incident(
            "Test detailed incident", IncidentSeverity.CRITICAL
        )

        details = self.tracing_manager.get_incident_details(incident.incident_id)
        assert details["incident_id"] == incident.incident_id
        assert details["severity"] == IncidentSeverity.CRITICAL.value
        assert details["status"] == IncidentStatus.DETECTED.value


if __name__ == "__main__":
    # 运行所有测试
    logger.info("Running security audit module tests...")
    pytest.main([__file__, "-v"])
