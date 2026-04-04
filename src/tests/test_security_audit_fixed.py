import unittest
import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from datetime import timedelta
from src.models.agent import Agent
from src.security_audit.node_validation import NodeValidationManager
from src.security_audit.config_management import ConfigurationManager
from src.security_audit.local_operation import LocalOperationManager
from src.security_audit.global_situation import GlobalSituationManager
from src.security_audit.emergency_response import EmergencyResponseManager
from src.security_audit.incident_tracing import IncidentTracingManager
from src.security_audit.node_validation import ValidationStatus
from src.security_audit.config_management import ConfigurationType
from src.security_audit.local_operation import OperationType, OperationStatus
from src.security_audit.global_situation import SituationLevel
from src.security_audit.emergency_response import ResponseLevel, ResponseStatus
from src.security_audit.incident_tracing import IncidentSeverity, IncidentStatus


class TestNodeValidation(unittest.TestCase):
    """测试节点验证管理"""

    def setUp(self):
        """设置测试环境"""
        self.validator = NodeValidationManager()
        self.test_node = Agent(agent_id="node-001", agent_type="PHOTOVOLTAIC")

    def test_node_validation_manager_initialization(self):
        """测试节点验证管理器初始化"""
        self.assertIsNotNone(self.validator)
        self.assertEqual(len(self.validator.validated_nodes), 0)

    def test_node_validation_with_valid_node(self):
        """测试验证有效节点"""
        result = self.validator.validate_node(self.test_node)
        self.assertEqual(result.status, ValidationStatus.VALID)
        self.assertTrue(result.is_trusted)

    def test_node_validation_with_multiple_nodes(self):
        """测试验证多个节点"""
        agents = [
            Agent(agent_id="node-001", agent_type="PHOTOVOLTAIC"),
            Agent(agent_id="node-002", agent_type="WIND"),
            Agent(agent_id="node-003", agent_type="PLC")
        ]

        for agent in agents:
            result = self.validator.validate_node(agent)
            self.assertIn(agent.agent_id, self.validator.validated_nodes)
            self.assertGreaterEqual(result.score, 0.0)

    def test_node_validation_status_checks(self):
        """测试验证状态检查"""
        self.validator.validate_node(self.test_node)
        result = self.validator.get_validation_result(self.test_node.agent_id)
        self.assertEqual(result.status, ValidationStatus.VALID)
        self.assertTrue(result.is_trusted)

    def test_trusted_nodes_retrieval(self):
        """测试获取可信节点列表"""
        self.validator.validate_node(self.test_node)
        trusted_nodes = self.validator.get_trusted_nodes()
        self.assertIn(self.test_node.agent_id, trusted_nodes)


class TestConfigurationManagement(unittest.TestCase):
    """测试配置管理"""

    def setUp(self):
        """设置测试环境"""
        self.config_manager = ConfigurationManager()

    def test_config_manager_initialization(self):
        """测试配置管理器初始化"""
        self.assertIsNotNone(self.config_manager)

    def test_get_configuration(self):
        """测试获取配置"""
        config = self.config_manager.get_configuration("node-001", ConfigurationType.SECURITY_POLICY)
        self.assertIsNotNone(config)
        self.assertEqual(config.config_type, ConfigurationType.SECURITY_POLICY)

    def test_configuration_types(self):
        """测试配置类型"""
        config_types = [
            ConfigurationType.SECURITY_POLICY,
            ConfigurationType.NETWORK_SETTINGS,
            ConfigurationType.AUDIT_SETTINGS
        ]

        for config_type in config_types:
            config = self.config_manager.get_configuration("node-001", config_type)
            self.assertIsNotNone(config)

    def test_create_configuration(self):
        """测试创建配置"""
        test_config = {"test_key": "test_value"}
        # 测试创建网络配置(不需要安全策略的特定字段)
        test_config = {"test_key": "test_value"}
        config = self.config_manager.create_configuration(
            "node-001", ConfigurationType.NETWORK_SETTINGS, test_config, "Test Configuration"
        )
        self.assertIsNotNone(config)
        self.assertEqual(config.node_id, "node-001")

    def test_configuration_update(self):
        """测试配置更新"""
        test_config = {"test_key": "test_value"}
        config = self.config_manager.create_configuration(
            "node-001", ConfigurationType.SECURITY_POLICY, test_config, "Test Configuration"
        )

        config.config_data["new_key"] = "new_value"
        updated_config = self.config_manager.update_configuration(config.config_id, config.config_data)
        self.assertEqual(updated_config.config_data["new_key"], "new_value")

    def test_configuration_history(self):
        """测试配置历史"""
        test_config = {"test_key": "test_value"}
        config = self.config_manager.create_configuration(
            "node-001", ConfigurationType.SECURITY_POLICY, test_config, "Test Configuration"
        )
        history = self.config_manager.get_configuration_history(config.config_id)
        self.assertGreater(len(history), 0)


class TestLocalOperation(unittest.TestCase):
    """测试本地操作管理"""

    def setUp(self):
        """设置测试环境"""
        self.operation_manager = LocalOperationManager()

    def test_operation_manager_initialization(self):
        """测试操作管理器初始化"""
        self.assertIsNotNone(self.operation_manager)

    def test_execute_read_operation(self):
        """测试执行读取操作"""
        result = self.operation_manager.execute_operation(
            "node-001", OperationType.READ, "data/test"
        )
        self.assertEqual(result.status, OperationStatus.ALLOWED)

    def test_execute_write_operation(self):
        """测试执行写入操作"""
        result = self.operation_manager.execute_operation(
            "node-001", OperationType.WRITE, "data/test", {"content": "test"}
        )
        self.assertEqual(result.status, OperationStatus.ALLOWED)

    def test_execute_execute_operation(self):
        """测试执行执行操作"""
        result = self.operation_manager.execute_operation(
            "node-001", OperationType.EXECUTE, "command/test"
        )
        self.assertEqual(result.status, OperationStatus.ALLOWED)

    def test_execute_admin_operation(self):
        """测试执行管理操作"""
        result = self.operation_manager.execute_operation(
            "node-001", OperationType.ADMIN, "system/config"
        )
        self.assertEqual(result.status, OperationStatus.ALLOWED)

    def test_operation_limits_enforcement(self):
        """测试操作限制执行"""
        self.assertIsNotNone(self.operation_manager.operation_limits)

    def test_blocked_operations(self):
        """测试被阻塞的操作"""
        self.assertEqual(len(self.operation_manager.blocked_operations), 0)


class TestGlobalSituation(unittest.TestCase):
    """测试全局态势感知"""

    def setUp(self):
        """设置测试环境"""
        self.situation_manager = GlobalSituationManager()

    def test_situation_manager_initialization(self):
        """测试态势管理器初始化"""
        self.assertIsNotNone(self.situation_manager)

    def test_situation_level_detection(self):
        """测试态势级别检测"""
        from src.security_audit.global_situation import SecuritySituation
    
        safe_situation = SecuritySituation(threat_score=0.05)
        self.assertEqual(safe_situation.level, SituationLevel.SAFE)
    
        low_situation = SecuritySituation(threat_score=0.2)
        self.assertEqual(low_situation.level, SituationLevel.LOW_RISK)
    
        medium_situation = SecuritySituation(threat_score=0.6)
        self.assertEqual(medium_situation.level, SituationLevel.MEDIUM_RISK)
    
        high_situation = SecuritySituation(threat_score=0.8)
        self.assertEqual(high_situation.level, SituationLevel.HIGH_RISK)
    
        critical_situation = SecuritySituation(threat_score=0.95)
        self.assertEqual(critical_situation.level, SituationLevel.CRITICAL)

    def test_situation_analysis(self):
        """测试态势分析"""
        analysis = self.situation_manager.get_situation_analysis()
        self.assertIn("statistics", analysis)
        self.assertGreater(analysis["statistics"]["total_situations"], 0)

    def test_situation_statistics(self):
        """测试态势统计"""
        analysis = self.situation_manager.get_situation_analysis()
        self.assertIn("statistics", analysis)
        self.assertGreater(analysis["statistics"]["total_situations"], 0)

    def test_threat_detection(self):
        """测试威胁检测"""
        node_data = {"node-001": {"status": "safe", "trust_score": 0.8}}
        operation_data = [{"node_id": "node-001", "operation_type": "read", "status": "allowed"}]

        threats = self.situation_manager.detect_threats(node_data, operation_data)
        self.assertIsInstance(threats, list)


class TestEmergencyResponse(unittest.TestCase):
    """测试应急响应"""

    def setUp(self):
        """设置测试环境"""
        self.response_manager = EmergencyResponseManager()

    def test_response_manager_initialization(self):
        """测试响应管理器初始化"""
        self.assertIsNotNone(self.response_manager)

    def test_create_response(self):
        """测试创建响应"""
        threat = {"threat_id": "threat-001", "threat_type": "malicious_agent"}
        response = self.response_manager.create_response(threat, "node-001")
        self.assertIsNotNone(response)
        self.assertEqual(response.response_level, ResponseLevel.BLOCK)

    def test_response_execution(self):
        """测试响应执行"""
        threat = {"threat_id": "threat-001", "threat_type": "malicious_agent"}
        response = self.response_manager.create_response(threat, "node-001")
        self.assertEqual(response.status, ResponseStatus.PENDING)
        executed_response = self.response_manager.execute_response(response)
        self.assertEqual(executed_response.status, ResponseStatus.COMPLETED)

    def test_response_rules_checking(self):
        """测试响应规则检查"""
        self.assertIn("malicious_agent", self.response_manager.response_rules)
        self.assertEqual(self.response_manager.response_rules["malicious_agent"], ResponseLevel.BLOCK)


class TestIncidentTracing(unittest.TestCase):
    """测试事件溯源"""

    def setUp(self):
        """设置测试环境"""
        self.tracing_manager = IncidentTracingManager()

    def test_incident_manager_initialization(self):
        """测试事件管理器初始化"""
        self.assertIsNotNone(self.tracing_manager)

    def test_create_incident(self):
        """测试创建事件"""
        incident = self.tracing_manager.create_incident("Test Incident")
        self.assertIsNotNone(incident)
        self.assertEqual(incident.status, IncidentStatus.DETECTED)

    def test_incident_status_transition(self):
        """测试事件状态转换"""
        incident = self.tracing_manager.create_incident("Test Incident")
        self.tracing_manager.confirm_incident(incident.incident_id, "Test Root Cause", ["node-001"])
        self.assertEqual(self.tracing_manager.get_incident_details(incident.incident_id)["status"], IncidentStatus.CONFIRMED.value)

    def test_incident_comment_adding(self):
        """测试添加事件评论"""
        incident = self.tracing_manager.create_incident("Test Incident")
        self.tracing_manager.incidents[incident.incident_id].add_comment("Test Comment")
        comments = self.tracing_manager.get_incident_details(incident.incident_id)["comments"]
        self.assertIn("Test Comment", ' '.join(comments))

    def test_incident_evidence_management(self):
        """测试证据管理"""
        incident = self.tracing_manager.create_incident("Test Incident")
        self.tracing_manager.incidents[incident.incident_id].add_evidence("test_evidence", "test_content")
        incident = self.tracing_manager.incidents[incident.incident_id]
        evidence = incident.evidence
        self.assertIn("test_evidence", evidence)

    def test_incident_list_retrieval(self):
        """测试获取事件列表"""
        incidents = self.tracing_manager.get_incident_list()
        self.assertIsInstance(incidents, list)

    def test_incident_details_retrieval(self):
        """测试获取事件详细信息"""
        incident = self.tracing_manager.create_incident("Test Incident")
        details = self.tracing_manager.get_incident_details(incident.incident_id)
        self.assertEqual(details["incident_id"], incident.incident_id)


if __name__ == '__main__':
    unittest.main()