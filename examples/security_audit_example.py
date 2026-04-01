"""
代理本体安全与态势感知模块示例
演示如何使用安全审计与监控组件
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import logging
from datetime import datetime, timedelta
from src.security_audit.node_validation import NodeValidationManager
from src.security_audit.config_management import ConfigurationManager
from src.security_audit.local_operation import LocalOperationManager, OperationType
from src.security_audit.global_situation import GlobalSituationManager
from src.security_audit.emergency_response import EmergencyResponseManager
from src.security_audit.incident_tracing import IncidentTracingManager, IncidentSeverity
from src.models.agent import Agent, AgentState

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def run_security_audit_demo():
    """运行代理本体安全与态势感知模块示例"""
    logger.info("开始代理本体安全与态势感知模块示例")
    
    try:
        # 1. 初始化各个组件
        validation_manager = NodeValidationManager()
        config_manager = ConfigurationManager()
        operation_manager = LocalOperationManager()
        situation_manager = GlobalSituationManager()
        response_manager = EmergencyResponseManager()
        tracing_manager = IncidentTracingManager()
        
        logger.info("所有安全审计组件初始化完成")
        
        # 2. 模拟一些电网场景的代理节点
        power_agents = [
            Agent(agent_id="grid-001", agent_type="PHOTOVOLTAIC"),
            Agent(agent_id="grid-002", agent_type="WIND"),
            Agent(agent_id="grid-003", agent_type="PLC"),
            Agent(agent_id="grid-004", agent_type="SCADA"),
            Agent(agent_id="grid-005", agent_type="LOAD")
        ]
        
        logger.info(f"创建了 {len(power_agents)} 个电网场景代理")
        
        # 3. 节点可信验证
        logger.info("\n=== 节点可信验证 ===\n")
        validated_nodes = []
        
        for agent in power_agents:
            result = validation_manager.validate_node(agent)
            validated_nodes.append(result)
            
            logger.info(f"节点 {agent.agent_id} 验证结果: {result.status.value}")
            if not result.is_trusted:
                logger.warning(f"节点 {agent.agent_id} 验证失败，信任分数: {result.score:.2f}")
        
        # 4. 安全配置管理
        logger.info("\n=== 安全配置管理 ===\n")
        
        # 查看默认配置
        logger.info("获取全局安全策略配置:")
        security_policy = config_manager.get_configuration("", "security_policy")
        if security_policy is not None:
            logger.info(f"  配置类型: {security_policy.config_type.value}")
            logger.info(f"  配置级别: {security_policy.config_level.value}")
            logger.info(f"  最小信任阈值: {security_policy.config_data['min_trust_threshold']}")
            logger.info(f"  异常检测启用: {security_policy.config_data['anomaly_detection_enabled']}")
        else:
            logger.warning("安全策略配置未找到")
        
        # 查看网络配置
        logger.info("\n获取网络配置:")
        network_config = config_manager.get_configuration("", "network_settings")
        if network_config is not None:
            logger.info(f"  允许的IP范围: {network_config.config_data['allowed_ips']}")
            logger.info(f"  连接超时: {network_config.config_data['connection_timeout']}秒")
        else:
            logger.warning("网络配置未找到")
        
        # 5. 本地操作管控
        logger.info("\n=== 本地操作管控 ===\n")
        
        # 模拟一些操作
        operations = [
            {"node_id": "grid-001", "type": OperationType.READ, "resource": "data/solar_energy"},
            {"node_id": "grid-002", "type": OperationType.WRITE, "resource": "control/wind_power"},
            {"node_id": "grid-003", "type": OperationType.EXECUTE, "resource": "command/switch_state"},
            {"node_id": "grid-004", "type": OperationType.READ, "resource": "monitor/scada_data"},
            {"node_id": "grid-005", "type": OperationType.WRITE, "resource": "control/load_management"}
        ]
        
        for op in operations:
            try:
                result = operation_manager.execute_operation(op["node_id"], op["type"], op["resource"])
                logger.info(f"操作执行结果: {result.status.value}")
                if result.result:
                    logger.info(f"操作详情: {result.result}")
            except Exception as e:
                logger.error(f"操作执行失败: {e}")
        
        # 查看操作统计
        logger.info("\n操作统计信息:")
        stats = operation_manager.get_operation_statistics()
        logger.info(f"  总操作数: {stats['total_operations']}")
        logger.info(f"  按类型: {dict(stats['operations_by_type'])}")
        
        # 查看被阻塞的操作
        blocked_ops = operation_manager.get_blocked_operations()
        logger.info(f"  被阻塞的操作数: {len(blocked_ops)}")
        
        # 6. 全局安全态势感知
        logger.info("\n=== 全局安全态势感知 ===\n")
        
        # 模拟一些节点和威胁数据
        node_data = {}
        for agent in power_agents:
            node_data[agent.agent_id] = {
                "status": "safe" if validation_manager.get_validation_result(agent.agent_id).is_trusted else "risky",
                "trust_score": validation_manager.get_validation_result(agent.agent_id).score,
                "resource_usage": {
                    "cpu": 0.45 + (0.2 * (len(power_agents) % 3)),
                    "memory": 0.55 + (0.1 * (len(power_agents) % 3)),
                    "network": 0.3 + (0.15 * (len(power_agents) % 2))
                },
                "alerts": []
            }
        
        threat_data = {
            "threat-001": {
                "threat_id": "threat-001",
                "threat_type": "malicious_agent",
                "node_id": "grid-001",
                "severity": 0.85,
                "confidence": 0.9,
                "details": {"source": "external_network"}
            },
            "threat-002": {
                "threat_id": "threat-002",
                "threat_type": "abnormal_behavior",
                "node_id": "grid-003",
                "severity": 0.65,
                "confidence": 0.85,
                "details": {"behavior": "unusual_command_sequence"}
            }
        }
        
        # 更新安全态势
        situation = situation_manager.update_situation(node_data, threat_data)
        logger.info(f"当前安全态势级别: {situation.level.value}")
        logger.info(f"威胁分数: {situation.threat_score:.2f}")
        logger.info(f"活跃威胁数: {len(situation.active_threats)}")
        logger.info(f"受影响节点数: {len(situation.affected_nodes)}")
        logger.info(f"态势描述: {situation.description}")
        
        # 查看态势分析报告
        analysis = situation_manager.get_situation_analysis()
        logger.info("\n安全态势分析报告:")
        logger.info(f"  总态势记录数: {len(analysis['history'])}")
        
        # 7. 自动应急响应
        logger.info("\n=== 自动应急响应 ===\n")
        
        # 为检测到的威胁创建响应
        for threat in threat_data.values():
            response = response_manager.create_response(threat, threat["node_id"])
            logger.info(f"创建响应 {response.response_id}")
            logger.info(f"响应级别: {response.response_level.value}")
            logger.info(f"响应操作: {response.actions}")
        
        # 执行所有待处理的响应
        logger.info("\n执行所有待处理的响应:")
        executed_responses = response_manager.execute_all_pending()
        
        for response in executed_responses:
            logger.info(f"响应 {response.response_id} 执行状态: {response.status.value}")
            if response.result:
                logger.info(f"响应结果: {response.result}")
        
        # 查看响应统计
        logger.info("\n响应统计信息:")
        response_stats = response_manager.get_response_statistics()
        logger.info(f"  总响应数: {response_stats['total_responses']}")
        logger.info(f"  状态分布: {response_stats['status_distribution']}")
        
        # 8. 安全事件溯源
        logger.info("\n=== 安全事件溯源 ===\n")
        
        # 创建事件
        for i, threat in enumerate(threat_data.values()):
            incident = tracing_manager.create_incident(
                description=f"{threat['threat_type']} detected on {threat['node_id']}",
                severity=IncidentSeverity.CRITICAL
            )
            logger.info(f"创建事件 {incident.incident_id}")
        
        # 查看事件列表
        logger.info("\n事件列表:")
        incidents = tracing_manager.get_incident_list()
        for inc in incidents:
            logger.info(f"  事件 {inc['incident_id']}: {inc['severity']} - {inc['status']}")
        
        # 查看事件统计
        logger.info("\n事件统计信息:")
        incident_stats = tracing_manager.get_incident_statistics()
        logger.info(f"  总事件数: {incident_stats['total_incidents']}")
        logger.info(f"  活跃事件数: {incident_stats['active_incidents']}")
        logger.info(f"  严重程度分布: {incident_stats['severity_distribution']}")
        logger.info(f"  状态分布: {incident_stats['status_distribution']}")
        
        # 9. 系统整合运行
        logger.info("\n=== 系统整合运行 ===\n")
        
        # 模拟系统持续运行一段时间
        logger.info("系统运行 60 秒，监控安全态势...")
        
        # 模拟时间推进
        end_time = datetime.now() + timedelta(seconds=5)
        
        while datetime.now() < end_time:
            # 周期性更新态势
            situation_manager.update_situation(node_data, threat_data)
            
            # 检测新威胁
            new_threats = situation_manager.detect_threats(node_data, operations)
            
            if new_threats:
                logger.warning(f"检测到 {len(new_threats)} 个新威胁")
                # 自动响应新威胁
                executed_responses = response_manager.auto_response(new_threats)
                
                for response in executed_responses:
                    logger.warning(f"响应 {response.response_id} 状态: {response.status.value}")
        
        logger.info("安全审计模块运行完成")
        
    except Exception as e:
        logger.error(f"演示运行失败: {e}")
        raise


if __name__ == "__main__":
    logger.info("启动代理本体安全与态势感知模块示例")
    run_security_audit_demo()