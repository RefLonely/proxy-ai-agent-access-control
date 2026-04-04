"""
全局安全态势感知模块
负责对整个系统的安全态势进行实时感知和评估
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import uuid
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class SituationLevel(Enum):
    """安全态势级别枚举"""
    SAFE = "safe"  # 安全
    LOW_RISK = "low_risk"  # 低风险
    MEDIUM_RISK = "medium_risk"  # 中风险
    HIGH_RISK = "high_risk"  # 高风险
    CRITICAL = "critical"  # 危机


class ThreatType(Enum):
    """威胁类型枚举"""
    MALICIOUS_AGENT = "malicious_agent"  # 恶意代理
    ABnormal_BEHAVIOR = "abnormal_behavior"  # 异常行为
    NETWORK_ATTACK = "network_attack"  # 网络攻击
    CONFIGURATION_VIOLATION = "configuration_violation"  # 配置违规
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # 资源耗尽
    PERMISSION_ESCALATION = "permission_escalation"  # 权限提升


@dataclass
class SecuritySituation:
    """安全态势"""
    situation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    level: SituationLevel = field(init=False)  # 不允许直接初始化，需要通过威胁分数计算
    threat_score: float = 0.0  # 威胁分数 (0-1)
    active_threats: List[ThreatType] = field(default_factory=list)
    affected_nodes: List[str] = field(default_factory=list)
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        """在初始化后设置安全级别"""
        self.level = self._determine_level(self.threat_score)
    
    @staticmethod
    def _determine_level(score: float) -> SituationLevel:
        """根据威胁分数确定安全级别"""
        if score >= 0.9:
            return SituationLevel.CRITICAL
        elif score >= 0.7:
            return SituationLevel.HIGH_RISK
        elif score >= 0.4:
            return SituationLevel.MEDIUM_RISK
        elif score >= 0.1:
            return SituationLevel.LOW_RISK
        else:
            return SituationLevel.SAFE
    
    @property
    def is_critical(self) -> bool:
        """判断是否危机状态"""
        return self.level == SituationLevel.CRITICAL
    
    @property
    def has_high_risk(self) -> bool:
        """判断是否高风险"""
        return self.level in [SituationLevel.HIGH_RISK, SituationLevel.CRITICAL]
    
    @property
    def severity_score(self) -> float:
        """计算严重程度分数"""
        level_scores = {
            SituationLevel.SAFE: 0.0,
            SituationLevel.LOW_RISK: 0.25,
            SituationLevel.MEDIUM_RISK: 0.5,
            SituationLevel.HIGH_RISK: 0.75,
            SituationLevel.CRITICAL: 1.0
        }
        return level_scores[self.level]


@dataclass
class ThreatDetection:
    """威胁检测"""
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: ThreatType = ThreatType.ABnormal_BEHAVIOR
    node_id: str = ""
    severity: float = 0.0
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict = field(default_factory=dict)
    
    @property
    def is_high_severity(self) -> bool:
        """判断是否高严重程度"""
        return self.severity >= 0.7
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type.value,
            "node_id": self.node_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details
        }


class GlobalSituationManager:
    """全局安全态势管理器"""
    
    def __init__(self):
        self.situation_history: List[SecuritySituation] = []
        self.threat_detections: List[ThreatDetection] = []
        self.current_situation: SecuritySituation = self._create_initial_situation()
        self.situation_history.append(self.current_situation)
        self.situation_cache: Dict[str, Any] = {}
    
    def _create_initial_situation(self) -> SecuritySituation:
        """创建初始安全态势"""
        return SecuritySituation(
            threat_score=0.0,
            active_threats=[],
            affected_nodes=[],
            description="Initial safe state"
        )
    
    def update_situation(self, node_data: Dict[str, Any], threat_data: Dict[str, Any]) -> SecuritySituation:
        """更新安全态势"""
        # 分析节点数据
        node_score = self._analyze_node_safety(node_data)
        
        # 分析威胁数据
        threat_score = self._analyze_threat_safety(threat_data)
        
        # 综合计算总体威胁分数
        overall_score = (node_score * 0.6) + (threat_score * 0.4)
        
        # 确定安全态势级别
        level = self._determine_situation_level(overall_score)
        
        # 收集活跃威胁和受影响节点
        active_threats = self._collect_active_threats(threat_data)
        affected_nodes = self._collect_affected_nodes(threat_data)
        
        # 更新当前态势
        self.current_situation = SecuritySituation(
            threat_score=overall_score,
            active_threats=active_threats,
            affected_nodes=affected_nodes,
            description=self._generate_situation_description(level, len(active_threats), len(affected_nodes)),
            details={
                "node_score": node_score,
                "threat_score": threat_score,
                "node_count": len(node_data),
                "threat_count": len(threat_data)
            }
        )
        
        self.situation_history.append(self.current_situation)
        logger.info(f"Security situation updated to {level.value} (score: {overall_score:.2f})")
        return self.current_situation
    
    def _analyze_node_safety(self, node_data: Dict[str, Any]) -> float:
        """分析节点安全状况"""
        if not node_data:
            return 0.0
        
        safe_nodes = 0
        total_nodes = len(node_data)
        
        for node_id, data in node_data.items():
            if data.get("status") == "safe" and data.get("trust_score", 0.0) >= 0.7:
                safe_nodes += 1
        
        return 1.0 - (safe_nodes / total_nodes)
    
    def _analyze_threat_safety(self, threat_data: Dict[str, Any]) -> float:
        """分析威胁安全状况"""
        if not threat_data:
            return 0.0
        
        total_severity = 0.0
        threat_count = len(threat_data)
        
        for threat_id, threat in threat_data.items():
            severity = threat.get("severity", 0.0)
            confidence = threat.get("confidence", 0.8)
            total_severity += severity * confidence
        
        return min(total_severity / threat_count if threat_count > 0 else 0.0, 1.0)
    
    def _determine_situation_level(self, score: float) -> SituationLevel:
        """确定安全态势级别"""
        if score >= 0.9:
            return SituationLevel.CRITICAL
        elif score >= 0.7:
            return SituationLevel.HIGH_RISK
        elif score >= 0.4:
            return SituationLevel.MEDIUM_RISK
        elif score >= 0.1:
            return SituationLevel.LOW_RISK
        else:
            return SituationLevel.SAFE
    
    def _collect_active_threats(self, threat_data: Dict[str, Any]) -> List[ThreatType]:
        """收集活跃威胁类型"""
        threat_types = set()
        for threat_id, threat in threat_data.items():
            try:
                threat_type = ThreatType(threat.get("threat_type"))
                threat_types.add(threat_type)
            except ValueError:
                continue
        
        return list(threat_types)
    
    def _collect_affected_nodes(self, threat_data: Dict[str, Any]) -> List[str]:
        """收集受影响节点"""
        affected_nodes = set()
        for threat_id, threat in threat_data.items():
            node_id = threat.get("node_id")
            if node_id:
                affected_nodes.add(node_id)
        
        return list(affected_nodes)
    
    def _generate_situation_description(self, level: SituationLevel, threat_count: int, affected_nodes: int) -> str:
        """生成态势描述"""
        if level == SituationLevel.SAFE:
            return "System is in safe state"
        elif level == SituationLevel.LOW_RISK:
            return f"Low risk situation with {threat_count} threats affecting {affected_nodes} nodes"
        elif level == SituationLevel.MEDIUM_RISK:
            return f"Medium risk situation with {threat_count} threats affecting {affected_nodes} nodes"
        elif level == SituationLevel.HIGH_RISK:
            return f"High risk situation with {threat_count} threats affecting {affected_nodes} nodes - immediate attention needed"
        else:  # CRITICAL
            return f"CRITICAL situation with {threat_count} threats affecting {affected_nodes} nodes - emergency response required"
    
    def detect_threats(self, node_data: Dict[str, Any], operation_data: Dict[str, Any]) -> List[ThreatDetection]:
        """检测威胁"""
        threats = []
        
        # 检测恶意代理
        threats.extend(self._detect_malicious_agents(node_data))
        
        # 检测异常行为
        threats.extend(self._detect_abnormal_behavior(operation_data))
        
        # 检测配置违规
        threats.extend(self._detect_configuration_violations(node_data))
        
        # 检测网络攻击
        threats.extend(self._detect_network_attacks(node_data))
        
        # 存储威胁检测结果
        self.threat_detections.extend(threats)
        
        return threats
    
    def _detect_malicious_agents(self, node_data: Dict[str, Any]) -> List[ThreatDetection]:
        """检测恶意代理"""
        threats = []
        
        for node_id, data in node_data.items():
            trust_score = data.get("trust_score", 0.0)
            validation_status = data.get("validation_status", "valid")
            
            if trust_score < 0.3 or validation_status == "invalid":
                threat = ThreatDetection(
                    threat_type=ThreatType.MALICIOUS_AGENT,
                    node_id=node_id,
                    severity=1.0 - trust_score,
                    confidence=0.95,
                    details={
                        "trust_score": trust_score,
                        "validation_status": validation_status
                    }
                )
                threats.append(threat)
        
        return threats
    
    def _detect_abnormal_behavior(self, operation_data: Dict[str, Any]) -> List[ThreatDetection]:
        """检测异常行为"""
        threats = []
        
        for operation in operation_data:
            if operation.get("status") == "blocked" or operation.get("risk_level") == "high":
                threat = ThreatDetection(
                    threat_type=ThreatType.ABnormal_BEHAVIOR,
                    node_id=operation.get("node_id", ""),
                    severity=0.8,
                    confidence=0.85,
                    details={
                        "operation_type": operation.get("operation_type"),
                        "target_resource": operation.get("target_resource"),
                        "status": operation.get("status")
                    }
                )
                threats.append(threat)
        
        return threats
    
    def _detect_configuration_violations(self, node_data: Dict[str, Any]) -> List[ThreatDetection]:
        """检测配置违规"""
        threats = []
        
        for node_id, data in node_data.items():
            if not data.get("configuration_valid", True):
                threat = ThreatDetection(
                    threat_type=ThreatType.CONFIGURATION_VIOLATION,
                    node_id=node_id,
                    severity=0.6,
                    confidence=0.9,
                    details={
                        "invalid_configurations": data.get("invalid_configurations", [])
                    }
                )
                threats.append(threat)
        
        return threats
    
    def _detect_network_attacks(self, node_data: Dict[str, Any]) -> List[ThreatDetection]:
        """检测网络攻击"""
        threats = []
        
        for node_id, data in node_data.items():
            network_stats = data.get("network_stats", {})
            if network_stats.get("connection_attempts", 0) > 1000 or network_stats.get("failed_connections", 0) > 500:
                threat = ThreatDetection(
                    threat_type=ThreatType.NETWORK_ATTACK,
                    node_id=node_id,
                    severity=0.9,
                    confidence=0.8,
                    details={
                        "connection_attempts": network_stats.get("connection_attempts"),
                        "failed_connections": network_stats.get("failed_connections")
                    }
                )
                threats.append(threat)
        
        return threats
    
    def get_situation_analysis(self) -> Dict[str, Any]:
        """获取态势分析报告"""
        if not self.situation_history:
            return {"error": "No situation data available"}
        
        current = self.current_situation
        history = self.get_situation_history()
        
        return {
            "current": {
                "level": current.level.value,
                "score": current.threat_score,
                "threat_count": len(current.active_threats),
                "affected_nodes": len(current.affected_nodes),
                "description": current.description
            },
            "history": [
                {
                    "timestamp": s.timestamp.isoformat(),
                    "level": s.level.value,
                    "score": s.threat_score,
                    "threat_count": len(s.active_threats),
                    "affected_nodes": len(s.affected_nodes)
                } for s in history
            ],
            "statistics": self._get_situation_statistics()
        }
    
    def _get_situation_statistics(self) -> Dict[str, Any]:
        """获取态势统计信息"""
        level_counts = {level.value: 0 for level in SituationLevel}
        
        for situation in self.situation_history:
            level_counts[situation.level.value] += 1
        
        total = len(self.situation_history)
        duration = self.situation_history[-1].timestamp - self.situation_history[0].timestamp
        
        return {
            "level_distribution": level_counts,
            "total_situations": total,
            "duration_hours": duration.total_seconds() / 3600,
            "average_duration_per_level": {
                level: (count / total) * duration.total_seconds() / 3600
                for level, count in level_counts.items()
            }
        }
    
    def get_situation_history(self, start_time: datetime = None, end_time: datetime = None) -> List[SecuritySituation]:
        """获取态势历史记录"""
        history = self.situation_history
        
        if start_time:
            history = [s for s in history if s.timestamp >= start_time]
        
        if end_time:
            history = [s for s in history if s.timestamp <= end_time]
        
        return history
    
    def get_active_threats(self) -> List[ThreatDetection]:
        """获取活跃威胁"""
        # 只返回最近 5 分钟内的威胁
        five_minutes_ago = datetime.now() - datetime.timedelta(minutes=5)
        return [threat for threat in self.threat_detections if threat.timestamp >= five_minutes_ago]
    
    def generate_situation_report(self) -> Dict[str, Any]:
        """生成安全态势报告"""
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat(),
            "period": {
                "start": self.situation_history[0].timestamp.isoformat(),
                "end": self.situation_history[-1].timestamp.isoformat()
            },
            "current_situation": {
                "level": self.current_situation.level.value,
                "score": self.current_situation.threat_score,
                "threat_count": len(self.current_situation.active_threats),
                "affected_nodes": len(self.current_situation.affected_nodes)
            },
            "threat_summary": {
                "total_threats": len(self.threat_detections),
                "critical_threats": len([t for t in self.threat_detections if t.is_high_severity]),
                "active_threats": len(self.get_active_threats())
            },
            "node_analysis": {
                "total_nodes": len({s.affected_nodes for s in self.situation_history}),
                "affected_nodes": list({node for s in self.situation_history for node in s.affected_nodes}),
                "affected_node_count": len({node for s in self.situation_history for node in s.affected_nodes})
            },
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """生成安全建议"""
        recommendations = []
        
        level = self.current_situation.level
        
        if level == SituationLevel.CRITICAL:
            recommendations.append("Immediately isolate affected nodes")
            recommendations.append("Deploy emergency response protocols")
            recommendations.append("Notify security operations center")
        elif level == SituationLevel.HIGH_RISK:
            recommendations.append("Monitor affected nodes closely")
            recommendations.append("Assess potential impact")
            recommendations.append("Prepare for escalation")
        elif level == SituationLevel.MEDIUM_RISK:
            recommendations.append("Investigate suspicious activities")
            recommendations.append("Review security logs")
            recommendations.append("Update security policies")
        elif level == SituationLevel.LOW_RISK:
            recommendations.append("Monitor system behavior")
            recommendations.append("Review access control settings")
        else:  # SAFE
            recommendations.append("Maintain current security posture")
        
        return recommendations