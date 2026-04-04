"""
安全事件溯源模块
负责对安全事件进行全面溯源和分析
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import uuid
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """事件严重程度枚举"""
    INFO = "info"  # 信息
    WARNING = "warning"  # 警告
    ERROR = "error"  # 错误
    CRITICAL = "critical"  # 严重


class IncidentStatus(Enum):
    """事件状态枚举"""
    DETECTED = "detected"  # 已检测
    INVESTIGATING = "investigating"  # 调查中
    CONFIRMED = "confirmed"  # 已确认
    MITIGATED = "mitigated"  # 已缓解
    RESOLVED = "resolved"  # 已解决


@dataclass
class Incident:
    """安全事件"""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: IncidentSeverity = IncidentSeverity.WARNING
    status: IncidentStatus = IncidentStatus.DETECTED
    detected_at: datetime = field(default_factory=datetime.now)
    confirmed_at: Optional[datetime] = None
    mitigated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    description: str = ""
    affected_nodes: List[str] = field(default_factory=list)
    root_cause: Optional[str] = None
    resolution_steps: List[str] = field(default_factory=list)
    evidence: Dict = field(default_factory=dict)
    related_incidents: List[str] = field(default_factory=list)
    assignee: str = ""
    comments: List[str] = field(default_factory=list)
    
    def update_status(self, new_status: IncidentStatus) -> None:
        """更新事件状态"""
        self.status = new_status
        
        if new_status == IncidentStatus.CONFIRMED and not self.confirmed_at:
            self.confirmed_at = datetime.now()
        elif new_status == IncidentStatus.MITIGATED and not self.mitigated_at:
            self.mitigated_at = datetime.now()
        elif new_status == IncidentStatus.RESOLVED and not self.resolved_at:
            self.resolved_at = datetime.now()
        
        logger.info(f"Incident {self.incident_id} status updated to {new_status.value}")
    
    def add_comment(self, comment: str, author: str = "system") -> None:
        """添加评论"""
        self.comments.append(f"{datetime.now().isoformat()} - {author}: {comment}")
        logger.info(f"Comment added to incident {self.incident_id}")
    
    def add_evidence(self, evidence_type: str, content: Any) -> None:
        """添加证据"""
        if evidence_type not in self.evidence:
            self.evidence[evidence_type] = []
        self.evidence[evidence_type].append(content)
        logger.info(f"Evidence added to incident {self.incident_id}")
    
    def get_duration(self) -> float:
        """获取事件持续时间（小时）"""
        if self.resolved_at and self.detected_at:
            return (self.resolved_at - self.detected_at).total_seconds() / 3600
        elif self.mitigated_at and self.detected_at:
            return (self.mitigated_at - self.detected_at).total_seconds() / 3600
        elif self.confirmed_at and self.detected_at:
            return (self.confirmed_at - self.detected_at).total_seconds() / 3600
        else:
            return 0.0


@dataclass
class TraceNode:
    """溯源节点"""
    node_id: str
    event_type: str
    timestamp: datetime
    details: Dict = field(default_factory=dict)
    related_nodes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "node_id": self.node_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "related_nodes": self.related_nodes
        }


@dataclass
class IncidentTrace:
    """事件溯源"""
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    nodes: List[TraceNode] = field(default_factory=list)
    timeline: List[Tuple[datetime, str]] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    root_cause_analysis: Dict = field(default_factory=dict)


class IncidentTracingManager:
    """事件溯源管理器"""
    
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}
        self.traces: Dict[str, IncidentTrace] = {}
        self.incident_count: int = 0
        self.active_incidents: List[Incident] = []
    
    def create_incident(self, description: str, severity: IncidentSeverity = IncidentSeverity.WARNING) -> Incident:
        """创建事件"""
        incident = Incident(
            severity=severity,
            description=description
        )
        
        self.incidents[incident.incident_id] = incident
        self.incident_count += 1
        self.active_incidents.append(incident)
        
        logger.info(f"Incident created: {incident.incident_id}")
        return incident
    
    def investigate_incident(self, incident_id: str, evidence: Dict) -> IncidentTrace:
        """调查事件"""
        if incident_id not in self.incidents:
            logger.error(f"Incident {incident_id} not found")
            return
        
        incident = self.incidents[incident_id]
        incident.update_status(IncidentStatus.INVESTIGATING)
        
        # 创建溯源
        trace = IncidentTrace(
            incident_id=incident_id,
            affected_components=incident.affected_nodes
        )
        
        # 分析证据
        self._analyze_evidence(incident, evidence, trace)
        
        # 构建事件时间线
        self._build_timeline(incident, trace)
        
        # 存储溯源
        self.traces[incident_id] = trace
        
        logger.info(f"Incident investigation completed: {incident_id}")
        return trace
    
    def _analyze_evidence(self, incident: Incident, evidence: Dict, trace: IncidentTrace) -> None:
        """分析证据"""
        for evidence_type, content in evidence.items():
            incident.add_evidence(evidence_type, content)
            
            # 根据证据类型创建溯源节点
            if evidence_type == "audit_logs":
                self._analyze_audit_logs(content, trace)
            elif evidence_type == "network_traffic":
                self._analyze_network_traffic(content, trace)
            elif evidence_type == "system_logs":
                self._analyze_system_logs(content, trace)
            elif evidence_type == "user_activities":
                self._analyze_user_activities(content, trace)
            else:
                logger.warning(f"Unknown evidence type: {evidence_type}")
    
    def _analyze_audit_logs(self, logs: List[Dict], trace: IncidentTrace) -> None:
        """分析审计日志"""
        for log in logs:
            node = TraceNode(
                node_id=log.get("node_id", "unknown"),
                event_type=log.get("event_type", "audit_event"),
                timestamp=log.get("timestamp", datetime.now()),
                details=log,
                related_nodes=log.get("related_nodes", [])
            )
            trace.nodes.append(node)
            trace.timeline.append((node.timestamp, node.event_type))
    
    def _analyze_network_traffic(self, traffic: List[Dict], trace: IncidentTrace) -> None:
        """分析网络流量"""
        for entry in traffic:
            node = TraceNode(
                node_id=entry.get("source_ip", "unknown"),
                event_type="network_traffic",
                timestamp=entry.get("timestamp", datetime.now()),
                details=entry,
                related_nodes=[entry.get("destination_ip")] if entry.get("destination_ip") else []
            )
            trace.nodes.append(node)
            trace.timeline.append((node.timestamp, "Network traffic"))
    
    def _analyze_system_logs(self, logs: List[Dict], trace: IncidentTrace) -> None:
        """分析系统日志"""
        for log in logs:
            node = TraceNode(
                node_id=log.get("hostname", "unknown"),
                event_type=log.get("level", "system_event"),
                timestamp=log.get("timestamp", datetime.now()),
                details=log,
                related_nodes=log.get("related_processes", [])
            )
            trace.nodes.append(node)
            trace.timeline.append((node.timestamp, node.event_type))
    
    def _analyze_user_activities(self, activities: List[Dict], trace: IncidentTrace) -> None:
        """分析用户活动"""
        for activity in activities:
            node = TraceNode(
                node_id=activity.get("username", "unknown"),
                event_type=activity.get("action", "user_activity"),
                timestamp=activity.get("timestamp", datetime.now()),
                details=activity,
                related_nodes=activity.get("affected_nodes", [])
            )
            trace.nodes.append(node)
            trace.timeline.append((node.timestamp, node.event_type))
    
    def _build_timeline(self, incident: Incident, trace: IncidentTrace) -> None:
        """构建事件时间线"""
        timeline = []
        
        # 排序时间线事件
        trace.timeline = sorted(trace.timeline, key=lambda x: x[0])
        
        for timestamp, event in trace.timeline:
            timeline.append(f"{timestamp.isoformat()} - {event}")
        
        incident.resolution_steps.append("Timeline created: " + " → ".join(timeline))
    
    def confirm_incident(self, incident_id: str, root_cause: str, affected_nodes: List[str]) -> Incident:
        """确认事件"""
        if incident_id not in self.incidents:
            logger.error(f"Incident {incident_id} not found")
            return
        
        incident = self.incidents[incident_id]
        incident.update_status(IncidentStatus.CONFIRMED)
        incident.root_cause = root_cause
        incident.affected_nodes.extend(affected_nodes)
        incident.add_comment(f"Root cause identified: {root_cause}", "investigator")
        
        logger.info(f"Incident confirmed: {incident_id}")
        return incident
    
    def mitigate_incident(self, incident_id: str, mitigation_steps: List[str]) -> Incident:
        """缓解事件"""
        if incident_id not in self.incidents:
            logger.error(f"Incident {incident_id} not found")
            return
        
        incident = self.incidents[incident_id]
        incident.update_status(IncidentStatus.MITIGATED)
        incident.resolution_steps.extend(mitigation_steps)
        
        for step in mitigation_steps:
            incident.add_comment(f"Mitigation step: {step}", "response_team")
        
        logger.info(f"Incident mitigated: {incident_id}")
        return incident
    
    def resolve_incident(self, incident_id: str, resolution_summary: str) -> Incident:
        """解决事件"""
        if incident_id not in self.incidents:
            logger.error(f"Incident {incident_id} not found")
            return
        
        incident = self.incidents[incident_id]
        incident.update_status(IncidentStatus.RESOLVED)
        incident.add_comment(resolution_summary, "resolution_team")
        
        self.active_incidents.remove(incident)
        
        logger.info(f"Incident resolved: {incident_id}")
        return incident
    
    def get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """获取事件详细信息"""
        if incident_id not in self.incidents:
            return {"error": "Incident not found"}
        
        incident = self.incidents[incident_id]
        trace = self.traces.get(incident_id, None)
        
        details = {
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "detected_at": incident.detected_at.isoformat(),
            "confirmed_at": incident.confirmed_at.isoformat() if incident.confirmed_at else None,
            "mitigated_at": incident.mitigated_at.isoformat() if incident.mitigated_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "description": incident.description,
            "affected_nodes": incident.affected_nodes,
            "root_cause": incident.root_cause,
            "assignee": incident.assignee,
            "duration": incident.get_duration(),
            "comments": incident.comments,
            "resolution_steps": incident.resolution_steps
        }
        
        if trace:
            details["trace"] = {
                "nodes": [node.to_dict() for node in trace.nodes],
                "timeline": [
                    {"timestamp": t.isoformat(), "event": e} for t, e in trace.timeline
                ],
                "affected_components": trace.affected_components
            }
        
        return details
    
    def get_incident_list(self, severity: IncidentSeverity = None, status: IncidentStatus = None) -> List[Dict]:
        """获取事件列表"""
        incidents = list(self.incidents.values())
        
        if severity:
            incidents = [inc for inc in incidents if inc.severity == severity]
        
        if status:
            incidents = [inc for inc in incidents if inc.status == status]
        
        return [
            {
                "incident_id": inc.incident_id,
                "severity": inc.severity.value,
                "status": inc.status.value,
                "detected_at": inc.detected_at.isoformat(),
                "affected_nodes": inc.affected_nodes,
                "description": inc.description
            }
            for inc in incidents
        ]
    
    def get_incident_statistics(self) -> Dict[str, Any]:
        """获取事件统计信息"""
        severity_counts: Dict[IncidentSeverity, int] = {s: 0 for s in IncidentSeverity}
        status_counts: Dict[IncidentStatus, int] = {s: 0 for s in IncidentStatus}
        
        for inc in self.incidents.values():
            severity_counts[inc.severity] += 1
            status_counts[inc.status] += 1
        
        return {
            "total_incidents": len(self.incidents),
            "active_incidents": len(self.active_incidents),
            "severity_distribution": {s.value: c for s, c in severity_counts.items()},
            "status_distribution": {s.value: c for s, c in status_counts.items()},
            "incident_types": self._get_incident_types(),
            "average_resolution_time": self._get_average_resolution_time()
        }
    
    def _get_incident_types(self) -> Dict[str, int]:
        """获取事件类型统计"""
        types = {}
        
        for inc in self.incidents.values():
            description = inc.description.lower()
            for type_keyword in ["malicious", "attack", "configuration", "resource", "network"]:
                if type_keyword in description:
                    if type_keyword not in types:
                        types[type_keyword] = 0
                    types[type_keyword] += 1
        
        return types
    
    def _get_average_resolution_time(self) -> float:
        """获取平均解决时间"""
        resolved_incidents = [inc for inc in self.incidents.values() if inc.status == IncidentStatus.RESOLVED]
        
        if not resolved_incidents:
            return 0.0
        
        total_time = sum(inc.get_duration() for inc in resolved_incidents)
        return total_time / len(resolved_incidents)
    
    def search_incidents(self, search_query: str) -> List[Dict]:
        """搜索事件"""
        results = []
        
        for inc in self.incidents.values():
            if search_query.lower() in inc.description.lower() or search_query in inc.affected_nodes:
                results.append({
                    "incident_id": inc.incident_id,
                    "severity": inc.severity.value,
                    "status": inc.status.value,
                    "detected_at": inc.detected_at.isoformat(),
                    "description": inc.description
                })
        
        return results
    
    def generate_incident_report(self) -> Dict[str, Any]:
        """生成事件报告"""
        stats = self.get_incident_statistics()
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat(),
            "statistics": stats,
            "incidents": self.get_incident_list(),
            "top_incidents": self._get_top_incidents(),
            "recommendations": self._generate_recommendations(stats)
        }
        
        return report
    
    def _get_top_incidents(self) -> List[Dict]:
        """获取主要事件"""
        critical_incidents = [inc for inc in self.incidents.values() if inc.severity == IncidentSeverity.CRITICAL]
        
        return [
            {
                "incident_id": inc.incident_id,
                "severity": inc.severity.value,
                "description": inc.description,
                "detected_at": inc.detected_at.isoformat(),
                "affected_nodes": inc.affected_nodes
            }
            for inc in critical_incidents
        ]
    
    def _generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """生成建议"""
        recommendations = []
        
        if stats["active_incidents"] > 0:
            recommendations.append("Prioritize mitigation of active incidents")
        
        if stats["severity_distribution"]["critical"] > 0:
            recommendations.append("Address critical severity incidents immediately")
        
        if stats.get("average_resolution_time", 0) > 24:
            recommendations.append("Improve incident response time")
        
        return recommendations