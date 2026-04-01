"""
安全审计模块
记录所有访问请求和决策过程，生成审计报告
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime
import uuid
from enum import Enum

from ..models.agent import Agent
from ..models.access_request import AccessRequest, AccessDecision, DecisionOutcome


class AuditEventType(Enum):
    """审计事件类型枚举"""
    ACCESS_REQUEST = "access_request"
    ACCESS_ALLOWED = "access_allowed"
    ACCESS_DENIED = "access_denied"
    ACCESS_CHALLENGED = "access_challenged"
    TRUST_UPDATE = "trust_update"
    AGENT_STATE_CHANGE = "agent_state_change"
    SCHEMA_UPDATE = "schema_update"
    EXCEPTION = "exception"


@dataclass
class AuditEvent:
    """审计事件表示"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType = AuditEventType.ACCESS_REQUEST
    timestamp: datetime = field(default_factory=datetime.now)
    source_agent_id: str = ""
    target_agent_id: str = ""
    request_id: str = ""
    decision: Optional[DecisionOutcome] = None
    trust_score: float = 0.0
    alignment_score: float = 0.0
    reason: str = ""
    metadata: Dict = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """判断事件是否成功"""
        return self.event_type in [AuditEventType.ACCESS_ALLOWED, AuditEventType.TRUST_UPDATE, AuditEventType.SCHEMA_UPDATE]
    
    @property
    def severity(self) -> str:
        """判断事件严重程度"""
        if self.event_type == AuditEventType.EXCEPTION or self.event_type == AuditEventType.ACCESS_DENIED:
            return "high"
        elif self.event_type == AuditEventType.ACCESS_CHALLENGED or self.event_type == AuditEventType.AGENT_STATE_CHANGE:
            return "medium"
        else:
            return "low"


class AuditManager:
    """安全审计管理类"""
    
    def __init__(self):
        # 审计事件存储
        self.audit_events: List[AuditEvent] = []
        # 异常行为检测规则
        self.anomaly_rules: Dict = {}
        # 审计报告配置
        self.report_config: Dict = {
            "include_trust_details": True,
            "include_alignment_details": True,
            "include_metadata": False
        }
        # 敏感字段列表 - 这些字段会被脱敏
        self.sensitive_fields = {
            'token', 'secret', 'password', 'key', 'api_key', 'credential', 
            'auth', 'private', 'signature', 'cookie'
        }
    
    def _desensitize(self, metadata: Dict) -> Dict:
        """对metadata中的敏感字段进行脱敏，符合等保要求"""
        if not metadata:
            return {}
        
        result = {}
        for key, value in metadata.items():
            if any(s in key.lower() for s in self.sensitive_fields):
                # 敏感字段替换为***
                result[key] = '***'
            elif isinstance(value, dict):
                result[key] = self._desensitize(value)
            else:
                result[key] = value
        return result
    
    def log_access_request(self, request: AccessRequest) -> AuditEvent:
        """记录访问请求 - 自动脱敏敏感字段"""
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_REQUEST,
            source_agent_id=request.requester_id,
            target_agent_id=request.target_id,
            request_id=request.request_id,
            metadata=self._desensitize(request.context)
        )
        self.audit_events.append(event)
        return event
    
    def log_access_decision(self, decision: AccessDecision) -> AuditEvent:
        """记录访问决策 - 自动脱敏敏感字段"""
        event_type = AuditEventType.ACCESS_ALLOWED
        if decision.outcome == DecisionOutcome.DENY:
            event_type = AuditEventType.ACCESS_DENIED
        elif decision.outcome == DecisionOutcome.CHALLENGE:
            event_type = AuditEventType.ACCESS_CHALLENGED
        
        event = AuditEvent(
            event_type=event_type,
            source_agent_id=decision.request.requester_id,
            target_agent_id=decision.request.target_id,
            request_id=decision.request.request_id,
            decision=decision.outcome,
            trust_score=decision.trust_score,
            alignment_score=decision.alignment_score,
            reason=decision.reason,
            metadata=self._desensitize(decision.request.context)
        )
        self.audit_events.append(event)
        return event
    
    def log_trust_update(self, source_agent_id: str, target_agent_id: str, old_score: float, new_score: float) -> AuditEvent:
        """记录信任更新"""
        event = AuditEvent(
            event_type=AuditEventType.TRUST_UPDATE,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            trust_score=new_score,
            reason=f"Trust updated from {old_score:.3f} to {new_score:.3f}",
            metadata={"old_score": old_score, "new_score": new_score}
        )
        self.audit_events.append(event)
        return event
    
    def log_agent_state_change(self, agent_id: str, old_state: str, new_state: str) -> AuditEvent:
        """记录代理状态变更"""
        event = AuditEvent(
            event_type=AuditEventType.AGENT_STATE_CHANGE,
            source_agent_id=agent_id,
            reason=f"State changed from {old_state} to {new_state}",
            metadata={"old_state": old_state, "new_state": new_state}
        )
        self.audit_events.append(event)
        return event
    
    def log_exception(self, exception: Exception, context: Dict = None) -> AuditEvent:
        """记录异常事件"""
        event = AuditEvent(
            event_type=AuditEventType.EXCEPTION,
            reason=str(exception),
            metadata=context or {}
        )
        self.audit_events.append(event)
        return event
    
    def log_schema_update(self, schema_id: str, changes: Dict) -> AuditEvent:
        """记录安全基模更新"""
        event = AuditEvent(
            event_type=AuditEventType.SCHEMA_UPDATE,
            reason=f"Schema {schema_id} updated",
            metadata=changes
        )
        self.audit_events.append(event)
        return event
    
    def get_audit_events(self, agent_id: Optional[str] = None, event_type: Optional[AuditEventType] = None, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> List[AuditEvent]:
        """获取审计事件"""
        events = self.audit_events
        
        if agent_id:
            events = [e for e in events if e.source_agent_id == agent_id or e.target_agent_id == agent_id]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        return events
    
    def generate_audit_report(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> Dict:
        """生成审计报告"""
        events = self.get_audit_events(start_time=start_time, end_time=end_time)
        
        total_events = len(events)
        successful_events = len([e for e in events if e.is_success])
        high_severity_events = len([e for e in events if e.severity == "high"])
        medium_severity_events = len([e for e in events if e.severity == "medium"])
        low_severity_events = len([e for e in events if e.severity == "low"])
        
        report = {
            "report_id": str(uuid.uuid4()),
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_events": total_events,
                "successful_events": successful_events,
                "success_rate": successful_events / total_events if total_events > 0 else 0.0,
                "high_severity_events": high_severity_events,
                "medium_severity_events": medium_severity_events,
                "low_severity_events": low_severity_events
            },
            "events": events
        }
        
        return report
    
    def detect_abnormal_behavior(self, agent_id: str, time_window: int = 3600) -> List[AuditEvent]:
        """检测异常行为"""
        end_time = datetime.now()
        start_time = end_time - datetime.timedelta(seconds=time_window)
        
        events = self.get_audit_events(agent_id=agent_id, start_time=start_time, end_time=end_time)
        
        # 异常行为检测规则
        abnormal_events = []
        
        # 1. 大量拒绝访问请求
        denied_events = [e for e in events if e.event_type == AuditEventType.ACCESS_DENIED]
        if len(denied_events) > 10:
            abnormal_events.extend(denied_events)
        
        # 2. 信任评分快速下降
        trust_events = [e for e in events if e.event_type == AuditEventType.TRUST_UPDATE and e.trust_score < 0.5]
        if len(trust_events) > 5:
            abnormal_events.extend(trust_events)
        
        # 3. 状态频繁变化
        state_events = [e for e in events if e.event_type == AuditEventType.AGENT_STATE_CHANGE]
        if len(state_events) > 3:
            abnormal_events.extend(state_events)
        
        return list(set(abnormal_events))
    
    def get_statistics(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> Dict:
        """获取统计信息"""
        events = self.get_audit_events(start_time=start_time, end_time=end_time)
        
        return {
            "total_requests": len([e for e in events if e.event_type == AuditEventType.ACCESS_REQUEST]),
            "allowed_requests": len([e for e in events if e.event_type == AuditEventType.ACCESS_ALLOWED]),
            "denied_requests": len([e for e in events if e.event_type == AuditEventType.ACCESS_DENIED]),
            "challenged_requests": len([e for e in events if e.event_type == AuditEventType.ACCESS_CHALLENGED]),
            "trust_updates": len([e for e in events if e.event_type == AuditEventType.TRUST_UPDATE]),
            "agent_state_changes": len([e for e in events if e.event_type == AuditEventType.AGENT_STATE_CHANGE]),
            "exceptions": len([e for e in events if e.event_type == AuditEventType.EXCEPTION])
        }
