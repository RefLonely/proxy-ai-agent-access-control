"""
安全审计模块
记录所有访问请求和决策过程，生成审计报告
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import uuid
from enum import Enum

from ..models.agent import Agent
from ..models.access_request import AccessRequest, AccessDecision, DecisionOutcome


class AuditEventType(Enum):
    """
    审计事件类型枚举
    
    定义了安全审计系统需要记录的各类事件类型。
    """
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
    """
    审计事件表示
    
    存储单个审计事件的完整信息，包括事件ID、时间戳、相关代理、
    决策结果、信任评分、对齐评分等。
    
    Attributes:
        event_id: 事件唯一标识符
        event_type: 事件类型
        timestamp: 事件时间戳
        source_agent_id: 源代理ID
        target_agent_id: 目标代理ID
        request_id: 访问请求ID
        decision: 访问决策结果
        trust_score: 信任评分
        alignment_score: 安全对齐评分
        reason: 决策原因说明
        metadata: 附加元数据
    """
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
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """判断事件是否成功"""
        return self.event_type in [
            AuditEventType.ACCESS_ALLOWED,
            AuditEventType.TRUST_UPDATE,
            AuditEventType.SCHEMA_UPDATE
        ]
    
    @property
    def severity(self) -> str:
        """判断事件严重程度
        
        Returns:
            "high" - 高严重性，"medium" - 中严重性，"low" - 低严重性
        """
        if self.event_type == AuditEventType.EXCEPTION or self.event_type == AuditEventType.ACCESS_DENIED:
            return "high"
        elif self.event_type == AuditEventType.ACCESS_CHALLENGED or self.event_type == AuditEventType.AGENT_STATE_CHANGE:
            return "medium"
        else:
            return "low"


class AuditManager:
    """
    安全审计管理类
    
    记录所有访问请求和决策过程，支持查询、统计和异常行为检测，
    生成符合等保要求的审计报告。对敏感信息自动脱敏。
    """
    
    def __init__(self) -> None:
        """初始化审计管理器"""
        # 审计事件存储
        self.audit_events: List[AuditEvent] = []
        # 异常行为检测规则
        self.anomaly_rules: Dict[str, Any] = {}
        # 审计报告配置
        self.report_config: Dict[str, Any] = {
            "include_trust_details": True,
            "include_alignment_details": True,
            "include_metadata": False
        }
        # 敏感字段列表 - 这些字段会被脱敏
        self.sensitive_fields = {
            'token', 'secret', 'password', 'key', 'api_key', 'credential',
            'auth', 'private', 'signature', 'cookie'
        }
    
    def _desensitize(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        对metadata中的敏感字段进行脱敏，符合等保要求
        
        递归处理嵌套字典，将包含敏感关键词的字段值替换为***。
        
        Args:
            metadata: 原始元数据字典
        
        Returns:
            脱敏后的元数据字典
        """
        if not metadata:
            return {}
        
        result: Dict[str, Any] = {}
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
        """
        记录访问请求 - 自动脱敏敏感字段
        
        Args:
            request: 访问请求对象
        
        Returns:
            创建的审计事件
        """
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
        """
        记录访问决策 - 自动脱敏敏感字段
        
        根据决策结果确定事件类型。
        
        Args:
            decision: 访问决策对象
        
        Returns:
            创建的审计事件
        """
        event_type = AuditEventType.ACCESS_ALLOWED
        if decision.outcome == DecisionOutcome.DENY:
            event_type = AuditEventType.ACCESS_DENIED
        elif decision.outcome == DecisionOutcome.CHALLENGE:
            event_type = AuditEventType.ACCESS_CHALLENGED
        elif decision.outcome == DecisionOutcome.LIMIT:
            event_type = AuditEventType.ACCESS_CHALLENGED
        elif decision.outcome == DecisionOutcome.ISOLATE:
            event_type = AuditEventType.ACCESS_DENIED
        
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
    
    def log_trust_update(
        self,
        source_agent_id: str,
        target_agent_id: str,
        old_score: float,
        new_score: float
    ) -> AuditEvent:
        """
        记录信任更新
        
        Args:
            source_agent_id: 源代理ID
            target_agent_id: 目标代理ID
            old_score: 更新前信任评分
            new_score: 更新后信任评分
        
        Returns:
            创建的审计事件
        """
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
    
    def log_agent_state_change(
        self,
        agent_id: str,
        old_state: str,
        new_state: str
    ) -> AuditEvent:
        """
        记录代理状态变更
        
        Args:
            agent_id: 代理ID
            old_state: 变更前状态
            new_state: 变更后状态
        
        Returns:
            创建的审计事件
        """
        event = AuditEvent(
            event_type=AuditEventType.AGENT_STATE_CHANGE,
            source_agent_id=agent_id,
            reason=f"State changed from {old_state} to {new_state}",
            metadata={"old_state": old_state, "new_state": new_state}
        )
        self.audit_events.append(event)
        return event
    
    def log_exception(
        self,
        exception: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """
        记录异常事件
        
        Args:
            exception: 异常对象
            context: 异常上下文信息
        
        Returns:
            创建的审计事件
        """
        event = AuditEvent(
            event_type=AuditEventType.EXCEPTION,
            reason=str(exception),
            metadata=context or {}
        )
        self.audit_events.append(event)
        return event
    
    def log_schema_update(self, schema_id: str, changes: Dict[str, Any]) -> AuditEvent:
        """
        记录安全基模更新
        
        Args:
            schema_id: 安全基模ID
            changes: 变更内容
        
        Returns:
            创建的审计事件
        """
        event = AuditEvent(
            event_type=AuditEventType.SCHEMA_UPDATE,
            reason=f"Schema {schema_id} updated",
            metadata=changes
        )
        self.audit_events.append(event)
        return event
    
    def get_audit_events(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[AuditEvent]:
        """
        获取审计事件，支持多种条件过滤
        
        Args:
            agent_id: 过滤指定代理的事件
            event_type: 过滤指定事件类型
            start_time: 过滤此时间之后的事件
            end_time: 过滤此时间之前的事件
        
        Returns:
            符合条件的审计事件列表
        """
        events = self.audit_events
        
        if agent_id:
            events = [
                e for e in events
                if e.source_agent_id == agent_id or e.target_agent_id == agent_id
            ]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        
        return events
    
    def generate_audit_report(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        生成审计报告
        
        包含统计信息和事件列表，符合等保审计要求。
        
        Args:
            start_time: 报告起始时间
            end_time: 报告结束时间
        
        Returns:
            审计报告字典，包含摘要和事件列表
        """
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
    
    def detect_abnormal_behavior(
        self,
        agent_id: str,
        time_window: int = 3600
    ) -> List[AuditEvent]:
        """
        检测异常行为
        
        在指定时间窗口内检测：
        1. 大量拒绝访问请求
        2. 多次信任评分快速下降
        3. 频繁的状态变化
        
        Args:
            agent_id: 代理ID
            time_window: 时间窗口大小（秒），默认3600秒（1小时）
        
        Returns:
            检测到的异常事件列表
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(seconds=time_window)
        
        events = self.get_audit_events(
            agent_id=agent_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # 异常行为检测结果
        abnormal_events: List[AuditEvent] = []
        
        # 1. 大量拒绝访问请求 (超过10次)
        denied_events = [e for e in events if e.event_type == AuditEventType.ACCESS_DENIED]
        if len(denied_events) > 10:
            abnormal_events.extend(denied_events)
        
        # 2. 信任评分快速下降 (低于0.5超过5次)
        trust_events = [
            e for e in events
            if e.event_type == AuditEventType.TRUST_UPDATE and e.trust_score < 0.5
        ]
        if len(trust_events) > 5:
            abnormal_events.extend(trust_events)
        
        # 3. 状态频繁变化 (超过3次)
        state_events = [e for e in events if e.event_type == AuditEventType.AGENT_STATE_CHANGE]
        if len(state_events) > 3:
            abnormal_events.extend(state_events)
        
        # 去重
        seen = set()
        result = []
        for event in abnormal_events:
            if event.event_id not in seen:
                seen.add(event.event_id)
                result.append(event)
        
        return result
    
    def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, int]:
        """
        获取统计信息
        
        统计各类事件的数量。
        
        Args:
            start_time: 统计起始时间
            end_time: 统计结束时间
        
        Returns:
            各类事件数量统计字典
        """
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
