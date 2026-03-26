from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional
from datetime import datetime


class AccessAction(Enum):
    """访问操作类型"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    CONTROL = "control"
    CONFIGURE = "configure"
    CONNECT = "connect"    # 连接操作
    DISCONNECT = "disconnect"  # 断开连接
    MONITOR = "monitor"    # 监控操作
    QUERY = "query"        # 查询操作
    UPDATE = "update"      # 更新操作
    ADJUST = "adjust"      # 调整操作


class DecisionOutcome(Enum):
    """访问决策结果"""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # 需要二次验证
    DEFER = "defer"  # 延迟决策


@dataclass
class AccessRequest:
    """访问请求表示"""
    request_id: str
    requester_id: str  # 请求者代理ID
    target_id: str  # 目标资源/代理ID
    action: AccessAction
    context: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    protocol: str = ""  # 工业协议: Modbus, OPC UA, etc.
    source_ip: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class AccessDecision:
    """访问决策表示"""
    request: AccessRequest
    outcome: DecisionOutcome
    confidence: float  # 决策置信度 0.0-1.0
    reason: str = ""
    trust_score: float = 0.0
    alignment_score: float = 0.0  # 安全对齐分数
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def is_allowed(self) -> bool:
        return self.outcome == DecisionOutcome.ALLOW
