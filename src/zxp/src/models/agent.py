from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, List
import uuid
from datetime import datetime


class AgentState(Enum):
    """代理状态枚举"""
    UNKNOWN = "unknown"
    ACTIVE = "active"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    OFFLINE = "offline"


class CommunicationType(Enum):
    """通信类型枚举"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class CommunicationRecord:
    """通信记录表示"""
    communication_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_agent_id: str = ""
    target_agent_id: str = ""
    communication_type: CommunicationType = CommunicationType.REQUEST
    protocol: str = "HTTP"
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = False
    error_message: Optional[str] = None
    
    @property
    def latency(self) -> float:
        """计算通信延迟（秒）"""
        # 简化实现，实际应记录开始和结束时间
        return 0.0


@dataclass
class TrustRelationship:
    """信任关系表示"""
    source_agent_id: str
    target_agent_id: str
    trust_score: float  # 0.0 - 1.0
    last_updated: datetime = field(default_factory=datetime.now)
    interaction_count: int = 0
    successful_interactions: int = 0
    
    def update_trust(self, success: bool, decay_factor: float = 0.95) -> None:
        """更新信任评分"""
        # 应用衰减
        self.trust_score *= decay_factor
        
        # 根据交互结果更新
        if success:
            # 成功交互增加信任
            increment = (1.0 - self.trust_score) * 0.1
            self.trust_score += increment
            self.successful_interactions += 1
        else:
            # 失败交互减少信任
            decrement = self.trust_score * 0.3
            self.trust_score -= decrement
            
        # 边界约束
        self.trust_score = max(0.0, min(1.0, self.trust_score))
        self.interaction_count += 1
        self.last_updated = datetime.now()
    
    @property
    def success_rate(self) -> float:
        """计算成功率"""
        if self.interaction_count == 0:
            return 0.0
        return self.successful_interactions / self.interaction_count


@dataclass
class Agent:
    """代理实体表示"""
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: str = ""  # 安全域
    agent_type: str = ""  # device, control, security, analytics
    state: AgentState = AgentState.ACTIVE
    metadata: Dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # 本地维护的信任关系图
    trust_relationships: Dict[str, TrustRelationship] = field(default_factory=dict)
    
    # 通信记录
    communication_records: List[CommunicationRecord] = field(default_factory=list)
    
    # 通信状态
    communication_status: Dict[str, str] = field(default_factory=dict)
    
    def get_trust(self, target_agent_id: str) -> Optional[TrustRelationship]:
        """获取对目标代理的信任关系"""
        return self.trust_relationships.get(target_agent_id)
    
    def set_trust(self, target_agent_id: str, trust_score: float) -> TrustRelationship:
        """设置对目标代理的信任关系"""
        relationship = TrustRelationship(
            source_agent_id=self.agent_id,
            target_agent_id=target_agent_id,
            trust_score=trust_score
        )
        self.trust_relationships[target_agent_id] = relationship
        return relationship
    
    def update_trust(self, target_agent_id: str, success: bool, decay_factor: float = 0.95) -> Optional[TrustRelationship]:
        """更新信任关系"""
        rel = self.trust_relationships.get(target_agent_id)
        if rel:
            rel.update_trust(success, decay_factor)
        return rel
    
    def add_communication_record(self, record: CommunicationRecord) -> None:
        """添加通信记录"""
        self.communication_records.append(record)
        
        # 保留最近100条通信记录
        if len(self.communication_records) > 100:
            self.communication_records = self.communication_records[-100:]
    
    def update_communication_status(self, target_agent_id: str, status: str) -> None:
        """更新通信状态"""
        self.communication_status[target_agent_id] = status
    
    def get_communication_status(self, target_agent_id: str) -> Optional[str]:
        """获取通信状态"""
        return self.communication_status.get(target_agent_id)
    
    def update_state(self, new_state: AgentState) -> None:
        """更新代理状态"""
        self.state = new_state
        self.last_seen = datetime.now()
    
    def get_active_communication_count(self) -> int:
        """获取活跃通信数量"""
        return sum(1 for status in self.communication_status.values() if status == "active")
    
    def get_communication_history(self, limit: int = 20) -> List[CommunicationRecord]:
        """获取通信历史"""
        return self.communication_records[-limit:]
