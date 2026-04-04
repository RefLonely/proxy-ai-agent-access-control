"""
代理通信管理模块
处理代理间的安全通信和协作机制
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import uuid
from enum import Enum
import hashlib
import hmac

from ..models.agent import Agent, AgentState, CommunicationRecord, CommunicationType


class CommunicationProtocol(Enum):
    """通信协议枚举"""
    HTTP = "HTTP"
    MQTT = "MQTT"
    AMQP = "AMQP"
    MODBUS = "MODBUS"
    OPCUA = "OPC UA"


@dataclass
class CommunicationChannel:
    """通信通道表示"""
    channel_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_agent_id: str = ""
    target_agent_id: str = ""
    protocol: CommunicationProtocol = CommunicationProtocol.HTTP
    status: str = "active"  # active, inactive, suspended
    last_used: datetime = field(default_factory=datetime.now)
    reliability: float = 1.0  # 0.0 - 1.0
    latency: float = 0.0  # 毫秒


class CommunicationManager:
    """代理通信管理类
    安全增强：添加签名验证，防止信任更新消息伪造
    """
    
    def __init__(self):
        # 通信通道映射
        self.channels: Dict[str, CommunicationChannel] = {}
        # 代理间通信记录
        self.communication_records: List[CommunicationRecord] = []
        # 通信状态监控
        self.communication_status: Dict[str, Dict[str, str]] = {}
        # 代理密钥 - 每个代理有自己的密钥用于签名
        self.agent_keys: Dict[str, bytes] = {}
        # 信任传播消息需要签名验证
        self.require_signature_for_trust_propagation = True
    
    def generate_agent_key(self, agent_id: str) -> bytes:
        """为代理生成签名密钥 - 生产环境应该用安全随机数生成"""
        import os
        key = os.urandom(32)  # 256-bit key for HMAC-SHA256
        self.agent_keys[agent_id] = key
        return key
    
    def get_agent_key(self, agent_id: str) -> Optional[bytes]:
        """获取代理密钥"""
        return self.agent_keys.get(agent_id)
    
    def sign_message(self, sender_agent_id: str, message: str) -> Tuple[str, bool]:
        """对消息进行签名"""
        key = self.get_agent_key(sender_agent_id)
        if not key:
            # 如果没有密钥，生成一个
            key = self.generate_agent_key(sender_agent_id)
        
        signature = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        return signature, True
    
    def verify_signature(self, sender_agent_id: str, message: str, signature: str) -> bool:
        """验证消息签名 - 防止伪造信任更新"""
        key = self.get_agent_key(sender_agent_id)
        if not key:
            # 如果没有密钥，无法验证，拒绝信任更新
            return False
        
        expected = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    
    def create_channel(self, source_agent_id: str, target_agent_id: str, protocol: CommunicationProtocol = CommunicationProtocol.HTTP) -> CommunicationChannel:
        """创建通信通道"""
        channel = CommunicationChannel(
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            protocol=protocol
        )
        self.channels[channel.channel_id] = channel
        
        # 初始化通信状态
        if source_agent_id not in self.communication_status:
            self.communication_status[source_agent_id] = {}
        self.communication_status[source_agent_id][target_agent_id] = "active"
        
        return channel
    
    def get_channel(self, channel_id: str) -> Optional[CommunicationChannel]:
        """获取通信通道"""
        return self.channels.get(channel_id)
    
    def get_channels_between_agents(self, source_agent_id: str, target_agent_id: str) -> List[CommunicationChannel]:
        """获取代理间的通信通道"""
        return [
            channel for channel in self.channels.values()
            if channel.source_agent_id == source_agent_id and channel.target_agent_id == target_agent_id
        ]
    
    def send_message(self, source_agent_id: str, target_agent_id: str, message: str, protocol: CommunicationProtocol = CommunicationProtocol.HTTP) -> CommunicationRecord:
        """发送消息"""
        # 检查是否存在通信通道
        channels = self.get_channels_between_agents(source_agent_id, target_agent_id)
        if not channels:
            # 创建新通信通道
            channel = self.create_channel(source_agent_id, target_agent_id, protocol)
        else:
            channel = channels[0]
        
        # 更新通道状态
        channel.last_used = datetime.now()
        
        # 记录通信
        record = CommunicationRecord(
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            communication_type=CommunicationType.REQUEST,
            protocol=protocol.value,
            message=message,
            success=True
        )
        
        self.communication_records.append(record)
        
        # 更新通信状态
        if source_agent_id not in self.communication_status:
            self.communication_status[source_agent_id] = {}
        self.communication_status[source_agent_id][target_agent_id] = "active"
        
        return record
    
    def receive_message(self, source_agent_id: str, target_agent_id: str, message: str, protocol: CommunicationProtocol = CommunicationProtocol.HTTP) -> CommunicationRecord:
        """接收消息"""
        record = CommunicationRecord(
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            communication_type=CommunicationType.RESPONSE,
            protocol=protocol.value,
            message=message,
            success=True
        )
        
        self.communication_records.append(record)
        
        return record
    
    def update_channel_reliability(self, channel_id: str, reliability: float) -> Optional[CommunicationChannel]:
        """更新通道可靠性"""
        channel = self.channels.get(channel_id)
        if channel:
            channel.reliability = max(0.0, min(1.0, reliability))
        return channel
    
    def update_channel_latency(self, channel_id: str, latency: float) -> Optional[CommunicationChannel]:
        """更新通道延迟"""
        channel = self.channels.get(channel_id)
        if channel:
            channel.latency = max(0.0, latency)
        return channel
    
    def suspend_channel(self, channel_id: str) -> Optional[CommunicationChannel]:
        """暂停通信通道"""
        channel = self.channels.get(channel_id)
        if channel:
            channel.status = "suspended"
            # 更新通信状态
            if channel.source_agent_id in self.communication_status:
                if channel.target_agent_id in self.communication_status[channel.source_agent_id]:
                    self.communication_status[channel.source_agent_id][channel.target_agent_id] = "suspended"
        return channel
    
    def activate_channel(self, channel_id: str) -> Optional[CommunicationChannel]:
        """激活通信通道"""
        channel = self.channels.get(channel_id)
        if channel:
            channel.status = "active"
            # 更新通信状态
            if channel.source_agent_id in self.communication_status:
                if channel.target_agent_id in self.communication_status[channel.source_agent_id]:
                    self.communication_status[channel.source_agent_id][channel.target_agent_id] = "active"
        return channel
    
    def get_agent_communication_status(self, agent_id: str) -> Dict[str, str]:
        """获取代理通信状态"""
        return self.communication_status.get(agent_id, {})
    
    def get_communication_history(self, agent_id: str, limit: int = 20) -> List[CommunicationRecord]:
        """获取代理通信历史"""
        return [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ][-limit:]
    
    def get_communication_stats(self, agent_id: str) -> Dict:
        """获取代理通信统计信息"""
        agent_records = [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ]
        
        success_count = sum(1 for record in agent_records if record.success)
        error_count = len(agent_records) - success_count
        avg_latency = sum(record.latency for record in agent_records) / len(agent_records) if len(agent_records) > 0 else 0.0
        
        return {
            "total_communications": len(agent_records),
            "success_rate": success_count / len(agent_records) if len(agent_records) > 0 else 0.0,
            "error_count": error_count,
            "average_latency": avg_latency
        }
    
    def detect_abnormal_communication(self, agent_id: str) -> List[CommunicationRecord]:
        """检测异常通信"""
        abnormal_records = []
        agent_records = [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ]
        
        # 简单的异常检测：成功率低于50%或延迟高于1秒
        for record in agent_records:
            if not record.success or record.latency > 1.0:
                abnormal_records.append(record)
        
        return abnormal_records
