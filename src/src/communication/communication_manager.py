"""
代理通信管理模块
处理代理间的安全通信和协作机制
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
from enum import Enum

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
    """
    通信通道表示
    
    存储两个代理之间通信通道的信息，包括协议、状态、可靠性、延迟等。
    
    Attributes:
        channel_id: 通道唯一标识符
        source_agent_id: 源代理ID
        target_agent_id: 目标代理ID
        protocol: 通信协议
        status: 通道状态 active/inactive/suspended
        last_used: 最后使用时间
        reliability: 通道可靠性评分 (0.0-1.0)
        latency: 平均延迟（毫秒）
    """
    channel_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_agent_id: str = ""
    target_agent_id: str = ""
    protocol: CommunicationProtocol = CommunicationProtocol.HTTP
    status: str = "active"  # active, inactive, suspended
    last_used: datetime = field(default_factory=datetime.now)
    reliability: float = 1.0  # 0.0 - 1.0
    latency: float = 0.0  # 毫秒


class CommunicationManager:
    """
    代理通信管理类
    
    管理代理间的通信通道，记录通信历史，监控通信状态，
    支持异常通信检测。
    """
    
    def __init__(self) -> None:
        """初始化通信管理器"""
        # 通信通道映射 channel_id -> channel
        self.channels: Dict[str, CommunicationChannel] = {}
        # 全局通信记录
        self.communication_records: List[CommunicationRecord] = []
        # 通信状态监控 agent_id -> {target_agent_id: status}
        self.communication_status: Dict[str, Dict[str, str]] = {}
    
    def create_channel(
        self,
        source_agent_id: str,
        target_agent_id: str,
        protocol: CommunicationProtocol = CommunicationProtocol.HTTP
    ) -> CommunicationChannel:
        """
        创建通信通道
        
        在两个代理之间建立新的通信通道。
        
        Args:
            source_agent_id: 源代理ID
            target_agent_id: 目标代理ID
            protocol: 通信协议，默认为HTTP
        
        Returns:
            创建的通信通道
        """
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
        """
        获取通信通道
        
        Args:
            channel_id: 通道ID
        
        Returns:
            通信通道对象，如果不存在返回 None
        """
        return self.channels.get(channel_id)
    
    def get_channels_between_agents(
        self,
        source_agent_id: str,
        target_agent_id: str
    ) -> List[CommunicationChannel]:
        """
        获取代理间的所有通信通道
        
        Args:
            source_agent_id: 源代理ID
            target_agent_id: 目标代理ID
        
        Returns:
            通信通道列表
        """
        return [
            channel for channel in self.channels.values()
            if channel.source_agent_id == source_agent_id
            and channel.target_agent_id == target_agent_id
        ]
    
    def send_message(
        self,
        source_agent_id: str,
        target_agent_id: str,
        message: str,
        protocol: CommunicationProtocol = CommunicationProtocol.HTTP
    ) -> CommunicationRecord:
        """
        发送消息
        
        如果没有通信通道，自动创建新通道。更新通道使用时间。记录通信历史。
        
        Args:
            source_agent_id: 源代理ID
            target_agent_id: 目标代理ID
            message: 消息内容
            protocol: 通信协议，默认为HTTP
        
        Returns:
            创建的通信记录
        """
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
    
    def receive_message(
        self,
        source_agent_id: str,
        target_agent_id: str,
        message: str,
        protocol: CommunicationProtocol = CommunicationProtocol.HTTP
    ) -> CommunicationRecord:
        """
        接收消息
        
        记录接收的消息到通信历史。
        
        Args:
            source_agent_id: 源代理ID
            target_agent_id: 目标代理ID
            message: 消息内容
            protocol: 通信协议，默认为HTTP
        
        Returns:
            创建的通信记录
        """
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
    
    def update_channel_reliability(
        self,
        channel_id: str,
        reliability: float
    ) -> Optional[CommunicationChannel]:
        """
        更新通道可靠性评分
        
        Args:
            channel_id: 通道ID
            reliability: 新的可靠性评分 (0.0-1.0)
        
        Returns:
            更新后的通道，如果通道不存在返回 None
        """
        channel = self.channels.get(channel_id)
        if channel:
            channel.reliability = max(0.0, min(1.0, reliability))
        return channel
    
    def update_channel_latency(
        self,
        channel_id: str,
        latency: float
    ) -> Optional[CommunicationChannel]:
        """
        更新通道平均延迟
        
        Args:
            channel_id: 通道ID
            latency: 延迟（毫秒）
        
        Returns:
            更新后的通道，如果通道不存在返回 None
        """
        channel = self.channels.get(channel_id)
        if channel:
            channel.latency = max(0.0, latency)
        return channel
    
    def suspend_channel(self, channel_id: str) -> Optional[CommunicationChannel]:
        """
        暂停通信通道
        
        Args:
            channel_id: 通道ID
        
        Returns:
            更新后的通道，如果通道不存在返回 None
        """
        channel = self.channels.get(channel_id)
        if channel:
            channel.status = "suspended"
            # 更新通信状态
            if channel.source_agent_id in self.communication_status:
                if channel.target_agent_id in self.communication_status[channel.source_agent_id]:
                    self.communication_status[channel.source_agent_id][channel.target_agent_id] = "suspended"
        return channel
    
    def activate_channel(self, channel_id: str) -> Optional[CommunicationChannel]:
        """
        激活通信通道
        
        Args:
            channel_id: 通道ID
        
        Returns:
            更新后的通道，如果通道不存在返回 None
        """
        channel = self.channels.get(channel_id)
        if channel:
            channel.status = "active"
            # 更新通信状态
            if channel.source_agent_id in self.communication_status:
                if channel.target_agent_id in self.communication_status[channel.source_agent_id]:
                    self.communication_status[channel.source_agent_id][channel.target_agent_id] = "active"
        return channel
    
    def get_agent_communication_status(self, agent_id: str) -> Dict[str, str]:
        """
        获取代理通信状态
        
        Args:
            agent_id: 代理ID
        
        Returns:
            通信状态字典 {target_agent_id: status}
        """
        return self.communication_status.get(agent_id, {})
    
    def get_communication_history(
        self,
        agent_id: str,
        limit: int = 20
    ) -> List[CommunicationRecord]:
        """
        获取代理通信历史
        
        返回最近 limit 条记录。
        
        Args:
            agent_id: 代理ID
            limit: 返回记录数量限制，默认20
        
        Returns:
            通信记录列表
        """
        return [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ][-limit:]
    
    def get_communication_stats(self, agent_id: str) -> Dict[str, Any]:
        """
        获取代理通信统计信息
        
        计算总通信次数、成功率、平均延迟等统计数据。
        
        Args:
            agent_id: 代理ID
        
        Returns:
            统计信息字典
        """
        agent_records = [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ]
        
        if not agent_records:
            return {
                "total_communications": 0,
                "success_rate": 0.0,
                "error_count": 0,
                "average_latency": 0.0
            }
        
        success_count = sum(1 for record in agent_records if record.success)
        error_count = len(agent_records) - success_count
        total_latency = sum(record.latency for record in agent_records)
        avg_latency = total_latency / len(agent_records) if len(agent_records) > 0 else 0.0
        
        return {
            "total_communications": len(agent_records),
            "success_rate": success_count / len(agent_records) if len(agent_records) > 0 else 0.0,
            "error_count": error_count,
            "average_latency": avg_latency
        }
    
    def detect_abnormal_communication(self, agent_id: str) -> List[CommunicationRecord]:
        """
        检测异常通信
        
        检测成功率低于50%或延迟高于1秒的异常通信记录。
        
        Args:
            agent_id: 代理ID
        
        Returns:
            异常通信记录列表
        """
        abnormal_records: List[CommunicationRecord] = []
        agent_records = [
            record for record in self.communication_records
            if record.source_agent_id == agent_id or record.target_agent_id == agent_id
        ]
        
        # 简单的异常检测：成功率低于50%或延迟高于1秒
        for record in agent_records:
            if not record.success or record.latency > 1.0:
                abnormal_records.append(record)
        
        return abnormal_records
