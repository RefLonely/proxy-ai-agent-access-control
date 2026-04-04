"""
代理通信管理模块
提供代理间的安全通信和协作机制
"""

from .communication_manager import (
    CommunicationManager,
    CommunicationProtocol,
    CommunicationChannel
)

__all__ = [
    "CommunicationManager",
    "CommunicationProtocol",
    "CommunicationChannel"
]
