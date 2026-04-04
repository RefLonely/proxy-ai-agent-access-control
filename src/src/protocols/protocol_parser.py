"""
基础协议解析器抽象类
定义电力协议解析器的通用接口
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class ProtocolType(Enum):
    """协议类型枚举"""
    IEC_60870_5 = "iec_60870_5"
    MODBUS = "modbus"
    OPC_UA = "opc_ua"
    DL_T_645 = "dl_t_645"
    UNKNOWN = "unknown"


@dataclass
class ProtocolData:
    """解析后的协议数据基类"""
    raw_data: bytes
    protocol_type: ProtocolType
    is_valid: bool = True
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""


class ProtocolException(Exception):
    """协议解析异常基类"""
    pass


class BaseProtocolParser(ABC):
    """协议解析器抽象基类"""
    
    @abstractmethod
    def parse(self, data: bytes) -> ProtocolData:
        """解析原始二进制数据"""
        pass
    
    @abstractmethod
    def build(self, fields: Dict[str, Any]) -> bytes:
        """根据字段构建二进制数据"""
        pass
    
    @abstractmethod
    def validate(self, data: bytes) -> Tuple[bool, str]:
        """验证数据格式是否合法"""
        pass
    
    @property
    @abstractmethod
    def protocol_type(self) -> ProtocolType:
        """返回协议类型"""
        pass
