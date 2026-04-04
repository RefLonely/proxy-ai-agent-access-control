"""
OPC UA 开放平台通信统一架构解析器
实现基础消息解析和异常检测能力
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from struct import unpack, pack
from enum import Enum

from .protocol_parser import BaseProtocolParser, ProtocolData, ProtocolException, ProtocolType


class OPCUAException(ProtocolException):
    """OPC UA 解析异常"""
    pass


class OPCUAMessageType(Enum):
    """OPC UA 消息类型"""
    HELLO = "HEL"
    ACKNOWLEDGE = "ACK"
    OPEN_SECURE_CHANNEL = "OPN"
    CLOSE_SECURE_CHANNEL = "CLO"
    SECURE_MESSAGE = "MSG"
    ERROR = "ERR"


@dataclass
class OPCUAMessage(ProtocolData):
    """
    OPC UA 消息结构
    
    存储解析后的OPC UA消息数据。
    
    Attributes:
        message_type: 消息类型代码 (3字节)
        chunk_type: 块类型 (1字节)
        message_size: 消息总大小
        secure_channel_id: 安全通道ID
        request_id: 请求ID
        payload: 消息负载
    """
    message_type: bytes = b''
    chunk_type: bytes = b''
    message_size: int = 0
    secure_channel_id: int = 0
    request_id: int = 0
    payload: bytes = field(default_factory=bytes)
    
    @property
    def message_type_str(self) -> str:
        """获取消息类型字符串表示"""
        return self.message_type.decode('ascii', errors='replace')


class OPCUAParser(BaseProtocolParser):
    """
    OPC UA 协议解析器
    
    实现OPC UA协议消息的解析、构建、验证和异常检测。
    """
    
    # 消息头大小
    HEADER_SIZE = 8
    HEADER_SIZE_SECURE = 12
    
    # OPC UA 默认端口
    DEFAULT_PORT = 4840
    
    # 最大消息大小
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10MB
    
    @property
    def protocol_type(self) -> ProtocolType:
        """获取协议类型"""
        return ProtocolType.OPC_UA
    
    def validate(self, data: bytes) -> Tuple[bool, str]:
        """
        验证OPC UA消息合法性
        
        检查消息长度、消息类型、块类型等字段。
        
        Args:
            data: 原始二进制消息数据
        
        Returns:
            (是否合法, 错误信息)
        """
        if len(data) < self.HEADER_SIZE:
            return False, f"Message too short: {len(data)} < {self.HEADER_SIZE}"
        
        # 获取消息长度
        message_size = int.from_bytes(data[4:8], byteorder='little')
        if message_size != len(data):
            return False, f"Length mismatch: header says {message_size}, got {len(data)}"
        
        if message_size > self.MAX_MESSAGE_SIZE:
            return False, f"Message too large: {message_size} > {self.MAX_MESSAGE_SIZE}"
        
        # 验证消息类型
        msg_type = data[0:3]
        valid_types = [b'HEL', b'ACK', b'OPN', b'CLO', b'MSG', b'ERR']
        if msg_type not in valid_types:
            return False, f"Invalid message type: {msg_type!r}"
        
        # 验证块类型
        chunk_type = data[3:4]
        if chunk_type not in [b'C', b'A', b'I']:
            return False, f"Invalid chunk type: {chunk_type!r}"
        
        return True, "Valid"
    
    def parse(self, data: bytes) -> OPCUAMessage:
        """
        解析OPC UA消息
        
        Args:
            data: 原始二进制消息数据
        
        Returns:
            解析后的消息对象，解析失败时 is_valid 为 False
        """
        msg = OPCUAMessage(
            raw_data=data,
            protocol_type=ProtocolType.OPC_UA
        )
        
        valid, msg_error = self.validate(data)
        if not valid:
            msg.is_valid = False
            msg.error_message = msg_error
            return msg
        
        try:
            msg.message_type = data[0:3]
            msg.chunk_type = data[3:4]
            msg.message_size = int.from_bytes(data[4:8], byteorder='little')
            
            # 如果是安全消息，有安全通道ID
            if msg.message_type_str == 'MSG':
                if len(data) >= self.HEADER_SIZE_SECURE:
                    msg.secure_channel_id = int.from_bytes(data[8:12], byteorder='little')
                    payload_start = 12
                    if len(data) > 12:
                        msg.payload = data[payload_start:]
            else:
                payload_start = 8
                if len(data) > payload_start:
                    msg.payload = data[payload_start:]
            
            # 解析基本字段
            msg.parsed_fields = {
                'message_type': msg.message_type_str,
                'chunk_type': msg.chunk_type.decode('ascii', errors='replace'),
                'message_size': msg.message_size,
                'secure_channel_id': msg.secure_channel_id,
                'payload_size': len(msg.payload)
            }
            
            # 特定消息类型解析
            if msg.message_type_str == 'HEL':
                self._parse_hello(msg)
            elif msg.message_type_str == 'ERR':
                self._parse_error(msg)
            
            return msg
        
        except Exception as e:
            msg.is_valid = False
            msg.error_message = f"Parse error: {str(e)}"
            return msg
    
    def _parse_hello(self, msg: OPCUAMessage) -> None:
        """
        解析Hello消息
        
        提取协议版本和接收缓冲区大小。
        
        Args:
            msg: 消息对象，解析结果写入此对象
        """
        if len(msg.payload) >= 8:
            msg.parsed_fields['protocol_version'] = int.from_bytes(
                msg.payload[0:4], byteorder='little')
            msg.parsed_fields['receive_buffer_size'] = int.from_bytes(
                msg.payload[4:8], byteorder='little')
    
    def _parse_error(self, msg: OPCUAMessage) -> None:
        """
        解析Error消息
        
        提取错误码。
        
        Args:
            msg: 消息对象，解析结果写入此对象
        """
        if len(msg.payload) >= 4:
            msg.parsed_fields['error_code'] = int.from_bytes(
                msg.payload[0:4], byteorder='little')
    
    def build(self, fields: Dict[str, Any]) -> bytes:
        """
        构建OPC UA消息
        
        根据给定字段构建二进制消息数据。
        
        Args:
            fields: 消息字段字典，包含 message_type, chunk_type, secure_channel_id, payload 等
        
        Returns:
            构建好的二进制消息数据
        """
        msg_type = fields.get('message_type', b'MSG')
        chunk_type = fields.get('chunk_type', b'C')
        secure_channel_id = fields.get('secure_channel_id', 0)
        payload = fields.get('payload', b'')
        
        # 计算总长度
        if secure_channel_id > 0:
            header_size = self.HEADER_SIZE_SECURE
        else:
            header_size = self.HEADER_SIZE
        
        total_size = header_size + len(payload)
        buffer = bytearray()
        buffer.extend(msg_type)
        buffer.extend(chunk_type)
        buffer.extend(total_size.to_bytes(4, byteorder='little'))
        
        if secure_channel_id > 0:
            buffer.extend(secure_channel_id.to_bytes(4, byteorder='little'))
        
        buffer.extend(payload)
        
        return bytes(buffer)
    
    def detect_anomalies(self, msg: OPCUAMessage) -> List[Tuple[str, str]]:
        """
        检测OPC UA协议异常
        
        检查消息大小、消息类型、块类型等异常。
        
        Args:
            msg: 解析后的消息对象
        
        Returns:
            异常列表，每项为(异常类型, 异常描述)
        """
        anomalies: List[Tuple[str, str]] = []
        
        if not msg.is_valid:
            anomalies.append(("INVALID_FORMAT", msg.error_message))
        
        # 错误消息检测
        if msg.message_type_str == 'ERR':
            error_code = msg.parsed_fields.get('error_code', -1)
            anomalies.append(("PROTOCOL_ERROR", f"OPC UA error code 0x{error_code:08x}"))
        
        # 超大消息检测
        if msg.message_size > 1 * 1024 * 1024:  # 超过1MB
            anomalies.append(("OVERSIZE_MESSAGE", f"Message size {msg.message_size} is unusually large"))
        
        # 不匹配的块类型检测
        chunk_type = msg.chunk_type.decode('ascii', errors='replace')
        if chunk_type not in ['C', 'A', 'I']:
            anomalies.append(("INVALID_CHUNK_TYPE", f"Invalid chunk type {chunk_type}"))
        
        # 消息大小与实际负载不匹配检测
        if len(msg.payload) > 0 and msg.secure_channel_id == 0 and len(msg.raw_data) != msg.message_size:
            anomalies.append(("SIZE_MISMATCH", f"Message size {msg.message_size} does not match actual {len(msg.raw_data)}"))
        
        return anomalies
