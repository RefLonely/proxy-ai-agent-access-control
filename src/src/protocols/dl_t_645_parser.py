"""
DL/T 645 多功能电能表通信协议解析器
实现基础解析和异常检测能力
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .protocol_parser import BaseProtocolParser, ProtocolData, ProtocolException, ProtocolType


class DLT645Exception(ProtocolException):
    """DL/T 645 解析异常"""
    pass


@dataclass
class DLT645Frame(ProtocolData):
    """
    DL/T 645 帧结构
    
    存储解析后的DL/T 645多功能电能表协议帧数据。
    
    Attributes:
        start_flag: 起始标志，固定为 0x68
        end_flag: 结束标志，固定为 0x16
        address: 地址域 (6字节)
        control_code: 控制码
        data_length: 数据长度
        data: 数据域
        checksum: 校验和
    """
    start_flag: int = 0x68
    end_flag: int = 0x16
    address: bytes = field(default_factory=bytes)  # 6字节地址
    control_code: int = 0
    data_length: int = 0
    data: bytes = field(default_factory=bytes)
    checksum: int = 0
    
    @property
    def address_str(self) -> str:
        """获取地址字符串表示"""
        return self.address.hex().upper()


class DLT645Parser(BaseProtocolParser):
    """
    DL/T 645 多功能电能表通信协议解析器
    
    实现DL/T 645协议的帧解析、构建、验证和异常检测。
    """
    
    # 帧标志
    START_FLAG = 0x68
    END_FLAG = 0x16
    
    # 控制码定义
    C_BROADCAST = 0x08  # 广播命令
    C_READ = 0x11       # 读数据
    C_WRITE = 0x14      # 写数据
    C_READ_REPLY = 0x91 # 读应答
    C_WRITE_REPLY = 0x94 # 写应答
    
    # 地址长度
    ADDRESS_LENGTH = 6
    
    # 最小帧长度
    MIN_FRAME_LENGTH = 10  # 2个起始 + 6地址 + 控制码 + 长度 + 数据 + 校验 + 结束
    
    @property
    def protocol_type(self) -> ProtocolType:
        """获取协议类型"""
        return ProtocolType.DL_T_645
    
    def validate(self, data: bytes) -> Tuple[bool, str]:
        """
        验证DL/T 645帧合法性
        
        检查起始标志、结束标志、长度、校验和等字段。
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)
        """
        if len(data) < self.MIN_FRAME_LENGTH:
            return False, f"Frame too short: {len(data)} < {self.MIN_FRAME_LENGTH}"
        
        # 检查起始标志
        if data[0] != self.START_FLAG or data[7] != self.START_FLAG:
            return False, f"Invalid start flags: expected two 0x68 at positions 0 and 7"
        
        # 检查结束标志
        if data[-1] != self.END_FLAG:
            return False, f"Invalid end flag: 0x{data[-1]:02x}, expected 0x{self.END_FLAG:02x}"
        
        # 计算期望长度
        data_length = data[8]
        expected_length = 2 + self.ADDRESS_LENGTH + 1 + 1 + data_length + 1 + 1
        if len(data) != expected_length:
            return False, f"Length mismatch: got {len(data)}, expected {expected_length}"
        
        # 验证校验和
        calculated_checksum = sum(data[1:-2]) & 0xFF
        received_checksum = data[-2]
        if calculated_checksum != received_checksum:
            return False, f"Checksum mismatch: calculated 0x{calculated_checksum:02x}, got 0x{received_checksum:02x}"
        
        return True, "Valid"
    
    def parse(self, data: bytes) -> DLT645Frame:
        """
        解析DL/T 645帧
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            解析后的帧对象，解析失败时 is_valid 为 False
        """
        frame = DLT645Frame(
            raw_data=data,
            protocol_type=ProtocolType.DL_T_645
        )
        
        valid, msg = self.validate(data)
        if not valid:
            frame.is_valid = False
            frame.error_message = msg
            return frame
        
        try:
            frame.address = data[1:7]
            frame.control_code = data[9]
            frame.data_length = data[8]
            
            # 提取数据
            data_start = 10
            data_end = data_start + frame.data_length
            frame.data = data[data_start:data_end]
            frame.checksum = data[-2]
            
            frame.parsed_fields = {
                'address': frame.address_str,
                'control_code': frame.control_code,
                'data_length': frame.data_length,
                'control_code_hex': f"0x{frame.control_code:02x}",
                'is_broadcast': (frame.control_code & 0x0F) == 0x08
            }
            
            # 尝试解析数据标识
            if frame.data_length >= 4 and frame.control_code in [self.C_READ, self.C_READ_REPLY]:
                data_id = frame.data[0:4]
                frame.parsed_fields['data_identifier'] = data_id.hex().upper()
            
            return frame
        
        except Exception as e:
            frame.is_valid = False
            frame.error_message = f"Parse error: {str(e)}"
            return frame
    
    def build(self, fields: Dict[str, Any]) -> bytes:
        """
        构建DL/T 645帧
        
        根据给定字段构建二进制帧数据。
        
        Args:
            fields: 帧字段字典，包含 address, control_code, data 等
        
        Returns:
            构建好的二进制帧数据
        
        Raises:
            ValueError: 当地址长度不为6字节时
        """
        address = fields.get('address', b'\x00\x00\x00\x00\x00\x00')
        control_code = fields.get('control_code', self.C_READ)
        data = fields.get('data', b'')
        
        if len(address) != 6:
            raise ValueError("Address must be 6 bytes")
        
        buffer = bytearray()
        buffer.append(self.START_FLAG)
        buffer.extend(address)
        buffer.append(self.START_FLAG)
        buffer.append(len(data))
        buffer.append(control_code)
        buffer.extend(data)
        
        # 计算校验和
        checksum = sum(buffer[1:]) & 0xFF
        buffer.append(checksum)
        buffer.append(self.END_FLAG)
        
        return bytes(buffer)
    
    def detect_anomalies(self, frame: DLT645Frame) -> List[Tuple[str, str]]:
        """
        检测DL/T 645协议异常
        
        检查地址、控制码、数据长度等异常。
        
        Args:
            frame: 解析后的帧对象
        
        Returns:
            异常列表，每项为(异常类型, 异常描述)
        """
        anomalies: List[Tuple[str, str]] = []
        
        if not frame.is_valid:
            anomalies.append(("INVALID_FORMAT", frame.error_message))
        
        # 全零地址广播检测
        if frame.address == b'\x00\x00\x00\x00\x00\x00' and frame.control_code != self.C_BROADCAST:
            anomalies.append(("ZERO_ADDRESS_NONBROADCAST", "All-zero address with non-broadcast command"))
        
        # 异常控制码检测 - DL/T 645控制码范围是0x00-0xFF
        if frame.control_code < 0x00 or frame.control_code > 0xFF:
            anomalies.append(("INVALID_CONTROL_CODE", f"Control code 0x{frame.control_code:02x} out of range"))
        
        # 数据长度不匹配检测
        if len(frame.data) != frame.data_length:
            anomalies.append(("DATA_LENGTH_MISMATCH", f"Expected {frame.data_length} bytes, got {len(frame.data)}"))
        
        # 广播命令有应答异常检测
        if (frame.control_code & 0x0F) == self.C_BROADCAST and len(frame.data) > 0:
            anomalies.append(("BROADCAST_WITH_RESPONSE", "Broadcast command should not have response data"))
        
        # 过长数据检测
        if frame.data_length > 200:
            anomalies.append(("EXCESSIVE_DATA", f"Data length {frame.data_length} exceeds typical maximum"))
        
        return anomalies
