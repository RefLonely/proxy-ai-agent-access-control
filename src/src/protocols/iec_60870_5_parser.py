"""
IEC 60870-5-101/104 远动协议解析器
实现基础帧解析和异常检测能力
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from struct import unpack, pack

from .protocol_parser import BaseProtocolParser, ProtocolData, ProtocolException, ProtocolType


class IEC608705Exception(ProtocolException):
    """IEC 60870-5 解析异常"""
    pass


@dataclass
class IEC608705Frame(ProtocolData):
    """
    IEC 60870-5 帧结构
    
    存储解析后的IEC 60870-5帧数据，包含帧头、地址、控制域、数据单元等信息。
    
    Attributes:
        start_byte: 起始字节，固定为 0x68
        length: 帧长度
        control_field: 控制字段
        address: 地址域
        data_units: 数据单元列表
        checksum: 校验和
    """
    start_byte: int = 0x68
    length: int = 0
    control_field: int = 0
    address: int = 0
    data_units: List[bytes] = field(default_factory=list)
    checksum: int = 0


class IEC608705Parser(BaseProtocolParser):
    """
    IEC 60870-5 协议解析器
    
    实现IEC 60870-5-101/104远动协议的帧解析、构建和验证功能，
    支持异常检测。
    """
    
    # 常量定义
    START_FRAME = 0x68
    END_FRAME = 0x16
    
    # 控制字段类型
    TYPE_I = 0  # 编号帧 (Information)
    TYPE_S = 1  # 监督帧 (Supervisory)
    TYPE_U = 2  # 无编号帧 (Unnumbered)
    
    def __init__(self) -> None:
        """初始化解析器，设置帧长度限制"""
        self.max_frame_length: int = 255
        self.min_frame_length: int = 6  # 起始符 + 长度 + 控制域 + 地址域 + 校验 + 结束符
    
    @property
    def protocol_type(self) -> ProtocolType:
        """获取协议类型"""
        return ProtocolType.IEC_60870_5
    
    def validate(self, data: bytes) -> Tuple[bool, str]:
        """
        验证IEC 60870-5帧合法性
        
        检查帧长度、起始符、结束符、校验和等字段。
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)，合法时错误信息为"Valid"
        """
        if len(data) < self.min_frame_length:
            return False, f"Frame too short: {len(data)} < {self.min_frame_length}"
        
        if data[0] != self.START_FRAME:
            return False, f"Invalid start byte: 0x{data[0]:02x}, expected 0x{self.START_FRAME:02x}"
        
        length = data[1]
        expected_length = length + 4  # start(1) + length(1) + control(1) + address(1) + data(length-2) + checksum(1) + end(1) = length + 4
        if len(data) != expected_length:
            return False, f"Length mismatch: got {len(data)}, expected {expected_length}"
        
        # 验证校验和
        calculated_checksum = sum(data[2:-2]) & 0xFF
        received_checksum = data[-2]
        if calculated_checksum != received_checksum:
            return False, f"Checksum mismatch: calculated 0x{calculated_checksum:02x}, got 0x{received_checksum:02x}"
        
        if data[-1] != self.END_FRAME:
            return False, f"Invalid end byte: 0x{data[-1]:02x}, expected 0x{self.END_FRAME:02x}"
        
        return True, "Valid"
    
    def parse(self, data: bytes) -> IEC608705Frame:
        """
        解析IEC 60870-5帧
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            解析后的帧对象，解析失败时 is_valid 为 False
        """
        frame = IEC608705Frame(
            raw_data=data,
            protocol_type=ProtocolType.IEC_60870_5
        )
        
        valid, msg = self.validate(data)
        if not valid:
            frame.is_valid = False
            frame.error_message = msg
            return frame
        
        try:
            frame.start_byte = data[0]
            frame.length = data[1]
            frame.control_field = data[2]
            frame.address = data[3]
            
            # 提取数据单元
            if frame.length > 2:
                data_start = 4
                data_end = 4 + (frame.length - 2)
                frame.data_units = [data[data_start:data_end]]
            
            frame.checksum = data[-2]
            frame.parsed_fields = {
                'start_byte': frame.start_byte,
                'length': frame.length,
                'control_field': frame.control_field,
                'address': frame.address,
                'checksum': frame.checksum,
                'frame_type': self._get_control_field_type(frame.control_field)
            }
            
            return frame
        
        except Exception as e:
            frame.is_valid = False
            frame.error_message = f"Parse error: {str(e)}"
            return frame
    
    def build(self, fields: Dict[str, Any]) -> bytes:
        """
        构建IEC 60870-5帧
        
        根据给定字段构建二进制帧数据。
        
        Args:
            fields: 帧字段字典，包含 start_byte, control_field, address, data 等
        
        Returns:
            构建好的二进制帧数据
        """
        start_byte = fields.get('start_byte', self.START_FRAME)
        control_field = fields.get('control_field', 0)
        address = fields.get('address', 0)
        data = fields.get('data', b'')
        
        length = 2 + len(data)
        buffer = bytearray()
        buffer.append(start_byte)
        buffer.append(length)
        buffer.append(control_field)
        buffer.append(address)
        buffer.extend(data)
        
        # 计算校验和
        checksum = sum(buffer[2:]) & 0xFF
        buffer.append(checksum)
        buffer.append(self.END_FRAME)
        
        return bytes(buffer)
    
    def _get_control_field_type(self, control_field: int) -> str:
        """
        根据控制字段确定帧类型
        
        Args:
            control_field: 控制字段值
        
        Returns:
            帧类型描述字符串
        """
        if (control_field & 0x01) == 0:
            return "I-frame (Information)"
        elif (control_field & 0x02) == 0:
            return "S-frame (Supervisory)"
        else:
            return "U-frame (Unnumbered)"
    
    def detect_anomalies(self, frame: IEC608705Frame) -> List[Tuple[str, str]]:
        """
        检测IEC 60870-5协议异常
        
        检查帧格式、长度、地址、控制字段标志等异常。
        
        Args:
            frame: 解析后的帧对象
        
        Returns:
            异常列表，每项为(异常类型, 异常描述)
        """
        anomalies: List[Tuple[str, str]] = []
        
        if not frame.is_valid:
            anomalies.append(("INVALID_FORMAT", frame.error_message))
        
        # 异常长度检测 - 即使帧无效也要检查
        length = frame.length if frame.length > 0 else (len(frame.raw_data) - 4)
        if length > self.max_frame_length:
            anomalies.append(("OVERSIZE_FRAME", f"Frame length {length} exceeds maximum {self.max_frame_length}"))
        
        # 异常地址检测
        if frame.address == 0x00 and length > 1:
            anomalies.append(("BROADCAST_ADDRESS", "Broadcast address in unexpected context"))
        
        # 保留位检测
        if (frame.control_field & 0xF0) != 0:
            anomalies.append(("UNEXPECTED_FLAGS", "Reserved bits set in control field"))
        
        return anomalies
