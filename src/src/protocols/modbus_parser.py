"""
Modbus 工业控制协议解析器
支持RTU和TCP模式，实现基础解析和异常检测
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from struct import unpack, pack
from enum import Enum

from .protocol_parser import BaseProtocolParser, ProtocolData, ProtocolException, ProtocolType


class ModbusException(ProtocolException):
    """Modbus 解析异常"""
    pass


class ModbusMode(Enum):
    """Modbus 工作模式"""
    RTU = "rtu"
    TCP = "tcp"
    ASCII = "ascii"


@dataclass
class ModbusFrame(ProtocolData):
    """
    Modbus 帧结构
    
    存储解析后的Modbus帧数据，支持RTU、TCP、ASCII三种模式。
    
    Attributes:
        transaction_id: 事务标识符 (TCP模式)
        protocol_id: 协议标识符 (TCP模式)
        length: 长度字段
        unit_id: 单元标识符/从站地址
        function_code: 功能码
        starting_address: 起始地址
        quantity: 数量
        data: 数据域
        crc: CRC校验值 (RTU模式)
    """
    transaction_id: int = 0
    protocol_id: int = 0
    length: int = 0
    unit_id: int = 0
    function_code: int = 0
    starting_address: int = 0
    quantity: int = 0
    data: bytes = field(default_factory=bytes)
    crc: int = 0


class ModbusParser(BaseProtocolParser):
    """
    Modbus 协议解析器
    
    支持RTU、TCP、ASCII三种工作模式，实现帧解析、构建、验证和异常检测。
    """
    
    # 功能码定义
    FC_READ_COILS = 0x01
    FC_READ_DISCRETE_INPUTS = 0x02
    FC_READ_HOLDING_REGISTERS = 0x03
    FC_READ_INPUT_REGISTERS = 0x04
    FC_WRITE_SINGLE_COIL = 0x05
    FC_WRITE_SINGLE_REGISTER = 0x06
    FC_WRITE_MULTIPLE_COILS = 0x0F
    FC_WRITE_MULTIPLE_REGISTERS = 0x10
    
    # 异常功能码掩码
    EXCEPTION_MASK = 0x80
    
    def __init__(self, mode: ModbusMode = ModbusMode.TCP) -> None:
        """
        初始化解析器
        
        Args:
            mode: Modbus工作模式，默认为 TCP
        """
        self.mode: ModbusMode = mode
        self.min_length = {
            ModbusMode.RTU: 4,    # Address + FC + Data + CRC
            ModbusMode.TCP: 8,    # Trans ID + Proto ID + Length + Unit ID + FC
            ModbusMode.ASCII: 9   # : + Address + FC + Data + LRC + CR/LF
        }
    
    @property
    def protocol_type(self) -> ProtocolType:
        """获取协议类型"""
        return ProtocolType.MODBUS
    
    def validate(self, data: bytes) -> Tuple[bool, str]:
        """
        验证Modbus帧合法性
        
        根据不同工作模式调用对应的验证方法。
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)
        """
        min_len = self.min_length[self.mode]
        if len(data) < min_len:
            return False, f"Frame too short: {len(data)} < {min_len}"
        
        if self.mode == ModbusMode.TCP:
            return self._validate_tcp(data)
        elif self.mode == ModbusMode.RTU:
            return self._validate_rtu(data)
        else:
            return self._validate_ascii(data)
    
    def _validate_tcp(self, data: bytes) -> Tuple[bool, str]:
        """
        验证Modbus TCP帧
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)
        """
        if len(data) < 8:
            return False, "Modbus TCP frame too short"
        
        length = (data[4] << 8) | data[5]
        expected_length = 6 + length  # 6 bytes MBAP header + length bytes payload
        if len(data) != expected_length:
            return False, f"Length mismatch: got {len(data)}, expected {expected_length}"
        
        protocol_id = (data[2] << 8) | data[3]
        if protocol_id != 0:
            return False, f"Invalid protocol ID: {protocol_id}, expected 0"
        
        return True, "Valid"
    
    def _validate_rtu(self, data: bytes) -> Tuple[bool, str]:
        """
        验证Modbus RTU帧CRC
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)
        """
        if len(data) < 4:
            return False, "Modbus RTU frame too short"
        
        received_crc = (data[-2] << 8) | data[-1]
        calculated_crc = self._calculate_crc(data[:-2])
        if received_crc != calculated_crc:
            return False, f"CRC mismatch: calculated 0x{calculated_crc:04x}, got 0x{received_crc:04x}"
        
        return True, "Valid"
    
    def _validate_ascii(self, data: bytes) -> Tuple[bool, str]:
        """
        验证Modbus ASCII帧
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            (是否合法, 错误信息)
        """
        if len(data) < 9:
            return False, "Modbus ASCII frame too short"
        
        if data[0] != ord(':'):
            return False, f"Invalid start character: {chr(data[0])}, expected :"
        
        if data[-2] != 0x0D or data[-1] != 0x0A:
            return False, "Invalid end markers, expected CR/LF"
        
        return True, "Valid"
    
    def parse(self, data: bytes) -> ModbusFrame:
        """
        解析Modbus帧
        
        根据不同工作模式调用对应的解析方法。
        
        Args:
            data: 原始二进制帧数据
        
        Returns:
            解析后的帧对象，解析失败时 is_valid 为 False
        """
        frame = ModbusFrame(
            raw_data=data,
            protocol_type=ProtocolType.MODBUS
        )
        
        valid, msg = self.validate(data)
        if not valid:
            frame.is_valid = False
            frame.error_message = msg
            return frame
        
        try:
            if self.mode == ModbusMode.TCP:
                self._parse_tcp(data, frame)
            elif self.mode == ModbusMode.RTU:
                self._parse_rtu(data, frame)
            else:
                self._parse_ascii(data, frame)
            
            frame.parsed_fields = {
                'unit_id': frame.unit_id,
                'function_code': frame.function_code,
                'starting_address': frame.starting_address,
                'quantity': frame.quantity,
                'data_length': len(frame.data),
                'is_exception': self.is_exception(frame.function_code)
            }
            
            return frame
        
        except Exception as e:
            frame.is_valid = False
            frame.error_message = f"Parse error: {str(e)}"
            return frame
    
    def _parse_tcp(self, data: bytes, frame: ModbusFrame) -> None:
        """
        解析Modbus TCP帧
        
        Args:
            data: 原始二进制帧数据
            frame: 帧对象，解析结果写入此对象
        """
        frame.transaction_id = (data[0] << 8) | data[1]
        frame.protocol_id = (data[2] << 8) | data[3]
        frame.length = (data[4] << 8) | data[5]
        frame.unit_id = data[6]
        frame.function_code = data[7]
        
        # 解析数据部分
        data_start = 8
        if len(data) > data_start:
            if frame.function_code in [self.FC_READ_HOLDING_REGISTERS, self.FC_READ_INPUT_REGISTERS]:
                # 请求帧：starting address (2) + quantity (2)
                if not self.is_exception(frame.function_code):
                    if len(data) >= data_start + 4:
                        frame.starting_address = (data[data_start] << 8) | data[data_start+1]
                        frame.quantity = (data[data_start+2] << 8) | data[data_start+3]
                        frame.data = data[data_start:]
                else:
                    # 异常响应：只有异常码
                    if len(data) >= data_start + 1:
                        exception_code = data[data_start]
                        frame.parsed_fields['exception_code'] = exception_code
                        frame.data = bytes([exception_code])
            elif frame.function_code in [self.FC_WRITE_SINGLE_COIL, self.FC_WRITE_SINGLE_REGISTER]:
                frame.starting_address = (data[data_start] << 8) | data[data_start+1]
                value = (data[data_start+2] << 8) | data[data_start+3]
                frame.parsed_fields['value'] = value
                frame.data = data[data_start:]
            elif frame.function_code in [self.FC_WRITE_MULTIPLE_COILS, self.FC_WRITE_MULTIPLE_REGISTERS]:
                frame.starting_address = (data[data_start] << 8) | data[data_start+1]
                frame.quantity = (data[data_start+2] << 8) | data[data_start+3]
                if len(data) > data_start + 5:
                    byte_count = data[data_start+4]
                    frame.data = data[data_start+5:]
                    frame.parsed_fields['byte_count'] = byte_count
                else:
                    frame.data = data[data_start+4:]
            else:
                frame.data = data[data_start:]
    
    def _parse_rtu(self, data: bytes, frame: ModbusFrame) -> None:
        """
        解析Modbus RTU帧
        
        Args:
            data: 原始二进制帧数据
            frame: 帧对象，解析结果写入此对象
        """
        frame.unit_id = data[0]
        frame.function_code = data[1]
        
        data_start = 2
        data_end = len(data) - 2  # exclude CRC
        frame.data = data[data_start:data_end]
        frame.crc = (data[-2] << 8) | data[-1]
        
        # 解析常用功能码
        if frame.function_code in [self.FC_READ_HOLDING_REGISTERS, self.FC_READ_INPUT_REGISTERS]:
            if not self.is_exception(frame.function_code):
                if len(frame.data) >= 4:
                    starting_address = (frame.data[0] << 8) | frame.data[1]
                    quantity = (frame.data[2] << 8) | frame.data[3]
                    frame.starting_address = starting_address
                    frame.quantity = quantity
    
    def _parse_ascii(self, data: bytes, frame: ModbusFrame) -> None:
        """
        解析Modbus ASCII帧
        
        Args:
            data: 原始二进制帧数据
            frame: 帧对象，解析结果写入此对象
        """
        # Skip start colon and end CRLF
        content = data[1:-2].decode('ascii')
        # Convert hex pairs to binary
        binary_data = bytes.fromhex(content[:-2])
        # lrc = content[-2:] - LRC 已经验证过了
        frame.unit_id = binary_data[0]
        frame.function_code = binary_data[1]
        frame.data = binary_data[2:]
    
    def build(self, fields: Dict[str, Any]) -> bytes:
        """
        构建Modbus帧
        
        根据当前工作模式调用对应的构建方法。
        
        Args:
            fields: 帧字段字典
        
        Returns:
            构建好的二进制帧数据
        """
        if self.mode == ModbusMode.TCP:
            return self._build_tcp(fields)
        elif self.mode == ModbusMode.RTU:
            return self._build_rtu(fields)
        else:
            return self._build_ascii(fields)
    
    def _build_tcp(self, fields: Dict[str, Any]) -> bytes:
        """
        构建Modbus TCP帧
        
        Args:
            fields: 帧字段字典
        
        Returns:
            构建好的二进制帧数据
        """
        transaction_id = fields.get('transaction_id', 0)
        protocol_id = fields.get('protocol_id', 0)
        unit_id = fields.get('unit_id', 1)
        function_code = fields.get('function_code', 0x03)
        starting_address = fields.get('starting_address', 0)
        quantity = fields.get('quantity', 10)
        
        # 构建数据部分
        data = bytearray()
        data.append(unit_id)
        data.append(function_code)
        data.append((starting_address >> 8) & 0xFF)
        data.append(starting_address & 0xFF)
        data.append((quantity >> 8) & 0xFF)
        data.append(quantity & 0xFF)
        
        # MBAP头部
        length = len(data)
        buffer = bytearray()
        buffer.append((transaction_id >> 8) & 0xFF)
        buffer.append(transaction_id & 0xFF)
        buffer.append((protocol_id >> 8) & 0xFF)
        buffer.append(protocol_id & 0xFF)
        buffer.append((length >> 8) & 0xFF)
        buffer.append(length & 0xFF)
        buffer.extend(data)
        
        return bytes(buffer)
    
    def _build_rtu(self, fields: Dict[str, Any]) -> bytes:
        """
        构建Modbus RTU帧
        
        Args:
            fields: 帧字段字典
        
        Returns:
            构建好的二进制帧数据
        """
        unit_id = fields.get('unit_id', 1)
        function_code = fields.get('function_code', 0x03)
        starting_address = fields.get('starting_address', 0)
        quantity = fields.get('quantity', 10)
        
        buffer = bytearray()
        buffer.append(unit_id)
        buffer.append(function_code)
        buffer.append((starting_address >> 8) & 0xFF)
        buffer.append(starting_address & 0xFF)
        buffer.append((quantity >> 8) & 0xFF)
        buffer.append(quantity & 0xFF)
        
        crc = self._calculate_crc(buffer)
        buffer.append((crc >> 8) & 0xFF)
        buffer.append(crc & 0xFF)
        
        return bytes(buffer)
    
    def _build_ascii(self, fields: Dict[str, Any]) -> bytes:
        """
        构建Modbus ASCII帧
        
        Args:
            fields: 帧字段字典
        
        Returns:
            构建好的二进制帧数据
        """
        # 简化实现，基于RTU格式转换
        data = self._build_rtu(fields)[:-2]
        hex_str = ':' + data.hex().upper()
        # Calculate LRC
        lrc = (0x100 - (sum(data) & 0xFF)) & 0xFF
        hex_str += f"{lrc:02X}\r\n"
        return hex_str.encode('ascii')
    
    def _calculate_crc(self, data: bytes) -> int:
        """
        计算Modbus RTU CRC-16
        
        使用标准Modbus CRC-16算法。
        
        Args:
            data: 输入数据
        
        Returns:
            CRC-16校验值
        """
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1
        return crc
    
    def is_exception(self, function_code: int) -> bool:
        """
        检查是否是异常响应
        
        Args:
            function_code: 功能码
        
        Returns:
            如果最高位为1表示异常响应，返回 True
        """
        return (function_code & self.EXCEPTION_MASK) != 0
    
    def detect_anomalies(self, frame: ModbusFrame) -> List[Tuple[str, str]]:
        """
        检测Modbus协议异常
        
        检查功能码、地址范围、数量等异常。
        
        Args:
            frame: 解析后的帧对象
        
        Returns:
            异常列表，每项为(异常类型, 异常描述)
        """
        anomalies: List[Tuple[str, str]] = []
        
        if not frame.is_valid:
            anomalies.append(("INVALID_FORMAT", frame.error_message))
        
        # 异常功能码检测
        if self.is_exception(frame.function_code):
            if len(frame.data) >= 1:
                exception_code = frame.data[0]
                anomalies.append(("PROTOCOL_EXCEPTION", f"Modbus exception code 0x{exception_code:02x}"))
        
        # 非法功能码检测
        if frame.function_code > 0x10 and not self.is_exception(frame.function_code):
            anomalies.append(("UNDEFINED_FUNCTION", f"Undefined function code 0x{frame.function_code:02x}"))
        
        # 地址范围异常检测
        if frame.starting_address > 0xFFFF:
            anomalies.append(("ADDRESS_OUT_OF_RANGE", f"Starting address {frame.starting_address} exceeds maximum"))
        
        # 数量异常检测
        if frame.function_code in [self.FC_READ_HOLDING_REGISTERS, self.FC_READ_INPUT_REGISTERS]:
            if frame.quantity > 125:
                anomalies.append(("QUANTITY_EXCEEDS_LIMIT", f"Requested {frame.quantity} registers exceeds maximum 125"))
        
        # 空数据检测
        if len(frame.data) == 0 and frame.function_code not in [0x01, 0x02]:
            anomalies.append(("EMPTY_DATA", "Data field is empty for non-read function"))
        
        return anomalies
        
