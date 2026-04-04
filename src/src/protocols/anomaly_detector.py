"""
电力协议统一异常检测器
整合各协议异常检测结果，进行综合分析
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import logging

from .protocol_parser import ProtocolData, ProtocolType, BaseProtocolParser
from .iec_60870_5_parser import IEC608705Parser, IEC608705Frame
from .modbus_parser import ModbusParser, ModbusFrame
from .opc_ua_parser import OPCUAParser, OPCUAMessage
from .dl_t_645_parser import DLT645Parser, DLT645Frame


logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """
    异常类型枚举
    
    定义了电力协议中可能出现的各类异常类型。
    """
    FORMAT_ERROR = "format_error"          # 格式错误
    CHECKSUM_ERROR = "checksum_error"      # 校验错误
    PROTOCOL_EXCEPTION = "protocol_exception"  # 协议异常响应
    UNDEFINED_FUNCTION = "undefined_function"  # 未定义功能
    ADDRESS_OUT_OF_RANGE = "address_out_of_range"  # 地址越界
    OVERSIZE_MESSAGE = "oversize_message"  # 消息过大
    FREQUENCY_ANOMALY = "frequency_anomaly"  # 频率异常
    SEQUENCE_ANOMALY = "sequence_anomaly"  # 序号异常
    ACCESS_PATTERN_ANOMALY = "access_pattern_anomaly"  # 访问模式异常


@dataclass
class AnomalyResult:
    """
    异常检测结果
    
    存储协议异常检测的结果，包含异常类型、风险评分等信息。
    
    Attributes:
        protocol_type: 检测的协议类型
        is_anomaly: 是否检测到异常
        anomaly_count: 异常数量
        anomalies: 异常列表，每项为(异常类型, 异常描述)
        risk_score: 风险评分 (0.0-1.0)，数值越高风险越大
        raw_data: 原始二进制数据
    """
    protocol_type: ProtocolType
    is_anomaly: bool
    anomaly_count: int = 0
    anomalies: List[Tuple[str, str]] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0-1.0 风险评分
    raw_data: bytes = field(default_factory=bytes)
    
    def __post_init__(self) -> None:
        """自动计算异常数量"""
        self.anomaly_count = len(self.anomalies)


class ProtocolAnomalyDetector:
    """
    电力协议统一异常检测器
    
    整合多种电力协议解析器，对接收的二进制数据进行协议自动识别和异常检测，
    计算综合风险评分，支持扩展自定义协议解析器。
    """
    
    def __init__(self) -> None:
        """初始化异常检测器，注册默认支持的协议解析器"""
        self.parsers: Dict[ProtocolType, BaseProtocolParser] = {
            ProtocolType.IEC_60870_5: IEC608705Parser(),
            ProtocolType.MODBUS: ModbusParser(),
            ProtocolType.OPC_UA: OPCUAParser(),
            ProtocolType.DL_T_645: DLT645Parser()
        }
        
        # 异常权重配置 - 不同异常类型对风险评分的贡献不同
        self.anomaly_weights: Dict[str, float] = {
            "INVALID_FORMAT": 0.3,
            "CHECKSUM_ERROR": 0.8,
            "OVERSIZE_FRAME": 0.4,
            "UNDEFINED_FUNCTION": 0.6,
            "ADDRESS_OUT_OF_RANGE": 0.5,
            "PROTOCOL_EXCEPTION": 0.5,
            "PROTOCOL_ERROR": 0.7,
            "BROADCAST_ADDRESS": 0.1,
        }
    
    def detect(self, data: bytes, protocol_type: ProtocolType) -> AnomalyResult:
        """
        对指定协议数据进行异常检测
        
        Args:
            data: 原始二进制数据
            protocol_type: 已知的协议类型
        
        Returns:
            异常检测结果，包含风险评分和异常列表
        """
        result = AnomalyResult(
            protocol_type=protocol_type,
            is_anomaly=False,
            raw_data=data
        )
        
        parser = self.parsers.get(protocol_type)
        if not parser:
            result.anomalies.append(("UNSUPPORTED_PROTOCOL", 
                                     f"No parser available for {protocol_type}"))
            result.is_anomaly = True
            result.risk_score = 0.5
            return result
        
        # 解析数据
        parsed: ProtocolData = parser.parse(data)
        if not parsed.is_valid:
            result.anomalies.append(("PARSE_FAILED", parsed.error_message))
        
        # 调用协议特定的异常检测
        anomalies: List[Tuple[str, str]] = []
        if protocol_type == ProtocolType.IEC_60870_5 and isinstance(parsed, IEC608705Frame):
            if hasattr(parser, 'detect_anomalies'):
                anomalies = parser.detect_anomalies(parsed)
        elif protocol_type == ProtocolType.MODBUS and isinstance(parsed, ModbusFrame):
            if hasattr(parser, 'detect_anomalies'):
                anomalies = parser.detect_anomalies(parsed)
        elif protocol_type == ProtocolType.OPC_UA and isinstance(parsed, OPCUAMessage):
            if hasattr(parser, 'detect_anomalies'):
                anomalies = parser.detect_anomalies(parsed)
        elif protocol_type == ProtocolType.DL_T_645 and isinstance(parsed, DLT645Frame):
            if hasattr(parser, 'detect_anomalies'):
                anomalies = parser.detect_anomalies(parsed)
        
        result.anomalies.extend(anomalies)
        
        # 计算风险评分
        result.risk_score = self._calculate_risk_score(result.anomalies)
        result.is_anomaly = result.risk_score > 0.0
        
        return result
    
    def detect_auto(self, data: bytes) -> AnomalyResult:
        """
        自动检测协议并进行异常检测
        
        自动识别数据的协议类型，然后进行异常检测。
        如果无法识别协议，直接返回高风险结果。
        
        Args:
            data: 原始二进制数据
        
        Returns:
            异常检测结果
        """
        # 尝试匹配协议特征
        detected_type = self._autodetect_protocol(data)
        if detected_type == ProtocolType.UNKNOWN:
            return AnomalyResult(
                protocol_type=ProtocolType.UNKNOWN,
                is_anomaly=True,
                risk_score=0.8,
                anomalies=[("PROTOCOL_DETECTION_FAILED", "Could not auto-detect protocol")],
                raw_data=data
            )
        
        return self.detect(data, detected_type)
    
    def _autodetect_protocol(self, data: bytes) -> ProtocolType:
        """
        根据协议特征自动检测协议类型
        
        使用协议特有的帧特征进行识别，优先检测特征更明确的协议。
        
        Args:
            data: 原始二进制数据
        
        Returns:
            检测到的协议类型，如果无法识别返回 UNKNOWN
        """
        if len(data) < 4:
            return ProtocolType.UNKNOWN
        
        # DL/T 645 检测 - 必须两个 0x68，特征最明确，先检测这个
        if len(data) >= 8 and data[0] == 0x68 and data[7] == 0x68 and data[-1] == 0x16:
            return ProtocolType.DL_T_645
        
        # IEC 60870-5 检测
        if data[0] == 0x68 and data[-1] == 0x16:
            return ProtocolType.IEC_60870_5
        
        # Modbus TCP 检测
        if len(data) >= 8:
            protocol_id = (data[2] << 8) | data[3]
            if protocol_id == 0:
                return ProtocolType.MODBUS
        
        # OPC UA 检测
        if len(data) >= 3:
            msg_type = data[0:3].decode('ascii', errors='replace')
            if msg_type in ['HEL', 'ACK', 'OPN', 'MSG', 'ERR']:
                return ProtocolType.OPC_UA
        
        return ProtocolType.UNKNOWN
    
    def _calculate_risk_score(self, anomalies: List[Tuple[str, str]]) -> float:
        """
        计算总体风险评分
        
        结合最大异常权重和总权重，考虑多个异常的叠加效应，
        使用饱和函数防止评分溢出。70% 权重给最严重的异常，
        30% 给总权重，避免单个严重异常被多个小异常稀释。
        
        Args:
            anomalies: 异常列表
        
        Returns:
            综合风险评分 (0.0-1.0)
        """
        if not anomalies:
            return 0.0
        
        total_weight = 0.0
        max_weight = 0.0
        
        for anomaly_type, _ in anomalies:
            weight = self.anomaly_weights.get(anomaly_type, 0.2)
            total_weight += weight
            if weight > max_weight:
                max_weight = weight
        
        # 考虑多个异常叠加效应，但用最大值饱和
        score = 0.7 * max_weight + 0.3 * min(total_weight, 1.0)
        return min(score, 1.0)
    
    def add_parser(self, protocol_type: ProtocolType, parser: BaseProtocolParser) -> None:
        """
        添加自定义协议解析器
        
        支持用户扩展自定义协议解析器，实现对新协议的支持。
        
        Args:
            protocol_type: 协议类型
            parser: 协议解析器实例，必须继承 BaseProtocolParser
        """
        self.parsers[protocol_type] = parser
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取检测统计信息
        
        Returns:
            统计信息字典，包含支持的协议数量和协议列表
        """
        return {
            'supported_protocols': len(self.parsers),
            'protocol_list': [p.value for p in self.parsers.keys()]
        }
