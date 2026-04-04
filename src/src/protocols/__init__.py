"""
电力协议解析与异常检测模块
支持工业电力系统常见协议:
- IEC 60870-5 (远动协议)
- Modbus (工业控制协议)
- OPC UA (开放平台通信统一架构)
- DL/T 645 (多功能电能表通信协议)
"""
from .protocol_parser import BaseProtocolParser, ProtocolData, ProtocolType, ProtocolException
from .iec_60870_5_parser import IEC608705Parser, IEC608705Frame, IEC608705Exception
from .modbus_parser import ModbusParser, ModbusFrame, ModbusException, ModbusMode
from .opc_ua_parser import OPCUAParser, OPCUAMessage, OPCUAException, OPCUAMessageType
from .dl_t_645_parser import DLT645Parser, DLT645Frame, DLT645Exception
from .anomaly_detector import ProtocolAnomalyDetector, AnomalyResult, AnomalyType

__all__ = [
    'BaseProtocolParser',
    'ProtocolData',
    'ProtocolType',
    'ProtocolException',
    'IEC608705Parser',
    'IEC608705Frame',
    'IEC608705Exception',
    'ModbusParser',
    'ModbusFrame',
    'ModbusException',
    'ModbusMode',
    'OPCUAParser',
    'OPCUAMessage',
    'OPCUAException',
    'OPCUAMessageType',
    'DLT645Parser',
    'DLT645Frame',
    'DLT645Exception',
    'ProtocolAnomalyDetector',
    'AnomalyResult',
    'AnomalyType'
]
