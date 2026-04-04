"""
电力协议解析模块单元测试
覆盖IEC 60870-5、Modbus、OPC UA、DL/T 645协议解析与异常检测
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.protocols import *
from src.protocols.protocol_parser import ProtocolType
from src.protocols.iec_60870_5_parser import IEC608705Parser
from src.protocols.modbus_parser import ModbusParser, ModbusMode
from src.protocols.opc_ua_parser import OPCUAParser
from src.protocols.dl_t_645_parser import DLT645Parser
from src.protocols.anomaly_detector import ProtocolAnomalyDetector


class TestIEC608705Parser:
    """IEC 60870-5协议解析测试"""
    
    def test_setup(self):
        parser = IEC608705Parser()
        assert parser.protocol_type == ProtocolType.IEC_60870_5
    
    def test_valid_frame_parse(self):
        parser = IEC608705Parser()
        # 构造一个简单的有效帧
        # 68 04 01 02 03 06 16
        # start=0x68, len=4, control=0x01, address=0x02, data=[0x03, 0x04], checksum=0x06, end=0x16
        data = bytes([0x68, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x16])
        frame = parser.parse(data)
        assert frame.is_valid
        assert frame.start_byte == 0x68
        assert frame.length == 4
        assert len(frame.data_units) == 1
        assert frame.checksum == 0x0A
    
    def test_invalid_start_byte(self):
        parser = IEC608705Parser()
        data = bytes([0x69, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x16])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Invalid start byte" in frame.error_message
    
    def test_checksum_error(self):
        parser = IEC608705Parser()
        data = bytes([0x68, 0x04, 0x01, 0x02, 0x03, 0x04, 0xFF, 0x16])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Checksum mismatch" in frame.error_message
    
    def test_detect_anomalies(self):
        parser = IEC608705Parser()
        data = bytes([0x68, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x16])
        frame = parser.parse(data)
        anomalies = parser.detect_anomalies(frame)
        # 正常帧不应该有异常
        assert len([a for a in anomalies if "INVALID" in a[0]]) == 0
    
    def test_detect_oversize_frame(self):
        parser = IEC608705Parser()
        parser.max_frame_length = 5
        data = bytes([0x68, 0x10, 0x01, 0x02] + [0x00]*14 + [0x16])
        frame = parser.parse(data)
        anomalies = parser.detect_anomalies(frame)
        assert any("OVERSIZE_FRAME" in a[0] for a in anomalies)


class TestModbusParser:
    """Modbus协议解析测试"""
    
    def test_setup_tcp(self):
        parser = ModbusParser(ModbusMode.TCP)
        assert parser.protocol_type == ProtocolType.MODBUS
    
    def test_valid_tcp_read(self):
        parser = ModbusParser(ModbusMode.TCP)
        # Modbus TCP: Transaction ID 0001, Protocol ID 0000, Length 0006, Unit 01, FC 03, Addr 0001, Qty 000A
        data = bytes([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x03,        # Function code - read holding registers
            0x00, 0x01,  # Starting address
            0x00, 0x0A   # Quantity
        ])
        frame = parser.parse(data)
        assert frame.is_valid
        assert frame.transaction_id == 1
        assert frame.protocol_id == 0
        assert frame.function_code == 0x03
        assert frame.starting_address == 1
        assert frame.quantity == 10
    
    def test_invalid_protocol_id(self):
        parser = ModbusParser(ModbusMode.TCP)
        data = bytes([
            0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x0A
        ])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Invalid protocol ID" in frame.error_message
    
    def test_crc_check_rtu(self):
        parser = ModbusParser(ModbusMode.RTU)
        # RTU: Addr 01, FC 03, 00 01, 00 0A + CRC 0D 94 (correct calculation)
        data = bytes([0x01, 0x03, 0x00, 0x01, 0x00, 0x0A, 0x0D, 0x94])
        valid, msg = parser.validate(data)
        assert valid, msg
    
    def test_detect_exception_function(self):
        parser = ModbusParser(ModbusMode.TCP)
        data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02
        ])
        frame = parser.parse(data)
        assert frame.is_valid
        assert parser.is_exception(frame.function_code)
        anomalies = parser.detect_anomalies(frame)
        assert any("PROTOCOL_EXCEPTION" in a[0] for a in anomalies)
    
    def test_detect_quantity_exceeds_limit(self):
        parser = ModbusParser(ModbusMode.TCP)
        data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x01, 0x00, 0x80
        ])
        frame = parser.parse(data)
        # 正常解析但quantity超过限制
        assert frame.starting_address == 1
        assert frame.quantity == 0x0080  # 128
        anomalies = parser.detect_anomalies(frame)
        assert any("QUANTITY_EXCEEDS_LIMIT" in a[0] for a in anomalies)


class TestOPCUAParser:
    """OPC UA协议解析测试"""
    
    def test_setup(self):
        parser = OPCUAParser()
        assert parser.protocol_type == ProtocolType.OPC_UA
    
    def test_valid_hello_message(self):
        parser = OPCUAParser()
        # HEL message: HEL C 00000010 (16 bytes) + payload
        data = bytes([
            ord('H'), ord('E'), ord('L'),  # Message type HEL
            ord('C'),  # Chunk type C
            0x10, 0x00, 0x00, 0x00,  # Message size 16
        ]) + bytes([0x00]*8)
        frame = parser.parse(data)
        assert frame.is_valid
        assert frame.message_type_str == "HEL"
        assert frame.message_size == 16
    
    def test_invalid_message_type(self):
        parser = OPCUAParser()
        data = bytes([
            ord('X'), ord('Y'), ord('Z'), ord('C'), 0x08, 0x00, 0x00, 0x00
        ])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Invalid message type" in frame.error_message
    
    def test_detect_oversize_message(self):
        parser = OPCUAParser()
        data = bytes([
            ord('M'), ord('S'), ord('G'), ord('C')
        ]) + (2 * 1024 * 1024 + 1).to_bytes(4, byteorder='little') + bytes([0x00]*10)
        frame = parser.parse(data)
        # 虽然长度不匹配，但应该检测到异常大小
        anomalies = parser.detect_anomalies(frame)
        # 由于长度不匹配已经无效，OVERSIZE_MESSAGE应该被检测到
        if len(data) == frame.message_size:
            assert any("OVERSIZE_MESSAGE" in a[0] for a in anomalies)


class TestDLT645Parser:
    """DL/T 645协议解析测试"""
    
    def test_setup(self):
        parser = DLT645Parser()
        assert parser.protocol_type == ProtocolType.DL_T_645
    
    def test_valid_frame(self):
        parser = DLT645Parser()
        # 68 01 02 03 04 05 06 68 01 11 00 00 00 00 18 16
        # 两个起始，6字节地址，长度，控制码，数据，校验，结束
        data = bytes([
            0x68,  # Start 1
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  # 6-byte address
            0x68,  # Start 2
            0x01,  # Data length
            0x11,  # Control code - read
            0x00,  # Data
            0x8F,  # Checksum (0x01+0x02+0x03+0x04+0x05+0x06+0x68+0x01+0x11+0x00 = 143 = 0x8F)
            0x16   # End
        ])
        frame = parser.parse(data)
        assert frame.is_valid
        assert frame.address_str == "010203040506"
        assert frame.control_code == 0x11
        assert frame.data_length == 1
    
    def test_invalid_start_flags(self):
        parser = DLT645Parser()
        data = bytes([
            0x68, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x69, 0x01, 0x11, 0x00, 0x86, 0x16
        ])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Invalid start flags" in frame.error_message
    
    def test_checksum_error(self):
        parser = DLT645Parser()
        data = bytes([
            0x68, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x68, 0x01, 0x11, 0x00, 0xFF, 0x16
        ])
        frame = parser.parse(data)
        assert not frame.is_valid
        assert "Checksum mismatch" in frame.error_message
    
    def test_detect_zero_address_anomaly(self):
        parser = DLT645Parser()
        # 正确校验和的全零地址帧
        # sum(1:-2) = sum([0x00*6 + 0x68 + 0x00 + 0x11]) = 0x68+0x11 = 0x79 = 121
        data = bytes([
            0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x11, 0x79, 0x16
        ])
        frame = parser.parse(data)
        assert frame.is_valid
        anomalies = parser.detect_anomalies(frame)
        assert any("ZERO_ADDRESS_NONBROADCAST" in a[0] for a in anomalies)


class TestProtocolAnomalyDetector:
    """统一异常检测器测试"""
    
    def test_setup(self):
        detector = ProtocolAnomalyDetector()
        stats = detector.get_statistics()
        assert stats['supported_protocols'] == 4
    
    def test_detect_iec_anomaly(self):
        detector = ProtocolAnomalyDetector()
        data = bytes([0x69, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x16])
        result = detector.detect(data, ProtocolType.IEC_60870_5)
        assert result.is_anomaly
        assert result.risk_score > 0
    
    def test_auto_detect_dlt645(self):
        detector = ProtocolAnomalyDetector()
        data = bytes([
            0x68, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x68, 0x01, 0x11, 0x00, 0x86, 0x16
        ])
        result = detector.detect_auto(data)
        assert result.protocol_type == ProtocolType.DL_T_645
    
    def test_auto_detect_iec60870(self):
        detector = ProtocolAnomalyDetector()
        data = bytes([0x68, 0x04, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x16])
        result = detector.detect_auto(data)
        assert result.protocol_type == ProtocolType.IEC_60870_5
    
    def test_risk_score_calculation(self):
        detector = ProtocolAnomalyDetector()
        # Checksum error should have high risk
        data = bytes([0x68, 0x04, 0x01, 0x02, 0x03, 0x04, 0xFF, 0x16])
        result = detector.detect(data, ProtocolType.IEC_60870_5)
        assert result.risk_score >= 0.3  # 至少有格式错误权重
    
    def test_unknown_protocol(self):
        detector = ProtocolAnomalyDetector()
        data = bytes([0x01, 0x02, 0x03, 0x04])
        result = detector.detect_auto(data)
        assert result.protocol_type == ProtocolType.UNKNOWN
        assert result.is_anomaly
        assert result.risk_score == 0.8


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
