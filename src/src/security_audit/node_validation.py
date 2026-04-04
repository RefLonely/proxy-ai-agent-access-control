"""
代理节点可信验证模块
负责对代理节点身份进行验证，防止恶意代理接入
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import uuid
import hashlib
import logging
from enum import Enum

from ..models.agent import Agent

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """验证状态枚举"""
    VALID = "valid"  # 验证成功
    INVALID = "invalid"  # 验证失败
    SUSPICIOUS = "suspicious"  # 可疑状态
    UNKNOWN = "unknown"  # 未知状态


class ValidationMethod(Enum):
    """验证方法枚举"""
    FINGERPRINT = "fingerprint"  # 设备指纹验证
    CERTIFICATE = "certificate"  # 证书验证
    BEHAVIORAL = "behavioral"  # 行为特征验证
    NETWORK = "network"  # 网络特征验证


@dataclass
class NodeValidationResult:
    """节点验证结果"""
    node_id: str
    status: ValidationStatus
    score: float  # 验证分数 (0-1)
    methods: List[ValidationMethod]  # 使用的验证方法
    details: Dict = field(default_factory=dict)
    validated_at: datetime = field(default_factory=datetime.now)
    
    @property
    def is_trusted(self) -> bool:
        """判断节点是否可信"""
        return self.status == ValidationStatus.VALID and self.score >= 0.7
    
    @property
    def severity(self) -> str:
        """判断验证结果严重程度"""
        if self.status == ValidationStatus.INVALID:
            return "high"
        elif self.status == ValidationStatus.SUSPICIOUS:
            return "medium"
        elif self.status == ValidationStatus.VALID:
            return "low"
        else:
            return "info"


@dataclass
class DeviceFingerprint:
    """设备指纹信息"""
    node_id: str
    hardware_id: str
    os_version: str
    python_version: str
    network_interfaces: List[str]
    mac_addresses: List[str]
    cpu_info: str
    memory_info: str
    disk_info: str
    fingerprint_hash: str = ""
    
    def calculate_hash(self) -> str:
        """计算设备指纹哈希"""
        data = f"{self.hardware_id}{self.os_version}{self.python_version}"
        for interface in self.network_interfaces:
            data += interface
        for mac in self.mac_addresses:
            data += mac
        data += f"{self.cpu_info}{self.memory_info}{self.disk_info}"
        
        self.fingerprint_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return self.fingerprint_hash


class NodeValidationManager:
    """节点验证管理器"""
    
    def __init__(self):
        self.validated_nodes: Dict[str, DeviceFingerprint] = {}
        self.validation_history: List[NodeValidationResult] = []
        self.validation_rules: Dict[ValidationMethod, float] = {
            ValidationMethod.FINGERPRINT: 0.4,
            ValidationMethod.CERTIFICATE: 0.3,
            ValidationMethod.BEHAVIORAL: 0.2,
            ValidationMethod.NETWORK: 0.1
        }
    
    def generate_device_fingerprint(self, agent: Agent) -> DeviceFingerprint:
        """生成设备指纹"""
        import platform
        import psutil
        
        interfaces = []
        mac_addresses = []
        
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interfaces.append(interface)
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        mac_addresses.append(addr.address)
        except Exception as e:
            logger.warning(f"Failed to get network interfaces: {e}")
        
        fingerprint = DeviceFingerprint(
            node_id=agent.agent_id,
            hardware_id=platform.node(),
            os_version=f"{platform.system()} {platform.release()}",
            python_version=platform.python_version(),
            network_interfaces=interfaces,
            mac_addresses=mac_addresses,
            cpu_info=platform.processor(),
            memory_info=f"{psutil.virtual_memory().total // (1024*1024*1024)}GB",
            disk_info=f"{psutil.disk_usage('/').total // (1024*1024*1024)}GB"
        )
        
        fingerprint.calculate_hash()
        return fingerprint
    
    def validate_node(self, agent: Agent, fingerprint: Optional[DeviceFingerprint] = None) -> NodeValidationResult:
        """验证节点身份"""
        if not fingerprint:
            fingerprint = self.generate_device_fingerprint(agent)
        
        validation_methods = []
        validation_score = 0.0
        details = {}
        
        # 设备指纹验证
        validation_methods.append(ValidationMethod.FINGERPRINT)
        if agent.agent_id in self.validated_nodes:
            # 与已存储的指纹进行比较
            stored_fingerprint = self.validated_nodes[agent.agent_id]
            if stored_fingerprint.fingerprint_hash == fingerprint.fingerprint_hash:
                validation_score += self.validation_rules[ValidationMethod.FINGERPRINT]
                details["fingerprint_match"] = True
            else:
                details["fingerprint_match"] = False
                details["stored_hash"] = stored_fingerprint.fingerprint_hash
                details["current_hash"] = fingerprint.fingerprint_hash
        else:
            # 新节点，直接通过指纹验证
            validation_score += self.validation_rules[ValidationMethod.FINGERPRINT]
            details["fingerprint_match"] = True
            details["is_new_node"] = True
        
        # 证书验证（模拟）
        validation_methods.append(ValidationMethod.CERTIFICATE)
        if self._validate_certificate(agent):
            validation_score += self.validation_rules[ValidationMethod.CERTIFICATE]
            details["certificate_valid"] = True
        else:
            details["certificate_valid"] = False
        
        # 行为特征验证（模拟）
        validation_methods.append(ValidationMethod.BEHAVIORAL)
        if self._validate_behavioral(agent):
            validation_score += self.validation_rules[ValidationMethod.BEHAVIORAL]
            details["behavioral_valid"] = True
        else:
            details["behavioral_valid"] = False
        
        # 网络特征验证（模拟）
        validation_methods.append(ValidationMethod.NETWORK)
        if self._validate_network(agent):
            validation_score += self.validation_rules[ValidationMethod.NETWORK]
            details["network_valid"] = True
        else:
            details["network_valid"] = False
        
        # 确定验证状态
        status = ValidationStatus.VALID
        if validation_score < 0.3:
            status = ValidationStatus.INVALID
        elif validation_score < 0.7:
            status = ValidationStatus.SUSPICIOUS
        
        # 存储验证结果
        self.validated_nodes[agent.agent_id] = fingerprint
        result = NodeValidationResult(
            node_id=agent.agent_id,
            status=status,
            score=validation_score,
            methods=validation_methods,
            details=details
        )
        self.validation_history.append(result)
        
        logger.info(f"Node validation for {agent.agent_id}: {status} ({validation_score:.2f})")
        return result
    
    def _validate_certificate(self, agent: Agent) -> bool:
        """证书验证（模拟）"""
        return agent.agent_id.startswith("grid-")
    
    def _validate_behavioral(self, agent: Agent) -> bool:
        """行为特征验证（模拟）"""
        return True
    
    def _validate_network(self, agent: Agent) -> bool:
        """网络特征验证（模拟）"""
        return True
    
    def get_validation_result(self, node_id: str) -> Optional[NodeValidationResult]:
        """获取节点验证结果"""
        results = [r for r in self.validation_history if r.node_id == node_id]
        if results:
            return results[-1]
        return None
    
    def get_trusted_nodes(self) -> List[str]:
        """获取可信节点列表"""
        trusted = []
        seen_nodes = set()
        for result in self.validation_history:
            if result.node_id not in seen_nodes and result.is_trusted:
                trusted.append(result.node_id)
                seen_nodes.add(result.node_id)
        return trusted
    
    def get_suspicious_nodes(self) -> List[str]:
        """获取可疑节点列表"""
        suspicious = []
        seen_nodes = set()
        for result in self.validation_history:
            if result.node_id not in seen_nodes and result.status == ValidationStatus.SUSPICIOUS:
                suspicious.append(result.node_id)
                seen_nodes.add(result.node_id)
        return suspicious
    
    def get_invalid_nodes(self) -> List[str]:
        """获取无效节点列表"""
        invalid = []
        seen_nodes = set()
        for result in self.validation_history:
            if result.node_id not in seen_nodes and result.status == ValidationStatus.INVALID:
                invalid.append(result.node_id)
                seen_nodes.add(result.node_id)
        return invalid
    
    def get_validation_summary(self) -> Dict:
        """获取验证统计信息"""
        nodes_count = len({r.node_id for r in self.validation_history})
        trusted_nodes = self.get_trusted_nodes()
        suspicious_nodes = self.get_suspicious_nodes()
        invalid_nodes = self.get_invalid_nodes()
        
        return {
            "total_nodes": nodes_count,
            "trusted_nodes": len(trusted_nodes),
            "suspicious_nodes": len(suspicious_nodes),
            "invalid_nodes": len(invalid_nodes),
            "trust_ratio": len(trusted_nodes) / nodes_count if nodes_count > 0 else 0.0
        }
    
    def revoke_trust(self, node_id: str) -> bool:
        """撤销节点信任"""
        if node_id in self.validated_nodes:
            del self.validated_nodes[node_id]
            logger.warning(f"Trust revoked for node {node_id}")
            return True
        return False
    
    def reset_validation(self) -> None:
        """重置验证状态"""
        self.validated_nodes.clear()
        self.validation_history.clear()
        logger.info("Node validation status reset")
