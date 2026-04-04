"""
节点安全配置管控模块
负责对代理节点的安全配置进行集中管理和动态调整
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigurationType(Enum):
    """配置类型枚举"""
    SECURITY_POLICY = "security_policy"  # 安全策略配置
    NETWORK_SETTINGS = "network_settings"  # 网络配置
    AUDIT_SETTINGS = "audit_settings"  # 审计配置
    PERMISSION_SETTINGS = "permission_settings"  # 权限配置
    MONITORING_SETTINGS = "monitoring_settings"  # 监控配置


class ConfigurationLevel(Enum):
    """配置级别枚举"""
    GLOBAL = "global"  # 全局配置
    REGIONAL = "regional"  # 区域配置
    LOCAL = "local"  # 本地配置


@dataclass
class SecurityConfiguration:
    """安全配置"""
    config_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_id: str = ""
    config_type: ConfigurationType = ConfigurationType.SECURITY_POLICY
    config_level: ConfigurationLevel = ConfigurationLevel.GLOBAL
    config_data: Dict = field(default_factory=dict)
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    version: int = 1
    is_active: bool = True
    
    def update(self, new_config: Dict) -> None:
        """更新配置"""
        self.config_data = new_config
        self.updated_at = datetime.now()
        self.version += 1
        logger.info(f"Configuration {self.config_id} updated to version {self.version}")
    
    def validate(self) -> bool:
        """验证配置的有效性"""
        if not self.config_data:
            return False
        
        # 简单验证安全策略配置
        if self.config_type == ConfigurationType.SECURITY_POLICY:
            required_fields = ["min_trust_threshold", "suspicious_threshold", "access_control_enabled"]
            for field in required_fields:
                if field not in self.config_data:
                    logger.warning(f"Security policy missing required field: {field}")
                    return False
        
        return True


@dataclass
class ConfigurationHistory:
    """配置变更历史"""
    history_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    config_id: str = ""
    version: int = 1
    config_data: Dict = field(default_factory=dict)
    change_type: str = "update"  # "create", "update", "delete"
    changed_by: str = ""
    change_reason: str = ""
    changed_at: datetime = field(default_factory=datetime.now)


class ConfigurationManager:
    """配置管理器"""
    
    def __init__(self):
        self.configurations: Dict[str, SecurityConfiguration] = {}
        self.history: Dict[str, List[ConfigurationHistory]] = {}
        self.default_configurations: Dict[ConfigurationType, Dict] = self._create_default_configs()
        
        # 初始化默认配置
        for config_type, default_data in self.default_configurations.items():
            default_config = SecurityConfiguration(
                config_type=config_type,
                config_level=ConfigurationLevel.GLOBAL,
                config_data=default_data,
                description=f"Default {config_type.value} configuration",
                is_active=True
            )
            self.configurations[default_config.config_id] = default_config
            self.history[default_config.config_id] = [
                ConfigurationHistory(
                    config_id=default_config.config_id,
                    version=1,
                    config_data=default_data,
                    change_type="create",
                    changed_by="system",
                    change_reason="Initial default configuration"
                )
            ]
    
    def _create_default_configs(self) -> Dict[ConfigurationType, Dict]:
        """创建默认配置"""
        return {
            ConfigurationType.SECURITY_POLICY: {
                "min_trust_threshold": 0.7,
                "suspicious_threshold": 0.3,
                "access_control_enabled": True,
                "anomaly_detection_enabled": True,
                "auto_response_enabled": True,
                "trust_decay_factor": 0.8
            },
            ConfigurationType.NETWORK_SETTINGS: {
                "port_range": "18789-18799",
                "allowed_ips": ["127.0.0.1", "192.168.0.0/16"],
                "blocked_ips": [],
                "connection_timeout": 30,
                "retry_attempts": 3
            },
            ConfigurationType.AUDIT_SETTINGS: {
                "enabled": True,
                "log_level": "INFO",
                "log_rotation": "daily",
                "retention_period": 90,
                "include_metadata": False
            },
            ConfigurationType.PERMISSION_SETTINGS: {
                "default_permissions": ["read", "write", "execute"],
                "restricted_operations": ["admin"],
                "permission_expiration": 3600,
                "enforce_least_privilege": True
            },
            ConfigurationType.MONITORING_SETTINGS: {
                "enabled": True,
                "metrics_collection": ["cpu", "memory", "disk", "network"],
                "sampling_interval": 60,
                "alert_thresholds": {
                    "cpu_usage": 80,
                    "memory_usage": 90,
                    "disk_usage": 95
                },
                "alert_notifications": ["email", "slack"]
            }
        }
    
    def get_configuration(self, node_id: str, config_type: ConfigurationType) -> Optional[SecurityConfiguration]:
        """获取节点配置（先查找本地配置，不存在则返回全局配置）"""
        # 查找节点本地配置
        for config in self.configurations.values():
            if config.node_id == node_id and config.config_type == config_type and config.is_active:
                return config
        
        # 查找全局配置
        for config in self.configurations.values():
            if config.config_level == ConfigurationLevel.GLOBAL and config.config_type == config_type and config.is_active:
                return config
        
        return None
    
    def create_configuration(self, node_id: str, config_type: ConfigurationType, config_data: Dict, description: str = "") -> SecurityConfiguration:
        """创建新配置"""
        config = SecurityConfiguration(
            node_id=node_id,
            config_type=config_type,
            config_level=ConfigurationLevel.LOCAL if node_id else ConfigurationLevel.GLOBAL,
            config_data=config_data,
            description=description
        )
        
        if not config.validate():
            logger.warning(f"Invalid configuration for node {node_id}")
            return self.get_configuration(node_id, config_type)
        
        self.configurations[config.config_id] = config
        
        # 创建历史记录
        if config.config_id not in self.history:
            self.history[config.config_id] = []
        self.history[config.config_id].append(
            ConfigurationHistory(
                config_id=config.config_id,
                version=1,
                config_data=config_data,
                change_type="create",
                changed_by="system",
                change_reason="New configuration created"
            )
        )
        
        logger.info(f"Created configuration {config.config_id} for node {node_id}")
        return config
    
    def update_configuration(self, config_id: str, new_config: Dict, changed_by: str = "system", change_reason: str = "") -> Optional[SecurityConfiguration]:
        """更新配置"""
        if config_id not in self.configurations:
            logger.error(f"Configuration {config_id} not found")
            return None
        
        config = self.configurations[config_id]
        
        # 创建历史记录
        if config_id not in self.history:
            self.history[config_id] = []
        self.history[config_id].append(
            ConfigurationHistory(
                config_id=config_id,
                version=config.version,
                config_data=config.config_data,
                change_type="update",
                changed_by=changed_by,
                change_reason=change_reason
            )
        )
        
        config.update(new_config)
        
        logger.info(f"Updated configuration {config_id}")
        return config
    
    def delete_configuration(self, config_id: str, changed_by: str = "system", change_reason: str = "") -> bool:
        """删除配置"""
        if config_id not in self.configurations:
            logger.error(f"Configuration {config_id} not found")
            return False
        
        config = self.configurations[config_id]
        config.is_active = False
        config.updated_at = datetime.now()
        
        # 创建历史记录
        self.history[config_id].append(
            ConfigurationHistory(
                config_id=config_id,
                version=config.version,
                config_data=config.config_data,
                change_type="delete",
                changed_by=changed_by,
                change_reason=change_reason
            )
        )
        
        logger.info(f"Deleted configuration {config_id}")
        return True
    
    def apply_configuration(self, node_id: str, config_id: str) -> bool:
        """将配置应用到节点"""
        if config_id not in self.configurations:
            logger.error(f"Configuration {config_id} not found")
            return False
        
        config = self.configurations[config_id]
        
        # 检查配置是否已经是节点本地配置
        if config.node_id == node_id:
            logger.info(f"Configuration {config_id} is already applied to node {node_id}")
            return True
        
        # 创建节点本地配置副本
        node_config = SecurityConfiguration(
            node_id=node_id,
            config_type=config.config_type,
            config_level=ConfigurationLevel.LOCAL,
            config_data=config.config_data.copy(),
            description=f"Copy of {config.description}",
            is_active=True
        )
        
        self.configurations[node_config.config_id] = node_config
        self.history[node_config.config_id] = [
            ConfigurationHistory(
                config_id=node_config.config_id,
                version=1,
                config_data=node_config.config_data,
                change_type="create",
                changed_by="system",
                change_reason=f"Applied configuration from {config.config_id}"
            )
        ]
        
        logger.info(f"Applied configuration {config_id} to node {node_id} as {node_config.config_id}")
        return True
    
    def get_configuration_history(self, config_id: str) -> List[ConfigurationHistory]:
        """获取配置历史"""
        return self.history.get(config_id, [])
    
    def compare_configurations(self, config1_id: str, config2_id: str) -> Dict[str, Any]:
        """比较两个配置的差异"""
        config1 = self.configurations.get(config1_id)
        config2 = self.configurations.get(config2_id)
        
        if not config1 or not config2:
            return {"error": "Configuration not found"}
        
        differences = {}
        
        # 比较配置数据
        for key in set(list(config1.config_data.keys()) + list(config2.config_data.keys())):
            value1 = config1.config_data.get(key)
            value2 = config2.config_data.get(key)
            if value1 != value2:
                differences[key] = {
                    "config1": value1,
                    "config2": value2
                }
        
        return {
            "config1_info": {
                "config_id": config1.config_id,
                "version": config1.version,
                "config_type": config1.config_type.value,
                "config_level": config1.config_level.value
            },
            "config2_info": {
                "config_id": config2.config_id,
                "version": config2.version,
                "config_type": config2.config_type.value,
                "config_level": config2.config_level.value
            },
            "differences": differences
        }
    
    def get_configuration_summary(self) -> Dict:
        """获取配置统计信息"""
        config_type_counts: Dict[str, int] = {}
        config_level_counts: Dict[str, int] = {}
        
        for config in self.configurations.values():
            if config.is_active:
                config_type_counts[config.config_type.value] = config_type_counts.get(config.config_type.value, 0) + 1
                config_level_counts[config.config_level.value] = config_level_counts.get(config.config_level.value, 0) + 1
        
        return {
            "total_configurations": len([c for c in self.configurations.values() if c.is_active]),
            "config_type_counts": config_type_counts,
            "config_level_counts": config_level_counts,
            "total_history_entries": sum(len(hist) for hist in self.history.values())
        }
    
    def validate_all_configurations(self) -> Dict[str, bool]:
        """验证所有配置"""
        validation_results = {}
        for config_id, config in self.configurations.items():
            validation_results[config_id] = config.validate()
        
        return validation_results
