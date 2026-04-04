"""
本地操作管控模块
负责对代理节点的本地操作进行监控和限制
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import uuid
import logging
import inspect
from enum import Enum

logger = logging.getLogger(__name__)


class OperationType(Enum):
    """操作类型枚举"""
    READ = "read"  # 读取操作
    WRITE = "write"  # 写入操作
    EXECUTE = "execute"  # 执行操作
    ADMIN = "admin"  # 管理操作
    CONFIGURE = "configure"  # 配置操作


class OperationStatus(Enum):
    """操作状态枚举"""
    ALLOWED = "allowed"  # 允许执行
    BLOCKED = "blocked"  # 阻塞执行
    LIMITED = "limited"  # 受限执行
    CHALLENGED = "challenged"  # 需验证执行


class OperationRiskLevel(Enum):
    """操作风险级别枚举"""
    LOW = "low"  # 低风险
    MEDIUM = "medium"  # 中风险
    HIGH = "high"  # 高风险
    CRITICAL = "critical"  # 高风险


@dataclass
class Operation:
    """操作表示"""
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_id: str = ""
    operation_type: OperationType = OperationType.READ
    target_resource: str = ""
    request_data: Dict = field(default_factory=dict)
    status: OperationStatus = OperationStatus.ALLOWED
    risk_level: OperationRiskLevel = OperationRiskLevel.LOW
    executed_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None
    error_message: Optional[str] = None


@dataclass
class OperationLimit:
    """操作限制"""
    limit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    operation_type: OperationType = OperationType.READ
    max_per_hour: int = 0  # 每小时最大操作数 (0表示无限制)
    max_per_day: int = 0  # 每天最大操作数 (0表示无限制)
    resource_pattern: str = "*"  # 资源匹配模式
    enabled: bool = True


class LocalOperationManager:
    """本地操作管理器"""
    
    def __init__(self):
        self.operation_history: List[Operation] = []
        self.operation_limits: Dict[str, OperationLimit] = self._create_default_limits()
        self.operation_stats: Dict[OperationType, int] = {t: 0 for t in OperationType}
        self.blocked_operations: List[Operation] = []
        self.operation_cache: Dict[str, Any] = {}
    
    def _create_default_limits(self) -> Dict[str, OperationLimit]:
        """创建默认操作限制"""
        limits = {}
        
        # 低风险操作限制
        limits["read_limit"] = OperationLimit(
            operation_type=OperationType.READ,
            max_per_hour=3600,
            max_per_day=86400,
            resource_pattern="*",
            enabled=True
        )
        
        # 写入操作限制
        limits["write_limit"] = OperationLimit(
            operation_type=OperationType.WRITE,
            max_per_hour=1800,
            max_per_day=43200,
            resource_pattern="*",
            enabled=True
        )
        
        # 执行操作限制
        limits["execute_limit"] = OperationLimit(
            operation_type=OperationType.EXECUTE,
            max_per_hour=300,
            max_per_day=7200,
            resource_pattern="*",
            enabled=True
        )
        
        # 管理操作限制
        limits["admin_limit"] = OperationLimit(
            operation_type=OperationType.ADMIN,
            max_per_hour=50,
            max_per_day=200,
            resource_pattern="*",
            enabled=True
        )
        
        return limits
    
    def check_operation_permission(self, node_id: str, operation_type: OperationType, target_resource: str) -> OperationStatus:
        """检查操作权限"""
        # 检查操作类型是否受限
        if self._is_operation_restricted(operation_type, target_resource):
            return OperationStatus.BLOCKED
        
        # 检查操作频率限制
        if self._check_operation_limit(operation_type):
            return OperationStatus.BLOCKED
        
        # 检查资源访问权限
        if not self._check_resource_permission(node_id, operation_type, target_resource):
            return OperationStatus.CHALLENGED
        
        return OperationStatus.ALLOWED
    
    def _is_operation_restricted(self, operation_type: OperationType, target_resource: str) -> bool:
        """检查操作是否受限"""
        if operation_type == OperationType.ADMIN and target_resource.endswith("secret"):
            return True
        
        return False
    
    def _check_operation_limit(self, operation_type: OperationType) -> bool:
        """检查操作频率限制"""
        limit = None
        for l in self.operation_limits.values():
            if l.operation_type == operation_type and l.enabled:
                limit = l
                break
        
        if not limit:
            return False
        
        # 统计当前操作频率
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(days=1)
        
        hourly_count = len([
            op for op in self.operation_history
            if op.operation_type == operation_type and op.executed_at >= one_hour_ago
        ])
        
        daily_count = len([
            op for op in self.operation_history
            if op.operation_type == operation_type and op.executed_at >= one_day_ago
        ])
        
        if limit.max_per_hour > 0 and hourly_count >= limit.max_per_hour:
            logger.warning(f"Operation limit exceeded: {operation_type} per hour ({hourly_count}/{limit.max_per_hour})")
            return True
        
        if limit.max_per_day > 0 and daily_count >= limit.max_per_day:
            logger.warning(f"Operation limit exceeded: {operation_type} per day ({daily_count}/{limit.max_per_day})")
            return True
        
        return False
    
    def _check_resource_permission(self, node_id: str, operation_type: OperationType, target_resource: str) -> bool:
        """检查资源访问权限"""
        if target_resource.startswith("protected") and operation_type in [OperationType.WRITE, OperationType.EXECUTE]:
            return False
        
        return True
    
    def execute_operation(self, node_id: str, operation_type: OperationType, target_resource: str, request_data: Dict = None) -> Operation:
        """执行操作"""
        # 检查操作权限
        status = self.check_operation_permission(node_id, operation_type, target_resource)
        
        operation = Operation(
            node_id=node_id,
            operation_type=operation_type,
            target_resource=target_resource,
            status=status,
            risk_level=self._determine_risk_level(operation_type),
            request_data=request_data or {}
        )
        
        # 如果操作允许执行
        if status == OperationStatus.ALLOWED:
            try:
                result = self._execute_actual_operation(operation)
                operation.result = result
                operation.completed_at = datetime.now()
                logger.info(f"Operation executed: {operation_type} on {target_resource}")
            except Exception as e:
                operation.status = OperationStatus.BLOCKED
                operation.error_message = str(e)
                operation.completed_at = datetime.now()
                logger.error(f"Operation failed: {e}")
        else:
            operation.completed_at = datetime.now()
            if status == OperationStatus.BLOCKED:
                self.blocked_operations.append(operation)
                logger.warning(f"Operation blocked: {operation_type} on {target_resource}")
        
        # 更新统计信息
        self.operation_history.append(operation)
        self.operation_stats[operation_type] += 1
        
        return operation
    
    def _execute_actual_operation(self, operation: Operation) -> Dict:
        """执行实际操作（模拟）"""
        operation_type = operation.operation_type.value
        target_resource = operation.target_resource
        
        # 模拟操作执行
        if operation_type == "read":
            return self._simulate_read(target_resource)
        elif operation_type == "write":
            return self._simulate_write(target_resource, operation.request_data)
        elif operation_type == "execute":
            return self._simulate_execute(target_resource, operation.request_data)
        elif operation_type == "admin":
            return self._simulate_admin(target_resource, operation.request_data)
        else:
            return {"result": "unsupported_operation"}
    
    def _simulate_read(self, target_resource: str) -> Dict:
        """模拟读取操作"""
        return {"result": "read_success", "data": f"Content of {target_resource}"}
    
    def _simulate_write(self, target_resource: str, data: Dict) -> Dict:
        """模拟写入操作"""
        return {"result": "write_success", "written": data}
    
    def _simulate_execute(self, target_resource: str, data: Dict) -> Dict:
        """模拟执行操作"""
        return {"result": "execute_success", "output": f"Execution completed on {target_resource}"}
    
    def _simulate_admin(self, target_resource: str, data: Dict) -> Dict:
        """模拟管理操作"""
        return {"result": "admin_success", "action": data.get("action", "unknown")}
    
    def _determine_risk_level(self, operation_type: OperationType) -> OperationRiskLevel:
        """确定操作风险级别"""
        if operation_type == OperationType.ADMIN:
            return OperationRiskLevel.CRITICAL
        elif operation_type == OperationType.EXECUTE:
            return OperationRiskLevel.HIGH
        elif operation_type == OperationType.WRITE:
            return OperationRiskLevel.MEDIUM
        else:
            return OperationRiskLevel.LOW
    
    def get_operation_statistics(self) -> Dict:
        """获取操作统计信息"""
        now = datetime.now()
        hourly_count = {op_type: 0 for op_type in OperationType}
        daily_count = {op_type: 0 for op_type in OperationType}
        
        one_hour_ago = now - timedelta(hours=1)
        one_day_ago = now - timedelta(days=1)
        
        for op in self.operation_history:
            if op.executed_at >= one_hour_ago:
                hourly_count[op.operation_type] += 1
            if op.executed_at >= one_day_ago:
                daily_count[op.operation_type] += 1
        
        return {
            "total_operations": len(self.operation_history),
            "operations_by_type": dict(self.operation_stats),
            "operations_by_status": {
                "allowed": len([op for op in self.operation_history if op.status == OperationStatus.ALLOWED]),
                "blocked": len(self.blocked_operations),
                "limited": len([op for op in self.operation_history if op.status == OperationStatus.LIMITED]),
                "challenged": len([op for op in self.operation_history if op.status == OperationStatus.CHALLENGED])
            },
            "hourly_count": hourly_count,
            "daily_count": daily_count
        }
    
    def get_operation_history(self, node_id: str = None, operation_type: OperationType = None, start_time: datetime = None, end_time: datetime = None) -> List[Operation]:
        """获取操作历史记录"""
        operations = self.operation_history
        
        if node_id:
            operations = [op for op in operations if op.node_id == node_id]
        
        if operation_type:
            operations = [op for op in operations if op.operation_type == operation_type]
        
        if start_time:
            operations = [op for op in operations if op.executed_at >= start_time]
        
        if end_time:
            operations = [op for op in operations if op.executed_at <= end_time]
        
        return operations
    
    def get_blocked_operations(self, node_id: str = None, start_time: datetime = None, end_time: datetime = None) -> List[Operation]:
        """获取被阻塞的操作"""
        operations = self.blocked_operations
        
        if node_id:
            operations = [op for op in operations if op.node_id == node_id]
        
        if start_time:
            operations = [op for op in operations if op.executed_at >= start_time]
        
        if end_time:
            operations = [op for op in operations if op.executed_at <= end_time]
        
        return operations
    
    def add_operation_limit(self, limit: OperationLimit) -> None:
        """添加操作限制"""
        limit_id = f"{limit.operation_type.value}_limit"
        self.operation_limits[limit_id] = limit
        logger.info(f"Added operation limit: {limit_id}")
    
    def remove_operation_limit(self, limit_id: str) -> bool:
        """删除操作限制"""
        if limit_id in self.operation_limits:
            del self.operation_limits[limit_id]
            logger.info(f"Removed operation limit: {limit_id}")
            return True
        return False
    
    def update_operation_limit(self, limit_id: str, max_per_hour: int = None, max_per_day: int = None, enabled: bool = None) -> Optional[OperationLimit]:
        """更新操作限制"""
        if limit_id not in self.operation_limits:
            return None
        
        limit = self.operation_limits[limit_id]
        if max_per_hour is not None:
            limit.max_per_hour = max_per_hour
        if max_per_day is not None:
            limit.max_per_day = max_per_day
        if enabled is not None:
            limit.enabled = enabled
        
        logger.info(f"Updated operation limit: {limit_id}")
        return limit
    
    def clear_operation_history(self, before_time: datetime = None) -> int:
        """清除操作历史记录"""
        if before_time:
            count = len([op for op in self.operation_history if op.executed_at < before_time])
            self.operation_history = [op for op in self.operation_history if op.executed_at >= before_time]
        else:
            count = len(self.operation_history)
            self.operation_history.clear()
        
        logger.info(f"Cleared {count} operation history records")
        return count
    
    def analyze_operation_patterns(self) -> Dict:
        """分析操作模式"""
        patterns = {
            "most_frequent_operations": {},
            "highest_risk_operations": {},
            "time_based_patterns": {}
        }
        
        # 统计最频繁的操作类型
        for op_type, count in self.operation_stats.items():
            patterns["most_frequent_operations"][op_type.value] = count
        
        # 统计高风险操作
        high_risk_ops = [
            op for op in self.operation_history
            if op.risk_level in [OperationRiskLevel.HIGH, OperationRiskLevel.CRITICAL]
        ]
        patterns["highest_risk_operations"] = len(high_risk_ops)
        
        # 统计时间分布模式
        hour_distribution = {hour: 0 for hour in range(24)}
        for op in self.operation_history:
            hour = op.executed_at.hour
            hour_distribution[hour] += 1
        patterns["time_based_patterns"] = hour_distribution
        
        return patterns
