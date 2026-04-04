"""
自动应急响应模块
负责对安全事件进行自动识别和响应
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import uuid
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ResponseLevel(Enum):
    """响应级别枚举"""
    NO_RESPONSE = "no_response"  # 无响应
    NOTIFICATION = "notification"  # 通知
    WARNING = "warning"  # 警告
    QUARANTINE = "quarantine"  # 隔离
    BLOCK = "block"  # 阻止
    SHUTDOWN = "shutdown"  # 关闭


class ResponseStatus(Enum):
    """响应状态枚举"""
    PENDING = "pending"  # 待执行
    EXECUTING = "executing"  # 执行中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"  # 失败
    CANCELED = "canceled"  # 已取消


@dataclass
class EmergencyResponse:
    """应急响应"""
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    threat_type: str = ""
    affected_node: str = ""
    response_level: ResponseLevel = ResponseLevel.NO_RESPONSE
    status: ResponseStatus = ResponseStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    executed_by: str = "system"
    actions: List[str] = field(default_factory=list)
    result: Optional[Dict] = None
    error_message: Optional[str] = None
    details: Dict = field(default_factory=dict)
    
    def execute(self) -> None:
        """执行响应"""
        self.status = ResponseStatus.EXECUTING
        self.started_at = datetime.now()
        
        logger.info(f"Executing {self.response_level.value} response for {self.affected_node}")
        
        try:
            self.result = self._execute_response_actions()
            self.status = ResponseStatus.COMPLETED
            self.completed_at = datetime.now()
            logger.info(f"Response completed for {self.affected_node}")
        except Exception as e:
            self.status = ResponseStatus.FAILED
            self.error_message = str(e)
            self.completed_at = datetime.now()
            logger.error(f"Response failed for {self.affected_node}: {e}")
    
    def _execute_response_actions(self) -> Dict:
        """执行响应操作"""
        level = self.response_level
        
        if level == ResponseLevel.NOTIFICATION:
            return self._send_notification()
        elif level == ResponseLevel.WARNING:
            return self._send_warning()
        elif level == ResponseLevel.QUARANTINE:
            return self._quarantine_node()
        elif level == ResponseLevel.BLOCK:
            return self._block_node()
        elif level == ResponseLevel.SHUTDOWN:
            return self._shutdown_node()
        else:
            return {"result": "no_action"}
    
    def _send_notification(self) -> Dict:
        """发送通知"""
        logger.info(f"Notification sent: Threat detected on {self.affected_node}")
        return {"result": "notification_sent"}
    
    def _send_warning(self) -> Dict:
        """发送警告"""
        logger.warning(f"Warning sent: Threat on {self.affected_node} requires attention")
        return {"result": "warning_sent"}
    
    def _quarantine_node(self) -> Dict:
        """隔离节点"""
        logger.warning(f"Node quarantined: {self.affected_node}")
        return {"result": "node_quarantined"}
    
    def _block_node(self) -> Dict:
        """阻止节点"""
        logger.error(f"Node blocked: {self.affected_node}")
        return {"result": "node_blocked"}
    
    def _shutdown_node(self) -> Dict:
        """关闭节点"""
        logger.critical(f"Node shutdown: {self.affected_node}")
        return {"result": "node_shutdown"}


class EmergencyResponseManager:
    """应急响应管理器"""
    
    def __init__(self):
        self.responses: List[EmergencyResponse] = []
        self.response_rules: Dict[str, ResponseLevel] = self._create_default_rules()
        self.active_responses: List[EmergencyResponse] = []
        self.response_stats: Dict[ResponseLevel, int] = {l: 0 for l in ResponseLevel}
        self.response_history: Dict[str, List[EmergencyResponse]] = {}
    
    def _create_default_rules(self) -> Dict[str, ResponseLevel]:
        """创建默认响应规则"""
        return {
            "malicious_agent": ResponseLevel.BLOCK,
            "abnormal_behavior": ResponseLevel.WARNING,
            "network_attack": ResponseLevel.BLOCK,
            "configuration_violation": ResponseLevel.QUARANTINE,
            "resource_exhaustion": ResponseLevel.QUARANTINE,
            "permission_escalation": ResponseLevel.BLOCK
        }
    
    def create_response(self, threat: Dict[str, Any], affected_node: str) -> EmergencyResponse:
        """创建响应"""
        threat_type = threat.get("threat_type", "unknown")
        response_level = self.response_rules.get(threat_type, ResponseLevel.NO_RESPONSE)
        
        response = EmergencyResponse(
            threat_id=threat.get("threat_id", str(uuid.uuid4())),
            threat_type=threat_type,
            affected_node=affected_node,
            response_level=response_level,
            actions=self._determine_response_actions(response_level),
            details=threat
        )
        
        self.responses.append(response)
        self.response_stats[response_level] += 1
        
        return response
    
    def _determine_response_actions(self, level: ResponseLevel) -> List[str]:
        """确定响应操作"""
        if level == ResponseLevel.NOTIFICATION:
            return ["send_email", "log_event"]
        elif level == ResponseLevel.WARNING:
            return ["send_email", "send_sms", "log_event"]
        elif level == ResponseLevel.QUARANTINE:
            return ["isolate_node", "block_traffic", "notify_admin"]
        elif level == ResponseLevel.BLOCK:
            return ["block_node", "isolate_traffic", "notify_admin", "log_event"]
        elif level == ResponseLevel.SHUTDOWN:
            return ["shutdown_node", "notify_admin", "alert_security"]
        else:
            return ["log_event"]
    
    def execute_response(self, response: EmergencyResponse) -> EmergencyResponse:
        """执行响应"""
        if response.status != ResponseStatus.PENDING:
            logger.warning(f"Response already {response.status.value}")
            return response
        
        self.active_responses.append(response)
        response.execute()
        
        if response.status == ResponseStatus.COMPLETED:
            self.active_responses.remove(response)
        
        return response
    
    def execute_all_pending(self) -> List[EmergencyResponse]:
        """执行所有待处理的响应"""
        pending = [r for r in self.responses if r.status == ResponseStatus.PENDING]
        executed = []
        
        for response in pending:
            try:
                executed_response = self.execute_response(response)
                executed.append(executed_response)
            except Exception as e:
                logger.error(f"Failed to execute response {response.response_id}: {e}")
        
        return executed
    
    def cancel_response(self, response_id: str) -> bool:
        """取消响应"""
        for response in self.responses:
            if response.response_id == response_id and response.status in [ResponseStatus.PENDING, ResponseStatus.EXECUTING]:
                if response.status == ResponseStatus.EXECUTING:
                    response.status = ResponseStatus.CANCELED
                    logger.warning(f"Response {response_id} canceled")
                else:
                    response.status = ResponseStatus.CANCELED
                    logger.info(f"Response {response_id} canceled")
                return True
        
        logger.warning(f"Response {response_id} not found or already completed")
        return False
    
    def get_response_status(self, response_id: str) -> Optional[ResponseStatus]:
        """获取响应状态"""
        for response in self.responses:
            if response.response_id == response_id:
                return response.status
        return None
    
    def get_response_by_node(self, node_id: str) -> List[EmergencyResponse]:
        """获取节点的响应"""
        return [r for r in self.responses if r.affected_node == node_id]
    
    def update_response_rules(self, threat_type: str, response_level: ResponseLevel) -> bool:
        """更新响应规则"""
        if threat_type not in self.response_rules:
            logger.warning(f"Threat type {threat_type} not recognized")
            return False
        
        old_level = self.response_rules[threat_type]
        self.response_rules[threat_type] = response_level
        
        logger.info(f"Response rule updated: {threat_type} from {old_level.value} to {response_level.value}")
        return True
    
    def get_response_statistics(self) -> Dict[str, Any]:
        """获取响应统计信息"""
        status_counts: Dict[ResponseStatus, int] = {s: 0 for s in ResponseStatus}
        
        for response in self.responses:
            status_counts[response.status] += 1
        
        level_counts: Dict[ResponseLevel, int] = {l: 0 for l in ResponseLevel}
        
        for response in self.responses:
            level_counts[response.response_level] += 1
        
        return {
            "total_responses": len(self.responses),
            "status_distribution": {s.value: count for s, count in status_counts.items()},
            "level_distribution": {l.value: count for l, count in level_counts.items()},
            "active_responses": len([r for r in self.active_responses if r.status == ResponseStatus.EXECUTING])
        }
    
    def get_response_history(self, node_id: str = None, response_level: ResponseLevel = None) -> List[EmergencyResponse]:
        """获取响应历史"""
        history = self.responses
        
        if node_id:
            history = [r for r in history if r.affected_node == node_id]
        
        if response_level:
            history = [r for r in history if r.response_level == response_level]
        
        return history
    
    def get_response_report(self) -> Dict[str, Any]:
        """生成响应报告"""
        stats = self.get_response_statistics()
        
        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now().isoformat(),
            "total_responses": stats["total_responses"],
            "status_distribution": stats["status_distribution"],
            "level_distribution": stats["level_distribution"],
            "active_responses": stats["active_responses"],
            "response_efficiency": self._calculate_response_efficiency(),
            "execution_times": self._calculate_response_times()
        }
        
        return report
    
    def _calculate_response_efficiency(self) -> Dict[str, float]:
        """计算响应效率"""
        completed = [r for r in self.responses if r.status == ResponseStatus.COMPLETED]
        total = len(self.responses)
        
        if total == 0:
            return {"success_rate": 0.0, "average_time": 0.0}
        
        success_rate = len(completed) / total
        average_time = sum(
            (r.completed_at - r.started_at).total_seconds()
            for r in completed if r.started_at and r.completed_at
        ) / len(completed)
        
        return {
            "success_rate": success_rate,
            "average_time_seconds": average_time
        }
    
    def _calculate_response_times(self) -> Dict[str, float]:
        """计算响应时间"""
        response_times = {l.value: [] for l in ResponseLevel}
        
        for response in self.responses:
            if response.status == ResponseStatus.COMPLETED and response.started_at and response.completed_at:
                duration = (response.completed_at - response.started_at).total_seconds()
                response_times[response.response_level.value].append(duration)
        
        average_times = {}
        for level, times in response_times.items():
            if times:
                average_times[level] = sum(times) / len(times)
            else:
                average_times[level] = 0.0
        
        return average_times
    
    def is_response_required(self, threat: Dict[str, Any]) -> bool:
        """判断是否需要响应"""
        threat_type = threat.get("threat_type", "unknown")
        severity = threat.get("severity", 0.0)
        confidence = threat.get("confidence", 0.0)
        
        if threat_type not in self.response_rules:
            return False
        
        response_level = self.response_rules.get(threat_type, ResponseLevel.NO_RESPONSE)
        
        return (
            response_level != ResponseLevel.NO_RESPONSE and
            severity >= 0.5 and
            confidence >= 0.7
        )
    
    def auto_response(self, threats: List[Dict[str, Any]]) -> List[EmergencyResponse]:
        """自动响应威胁"""
        executed = []
        
        for threat in threats:
            if self.is_response_required(threat):
                node_id = threat.get("node_id", "unknown")
                response = self.create_response(threat, node_id)
                executed_response = self.execute_response(response)
                executed.append(executed_response)
            else:
                logger.info(f"Response not required for threat: {threat.get('threat_type')}")
        
        return executed
