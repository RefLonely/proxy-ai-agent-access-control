"""
主访问控制器 - 整合信任边界动态维护和幻觉抑制安全对齐
"""
from typing import Dict, Optional, Tuple, List
import logging

from .models.agent import Agent
from .models.access_request import AccessRequest, AccessDecision, DecisionOutcome
from .trust.trust_manager import TrustManager
from .alignment.schema_manager import SchemaManager
from .alignment.embedding_matcher import EmbeddingMatcher
from .alignment.alignment_validator import AlignmentValidator, ValidationResult
from .security_audit.audit_manager import AuditManager, AuditEventType
from .communication.communication_manager import CommunicationManager, CommunicationProtocol
from .protocols.protocol_parser import ProtocolType
from .protocols.anomaly_detector import ProtocolAnomalyDetector, AnomalyResult

logger = logging.getLogger(__name__)


class AgenticAccessController:
    """
    代理式AI自主访问控制器
    整合:
    1. 基于动态信念图的信任边界动态维护
    2. 基于安全基模对比的幻觉抑制与安全对齐
    3. 安全审计功能
    4. 代理通信管理
    """
    
    def __init__(
        self,
        local_agent: Agent,
        min_trust_threshold: float = 0.5,
        min_alignment_threshold: float = 0.7,
        consensus_enabled: bool = True,
        protocol_anomaly_risk_threshold: float = 0.5
    ):
        # 信任管理模块
        self.trust_manager = TrustManager(
            local_agent=local_agent,
            min_trust_threshold=min_trust_threshold,
            consensus_enabled=consensus_enabled
        )
        
        # 安全对齐模块
        self.schema_manager = SchemaManager()
        self.embedding_matcher = EmbeddingMatcher()
        self.alignment_validator = AlignmentValidator(
            schema_manager=self.schema_manager,
            embedding_matcher=self.embedding_matcher,
            min_alignment_threshold=min_alignment_threshold
        )
        
        # 安全审计模块
        self.audit_manager = AuditManager()
        
        # 通信管理模块
        self.communication_manager = CommunicationManager()
        
        # 协议异常检测模块
        self.protocol_anomaly_detector = ProtocolAnomalyDetector()
        self.protocol_anomaly_risk_threshold = protocol_anomaly_risk_threshold
        
        # 统计
        self.total_requests = 0
        self.allowed_requests = 0
        self.denied_requests = 0
        self.challenged_requests = 0
        self.detected_hallucinations = 0
        self.detected_protocol_anomalies = 0
    
    def add_remote_agent(self, agent: Agent, initial_trust: float) -> None:
        """添加远程代理"""
        self.trust_manager.add_remote_agent(agent, initial_trust)
    
    def load_default_industrial_schemas(self) -> None:
        """加载工业默认安全基模"""
        self.schema_manager.load_default_industrial_schemas()
        
        # 预计算嵌入
        if self.embedding_matcher.model is not None:
            for schema in self.schema_manager.list_schemas():
                schema_text = f"{schema.name} {schema.description}"
                schema.embedding = self.embedding_matcher.embed_text(schema_text)
    
    def evaluate_access(
        self,
        request: AccessRequest,
        llm_decision: DecisionOutcome,
        llm_reasoning: str
    ) -> AccessDecision:
        """
        评估访问请求
        整合协议异常检测、信任评估和对齐验证
        """
        self.total_requests += 1
        
        # 记录审计事件
        self.audit_manager.log_access_request(request)
        
        # 步骤0: 协议异常检测 (前置检查)
        protocol_anomaly_result = self._check_protocol_anomaly(request)
        request.context['protocol_anomaly'] = protocol_anomaly_result
        if protocol_anomaly_result is not None and protocol_anomaly_result.is_anomaly:
            # 如果协议风险评分超过阈值，直接拒绝访问
            if protocol_anomaly_result.risk_score >= self.protocol_anomaly_risk_threshold:
                logger.warning(
                    f"Access denied for {request.request_id}: "
                    f"protocol anomaly detected, risk score {protocol_anomaly_result.risk_score:.3f}, "
                    f"anomalies: {protocol_anomaly_result.anomalies}"
                )
                self.detected_protocol_anomalies += 1
                self.denied_requests += 1
                decision = AccessDecision(
                    request=request,
                    outcome=DecisionOutcome.DENY,
                    confidence=1.0 - protocol_anomaly_result.risk_score,
                    reason=f"Protocol anomaly detected: {len(protocol_anomaly_result.anomalies)} anomalies found, "
                           f"risk score {protocol_anomaly_result.risk_score:.3f} exceeds threshold",
                    trust_score=0.0,
                    alignment_score=0.0
                )
                self.audit_manager.log_access_decision(decision)
                return decision
        
        # 步骤1: 信任评估
        trust_score, trust_ok = self.trust_manager.evaluate_access_trust(
            requester_id=request.requester_id,
            target_id=request.target_id
        )
        request.context['trust'] = trust_score
        
        # 如果信任不够，直接拒绝
        if not trust_ok:
            logger.info(f"Access denied for {request.request_id}: insufficient trust {trust_score:.3f}")
            self.denied_requests += 1
            decision = AccessDecision(
                request=request,
                outcome=DecisionOutcome.DENY,
                confidence=trust_score,
                reason=f"Insufficient trust: {trust_score:.3f} below threshold",
                trust_score=trust_score,
                alignment_score=0.0
            )
            self.audit_manager.log_access_decision(decision)
            return decision
        
        # 步骤2: 安全对齐验证 (抑制幻觉)
        validation = self.alignment_validator.validate_llm_decision(
            request=request,
            llm_decision=llm_decision,
            llm_reasoning=llm_reasoning
        )
        
        alignment_score = validation.alignment_score
        
        # 检测到幻觉或高风险
        if validation.recommendation == DecisionOutcome.DENY:
            self.detected_hallucinations += 1
            self.denied_requests += 1
            decision = AccessDecision(
                request=request,
                outcome=DecisionOutcome.DENY,
                confidence=alignment_score,
                reason=f"Security alignment failed: {validation.reason}",
                trust_score=trust_score,
                alignment_score=alignment_score
            )
            self.audit_manager.log_access_decision(decision)
            return decision
        
        # 需要挑战/二次验证
        if validation.recommendation == DecisionOutcome.CHALLENGE:
            self.challenged_requests += 1
            decision = AccessDecision(
                request=request,
                outcome=DecisionOutcome.CHALLENGE,
                confidence=alignment_score,
                reason=f"Alignment uncertain: {validation.reason}",
                trust_score=trust_score,
                alignment_score=alignment_score
            )
            self.audit_manager.log_access_decision(decision)
            return decision
        
        # 低对齐，限制访问
        if validation.recommendation == DecisionOutcome.LIMIT:
            self.challenged_requests += 1  # 限制计入待审核
            decision = AccessDecision(
                request=request,
                outcome=DecisionOutcome.LIMIT,
                confidence=alignment_score,
                reason=f"Low alignment: {validation.reason}, allow with restricted permissions",
                trust_score=trust_score,
                alignment_score=alignment_score
            )
            self.audit_manager.log_access_decision(decision)
            return decision
        
        # 无匹配，隔离请求源
        if validation.recommendation == DecisionOutcome.ISOLATE:
            self.denied_requests += 1
            decision = AccessDecision(
                request=request,
                outcome=DecisionOutcome.ISOLATE,
                confidence=alignment_score,
                reason=f"Security violation: {validation.reason}, isolate source agent",
                trust_score=trust_score,
                alignment_score=alignment_score
            )
            self.audit_manager.log_access_decision(decision)
            # 隔离处理：立即降低所有指向该源的信任评分
            # 注意：需要确保trust_manager.dbg.contract_boundary方法存在
            try:
                if hasattr(self.trust_manager, 'dbg') and hasattr(self.trust_manager.dbg, 'contract_boundary'):
                    self.trust_manager.dbg.contract_boundary(request.requester_id, decay_factor=0.5)
            except Exception as e:
                logger.error(f"Failed to isolate agent {request.requester_id}: {e}")
            return decision
        
        # 信任和对齐都通过
        outcome = validation.recommendation
        if outcome == DecisionOutcome.ALLOW:
            self.allowed_requests += 1
        elif outcome == DecisionOutcome.DENY:
            self.denied_requests += 1
        
        decision = AccessDecision(
            request=request,
            outcome=outcome,
            confidence=trust_score * alignment_score,
            reason=f"Trust: {trust_score:.3f}, Alignment: {alignment_score:.3f}",
            trust_score=trust_score,
            alignment_score=alignment_score
        )
        self.audit_manager.log_access_decision(decision)
        
        return decision
    
    def _check_protocol_anomaly(self, request: AccessRequest) -> Optional[AnomalyResult]:
        """
        检查请求中的协议数据是否存在异常
        从request.metadata中获取原始二进制数据进行检测
        """
        # 从metadata获取原始协议数据
        raw_data = request.metadata.get('raw_protocol_data', None)
        if raw_data is None:
            return None
        
        if not isinstance(raw_data, bytes):
            # 如果数据不是字节类型，视为格式错误
            logger.warning(f"Invalid protocol data type for request {request.request_id}: expected bytes")
            return AnomalyResult(
                protocol_type=ProtocolType.UNKNOWN,
                is_anomaly=True,
                risk_score=0.6,
                anomalies=[("INVALID_DATA_TYPE", f"Expected bytes, got {type(raw_data)}")],
                raw_data=b''
            )
        
        # 处理空数据情况
        if len(raw_data) == 0:
            logger.warning(f"Empty protocol data for request {request.request_id}")
            return AnomalyResult(
                protocol_type=ProtocolType.UNKNOWN,
                is_anomaly=True,
                risk_score=0.3,
                anomalies=[("EMPTY_REQUEST", "Empty protocol data received")],
                raw_data=b''
            )
        
        # 获取协议类型
        protocol_name = request.protocol.lower() if request.protocol else ''
        protocol_type_map = {
            'modbus': ProtocolType.MODBUS,
            'iec': ProtocolType.IEC_60870_5,
            'iec60870': ProtocolType.IEC_60870_5,
            'iec-60870-5': ProtocolType.IEC_60870_5,
            '101': ProtocolType.IEC_60870_5,
            '104': ProtocolType.IEC_60870_5,
            'opc': ProtocolType.OPC_UA,
            'opcua': ProtocolType.OPC_UA,
            'opc-ua': ProtocolType.OPC_UA,
            'dl': ProtocolType.DL_T_645,
            'dlt': ProtocolType.DL_T_645,
            'dl-t645': ProtocolType.DL_T_645,
            'dlt645': ProtocolType.DL_T_645
        }
        
        protocol_type = protocol_type_map.get(protocol_name, None)
        
        if protocol_type:
            # 已知协议，针对性检测
            return self.protocol_anomaly_detector.detect(raw_data, protocol_type)
        else:
            # 未知协议，自动检测
            if protocol_name:
                logger.info(f"Unknown protocol '{request.protocol}', attempting auto-detection")
            return self.protocol_anomaly_detector.detect_auto(raw_data)
    
    def report_result(self, requester_id: str, target_id: str, success: bool) -> None:
        """报告交互结果，更新信任"""
        # 更新信任
        old_score = self.trust_manager.get_trust_score(requester_id, target_id)
        self.trust_manager.report_interaction_result(requester_id, target_id, success)
        new_score = self.trust_manager.get_trust_score(requester_id, target_id)
        
        # 记录信任更新审计事件
        self.audit_manager.log_trust_update(requester_id, target_id, old_score, new_score)
        
        # 记录通信事件
        if success:
            self.communication_manager.send_message(
                requester_id,
                target_id,
                "Interaction successful",
                protocol=self.communication_manager.CommunicationProtocol.HTTP
            )
        else:
            self.communication_manager.send_message(
                requester_id,
                target_id,
                "Interaction failed",
                protocol=self.communication_manager.CommunicationProtocol.HTTP
            )
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        trust_stats = self.trust_manager.get_statistics()
        audit_stats = self.audit_manager.get_statistics()
        communication_stats = {
            'total_communications': len(self.communication_manager.communication_records),
            'active_channels': len([c for c in self.communication_manager.channels.values() if c.status == "active"])
        }
        protocol_stats = self.protocol_anomaly_detector.get_statistics()
        
        return {
            'total_requests': self.total_requests,
            'allowed_requests': self.allowed_requests,
            'denied_requests': self.denied_requests,
            'challenged_requests': self.challenged_requests,
            'detected_hallucinations': self.detected_hallucinations,
            'detected_protocol_anomalies': self.detected_protocol_anomalies,
            'allow_rate': self.allowed_requests / self.total_requests if self.total_requests > 0 else 0,
            **trust_stats,
            **audit_stats,
            **communication_stats,
            'supported_protocols': protocol_stats.get('supported_protocols', 0)
        }
    
    def generate_audit_report(self, start_time=None, end_time=None) -> Dict:
        """生成审计报告"""
        return self.audit_manager.generate_audit_report(start_time, end_time)
    
    def detect_abnormal_behavior(self, agent_id: str) -> List:
        """检测异常行为"""
        return self.audit_manager.detect_abnormal_behavior(agent_id)
