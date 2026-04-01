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
        min_alignment_threshold: float = 0.6,
        consensus_enabled: bool = True
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
        
        # 统计
        self.total_requests = 0
        self.allowed_requests = 0
        self.denied_requests = 0
        self.challenged_requests = 0
        self.detected_hallucinations = 0
    
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
        整合信任评估和对齐验证
        """
        self.total_requests += 1
        
        # 记录审计事件
        self.audit_manager.log_access_request(request)
        
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
        
        # 检测到幻觉
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
            self.trust_manager.dbg.contract_boundary(request.requester_id, decay_factor=0.5)
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
        
        return {
            'total_requests': self.total_requests,
            'allowed_requests': self.allowed_requests,
            'denied_requests': self.denied_requests,
            'challenged_requests': self.challenged_requests,
            'detected_hallucinations': self.detected_hallucinations,
            'allow_rate': self.allowed_requests / self.total_requests if self.total_requests > 0 else 0,
            **trust_stats,
            **audit_stats,
            **communication_stats
        }
    
    def generate_audit_report(self, start_time=None, end_time=None) -> Dict:
        """生成审计报告"""
        return self.audit_manager.generate_audit_report(start_time, end_time)
    
    def detect_abnormal_behavior(self, agent_id: str) -> List:
        """检测异常行为"""
        return self.audit_manager.detect_abnormal_behavior(agent_id)
