from dataclasses import dataclass
from typing import List, Optional, Tuple
import re
import logging

from ..models.access_request import AccessRequest, AccessDecision, DecisionOutcome, AccessAction
from ..models.security_schema import SecuritySchema, SchemaMatchResult
from .schema_manager import SchemaManager
from .embedding_matcher import EmbeddingMatcher

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """对齐验证结果"""
    valid: bool
    alignment_score: float
    best_match_schema: Optional[SecuritySchema]
    matching_results: List[SchemaMatchResult]
    reason: str
    recommendation: DecisionOutcome


class AlignmentValidator:
    """对齐验证器 - 验证LLM决策是否与安全基模对齐，抑制幻觉"""
    
    def __init__(self, 
                 schema_manager: SchemaManager,
                 embedding_matcher: EmbeddingMatcher = None,
                 min_alignment_threshold: float = 0.7,
                 challenge_threshold: float = 0.5):
        self.schema_manager = schema_manager
        self.embedding_matcher = embedding_matcher or EmbeddingMatcher()
        self.min_alignment_threshold = min_alignment_threshold
        self.challenge_threshold = challenge_threshold
    
    def _match_request_to_schema(
        self,
        request: AccessRequest,
        schema: SecuritySchema
    ) -> SchemaMatchResult:
        """将访问请求与安全基模匹配"""
        subject = request.requester_id
        object = request.target_id
        action = request.action.value
        
        # 各部分匹配
        subject_match = self.schema_manager.match_pattern(
            schema.subject_pattern, subject
        )
        object_match = self.schema_manager.match_pattern(
            schema.object_pattern, object
        )
        action_match = self.schema_manager.match_pattern(
            schema.action_pattern, action
        )
        
        # 条件匹配 (简化实现)
        condition_match = self._evaluate_condition(schema.condition_expr, request)
        
        # 嵌入相似度
        request_desc = f"{subject} requests {action} on {object}"
        similarity = self.embedding_matcher.match_decision_with_schema(
            request_desc, schema
        )
        
        # 计算总体分数
        parts = [
            0.25 if subject_match else 0,
            0.25 if object_match else 0,
            0.25 if action_match else 0,
            0.25 if condition_match else 0
        ]
        pattern_score = sum(parts)
        overall_score = 0.6 * pattern_score + 0.4 * similarity
        
        return SchemaMatchResult(
            schema=schema,
            subject_match=subject_match,
            object_match=object_match,
            action_match=action_match,
            condition_match=condition_match,
            embedding_similarity=similarity,
            overall_score=overall_score
        )
    
    def _evaluate_condition(self, condition_expr: str, request: AccessRequest) -> bool:
        """简单条件求值"""
        # 简化实现，支持基本条件表达式
        # 生产环境应使用完整的表达式求值器
        
        # 替换变量
        expr = condition_expr.lower()
        expr = expr.replace("domain", f"'{request.context.get('domain', '')}'")
        expr = expr.replace("trust", str(request.context.get('trust', 0)))
        expr = expr.replace("action", f"'{request.action.value}'")
        
        try:
            # 安全警告: 这里仅作演示，生产环境不应使用eval
            # 应该使用专门的安全表达式解析器
            result = eval(expr)
            return bool(result)
        except:
            # 如果求值失败，默认不匹配
            return False
    
    def validate_llm_decision(
        self,
        request: AccessRequest,
        llm_decision: DecisionOutcome,
        llm_reasoning: str
    ) -> ValidationResult:
        """
        验证LLM生成的决策是否与安全基模对齐
        双路径验证: LLM生成路径 vs 安全基模匹配路径
        """
        # 第一步: 查询匹配的安全基模
        schemas = self.schema_manager.query_schemas(
            subject=request.requester_id,
            object=request.target_id,
            action=request.action.value
        )
        
        if not schemas:
            logger.warning(f"No matching security schemas found for request {request.request_id}")
            return ValidationResult(
                valid=False,
                alignment_score=0.0,
                best_match_schema=None,
                matching_results=[],
                reason="No matching security schemas found",
                recommendation=DecisionOutcome.CHALLENGE
            )
        
        # 第二步: 对每个匹配基模进行完整匹配
        matches = []
        for schema in schemas:
            match = self._match_request_to_schema(request, schema)
            matches.append(match)
        
        # 按分数排序
        matches.sort(key=lambda m: m.overall_score, reverse=True)
        best_match = matches[0]
        
        # 第三步: 计算总体对齐分数
        best_score = best_match.overall_score
        
        # 第四步: 检查LLM决策是否与基模规则一致
        if best_match.is_match:
            schema_decision = DecisionOutcome.ALLOW if best_match.schema.allow else DecisionOutcome.DENY
            decision_consistent = (schema_decision == llm_decision)
            
            if not decision_consistent:
                logger.info(
                    f"LLM decision {llm_decision} inconsistent with schema {best_match.schema.schema_id} "
                    f"which requires {schema_decision}"
                )
                # 不一致，说明可能有幻觉
                best_score *= 0.5
        
        # 第五步: 基于对齐分数给出结论
        if best_score >= self.min_alignment_threshold:
            # 高度对齐，接受LLM决策
            recommendation = llm_decision
            valid = True
            reason = f"Good alignment with schema {best_match.schema.name}, score {best_score:.3f}"
        elif best_score >= self.challenge_threshold:
            # 中度对齐，需要二次验证
            recommendation = DecisionOutcome.CHALLENGE
            valid = False
            reason = f"Moderate alignment ({best_score:.3f}), requires additional verification"
        else:
            # 低对齐，拒绝决策
            recommendation = DecisionOutcome.DENY
            valid = False
            reason = f"Poor alignment ({best_score:.3f}), possible hallucination"
        
        return ValidationResult(
            valid=valid,
            alignment_score=best_score,
            best_match_schema=best_match.schema,
            matching_results=matches,
            reason=reason,
            recommendation=recommendation
        )
    
    def compute_alignment_score(
        self,
        request: AccessRequest,
        llm_reasoning: str
    ) -> float:
        """计算对齐分数"""
        schemas = self.schema_manager.query_schemas(
            subject=request.requester_id,
            object=request.target_id,
            action=request.action.value
        )
        
        if not schemas:
            return 0.0
        
        max_score = 0.0
        for schema in schemas:
            similarity = self.embedding_matcher.match_decision_with_schema(
                llm_reasoning, schema
            )
            if similarity > max_score:
                max_score = similarity
        
        return max_score
