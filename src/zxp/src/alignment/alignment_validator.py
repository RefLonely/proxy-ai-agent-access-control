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
    """对齐验证器 - 验证LLM决策是否与安全基模对齐，抑制幻觉
    电网五级响应机制：
    - >= min_alignment_threshold (0.8): ALLOW 允许
    - >= challenge_threshold (0.5): CHALLENGE 挑战
    - >= limit_threshold (0.2): LIMIT 限制
    - > 0: DENY 拒绝
    - <= 0: ISOLATE 隔离
    """
    
    def __init__(self, 
                 schema_manager: SchemaManager,
                 embedding_matcher: EmbeddingMatcher = None,
                 min_alignment_threshold: float = 0.6,
                 challenge_threshold: float = 0.4,
                 limit_threshold: float = 0.2):
        self.schema_manager = schema_manager
        self.embedding_matcher = embedding_matcher or EmbeddingMatcher()
        self.min_alignment_threshold = min_alignment_threshold
        self.challenge_threshold = challenge_threshold
        self.limit_threshold = limit_threshold
    
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
        """安全条件求值 - 不使用eval，避免代码注入漏洞
        支持简单的条件表达式: domain == 'xxx', trust >= 0.5, domain != 'external' 等
        """
        expr = condition_expr.strip()
        
        # 预处理变量 - 将变量替换为实际值
        # 支持的变量: domain, trust, action
        value_map = {
            'domain': f"'{request.context.get('domain', '')}'".lower(),
            'trust': str(request.context.get('trust', 0)),
            'action': f"'{request.action.value}'".lower(),
        }
        
        # 分词和替换 - 简单实现，足够支持项目需要的条件
        processed = expr.lower()
        for var_name, var_value in value_map.items():
            processed = processed.replace(var_name, var_value)
        
        # 安全解析: 只支持基本比较和逻辑运算
        # 支持: ==, !=, >=, <=, >, <, and, or
        try:
            result = self._safe_eval_comparison(processed)
            return bool(result)
        except Exception as e:
            logger.debug(f"Condition evaluation failed: {e}")
            # 如果求值失败，默认不匹配
            return False
    
    def _safe_eval_comparison(self, expr: str) -> bool:
        """安全地计算比较表达式，不使用eval"""
        # 处理 and/or
        if ' and ' in expr:
            left, right = expr.split(' and ', 1)
            return self._safe_eval_comparison(left.strip()) and self._safe_eval_comparison(right.strip())
        if ' or ' in expr:
            left, right = expr.split(' or ', 1)
            return self._safe_eval_comparison(left.strip()) or self._safe_eval_comparison(right.strip())
        
        # 比较运算符匹配
        import re
        match = re.match(r'^(.*?)\s*(==|!=|>=|<=|>|<)\s*(.*)$', expr)
        if not match:
            # 如果就是一个布尔值
            if expr in ['true', 'yes', '1']:
                return True
            if expr in ['false', 'no', '0']:
                return False
            return False
        
        left_str, op, right_str = match.groups()
        left_val = self._parse_value(left_str.strip())
        right_val = self._parse_value(right_str.strip())
        
        # 执行比较
        if op == '==':
            return left_val == right_val
        elif op == '!=':
            return left_val != right_val
        elif op == '>=':
            return left_val >= right_val
        elif op == '<=':
            return left_val <= right_val
        elif op == '>':
            return left_val > right_val
        elif op == '<':
            return left_val < right_val
        return False
    
    def _parse_value(self, val_str: str):
        """解析值 - 支持字符串和数字"""
        val_str = val_str.strip()
        # 去掉引号
        if (val_str.startswith("'") and val_str.endswith("'")) or (val_str.startswith('"') and val_str.endswith('"')):
            return val_str[1:-1].lower()
        # 尝试解析数字
        try:
            return float(val_str)
        except ValueError:
            return val_str.lower()
    
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
        # best_match.is_match 检查需要基于阈值，不能直接访问属性
        best_match_is_match = best_match.overall_score >= self.challenge_threshold
        if best_match_is_match:
            schema_decision = DecisionOutcome.ALLOW if best_match.schema.allow else DecisionOutcome.DENY
            decision_consistent = (schema_decision == llm_decision)
            
            if not decision_consistent:
                logger.info(
                    f"LLM decision {llm_decision} inconsistent with schema {best_match.schema.schema_id} "
                    f"which requires {schema_decision}"
                )
                # 不一致，说明可能有幻觉 - 降低分数但保留一定比例
                if best_score > 0:
                    best_score *= 0.8
                # 只有当分数极低时才降到0，避免过度惩罚
                if best_score <= 0.1:
                    best_score = 0.0
        
        # 第五步: 基于对齐分数给出结论 - 电网五级响应机制
        # 调试信息
        logger.debug(f"best_score={best_score}, min_threshold={self.min_alignment_threshold}")
        
        if best_score >= self.min_alignment_threshold:
            # 高度对齐 (>= 阈值)，接受LLM决策
            recommendation = DecisionOutcome.ALLOW
            valid = True
            reason = f"Good alignment with schema {best_match.schema.name}, score {best_score:.3f}"
        elif best_score >= self.challenge_threshold:
            # 中度对齐 (>= 挑战阈值)，需要二次验证
            recommendation = DecisionOutcome.CHALLENGE
            valid = False
            reason = f"Moderate alignment ({best_score:.3f}), requires additional verification"
        elif best_score >= self.limit_threshold:
            # 低度对齐 (>= 限制阈值)，限制访问
            recommendation = DecisionOutcome.LIMIT
            valid = False
            reason = f"Low alignment ({best_score:.3f}), allow but restrict permissions"
        elif best_score > 0:
            # 极低对齐 (> 0)，拒绝访问
            recommendation = DecisionOutcome.DENY
            valid = False
            reason = f"Very low alignment ({best_score:.3f}), possible hallucination or malicious request"
        else:
            # 无匹配 (<= 0)，隔离请求源
            recommendation = DecisionOutcome.ISOLATE
            valid = False
            reason = f"No valid alignment found ({best_score:.3f}), request source should be isolated"

        
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
