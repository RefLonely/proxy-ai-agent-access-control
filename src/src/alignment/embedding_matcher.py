from typing import List, Optional, Tuple
import numpy as np
import re

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMER_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMER_AVAILABLE = False
    SentenceTransformer = None

from ..models.security_schema import SecuritySchema, SchemaMatchResult


class EmbeddingMatcher:
    """嵌入匹配器 - 用于安全基模的嵌入空间对比"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = None
        self.model_name = model_name
        if SENTENCE_TRANSFORMER_AVAILABLE:
            try:
                self.model = SentenceTransformer(model_name)
            except Exception as e:
                print(f"Warning: Could not load sentence transformer: {e}")
                self.model = None
    
    def embed_text(self, text: str) -> Optional[List[float]]:
        """计算文本嵌入"""
        if self.model is None:
            return None
        
        embedding = self.model.encode(text)
        return embedding.tolist()
    
    def cosine_similarity(self, a: List[float], b: List[float]) -> float:
        """计算余弦相似度"""
        if a is None or b is None:
            return 0.0
        
        a_np = np.array(a)
        b_np = np.array(b)
        
        dot_product = np.dot(a_np, b_np)
        norm_a = np.linalg.norm(a_np)
        norm_b = np.linalg.norm(b_np)
        
        if norm_a == 0 or norm_b == 0:
            return 0.0
        
        return float(dot_product / (norm_a * norm_b))
    
    def match_decision_with_schema(
        self,
        decision_text: str,
        schema: SecuritySchema
    ) -> float:
        """将决策文本与安全基模匹配，返回相似度"""
        if self.model is None:
            # 如果没有嵌入模型，基于正则匹配返回近似分数
            return self._regex_based_score(decision_text, schema)
        
        # 获取嵌入
        decision_embedding = self.embed_text(decision_text)
        schema_embedding = schema.embedding
        
        if schema_embedding is None:
            # 构建schema文本并计算嵌入
            schema_text = f"{schema.name} {schema.description} {schema.subject_pattern} {schema.object_pattern} {schema.action_pattern}"
            schema_embedding = self.embed_text(schema_text)
            schema.embedding = schema_embedding
        
        return self.cosine_similarity(decision_embedding, schema_embedding)
    
    def _regex_based_score(self, decision_text: str, schema: SecuritySchema) -> float:
        """后备方法：基于正则匹配的分数计算"""
        score = 0.0
        total = 4.0
        
        # 检查各个部分是否匹配
        try:
            if re.search(schema.subject_pattern, decision_text, re.IGNORECASE):
                score += 1.0
        except re.error:
            # 如果正则无效，直接不加分
            pass
        
        try:
            if re.search(schema.object_pattern, decision_text, re.IGNORECASE):
                score += 1.0
        except re.error:
            pass
        
        try:
            if re.search(schema.action_pattern, decision_text, re.IGNORECASE):
                score += 1.0
        except re.error:
            pass
        
        # 简单的条件匹配
        if schema.condition_expr.lower() in decision_text.lower():
            score += 1.0
        
        return score / total
    
    def find_best_matching_schema(
        self,
        decision_text: str,
        schemas: List[SecuritySchema]
    ) -> Tuple[Optional[SecuritySchema], float, List[Tuple[SecuritySchema, float]]]:
        """找到最匹配的安全基模"""
        scores = []
        for schema in schemas:
            similarity = self.match_decision_with_schema(decision_text, schema)
            scores.append((schema, similarity))
        
        scores.sort(key=lambda x: x[1], reverse=True)
        
        if not scores:
            return None, 0.0, []
        
        best_schema, best_score = scores[0]
        return best_schema, best_score, scores
