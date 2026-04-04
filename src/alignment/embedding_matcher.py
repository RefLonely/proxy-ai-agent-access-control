from typing import List, Optional, Tuple, Dict
import numpy as np
import re

# 电网专业术语同义词词典 - 用于增强电网场景匹配
POWER_GRID_TERM_SYNONYMS: Dict[str, List[str]] = {
    "台区": ["district", "distribution area", "transformer area", "配网台区", "供电台区"],
    "配电网": ["distribution network", "distributed grid", "配网"],
    "光伏": ["photovoltaic", "pv", "太阳能发电", "光伏电站"],
    "储能": ["energy storage", "battery storage", "储能系统"],
    "虚拟电厂": ["vpp", "virtual power plant"],
    "SCADA": ["supervisory control and data acquisition", "监控和数据采集", "调度自动化"],
    "断路器": ["breaker", "circuit breaker", "开关"],
    "发电机": ["generator", "genset", "发电机组"],
    "变压器": ["transformer", "变电器"],
    "母线": ["bus", "busbar"],
    "馈线": ["feeder"],
    "继电保护": ["relay protection", "protection relay"],
    "调度": ["dispatch", "dispatching", "调派"],
    "发电计划": ["generation schedule", "power plan", "dispatch plan"],
    "并网": ["grid connection", "connect to grid"],
    "离网": ["off grid", "disconnect from grid"],
    "分布式新能源": ["distributed renewable energy", "distributed generation"],
    "需求响应": ["demand response", "dr"],
    "负荷": ["load", "电力负荷"],
}

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMER_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMER_AVAILABLE = False
    SentenceTransformer = None

from ..models.security_schema import SecuritySchema, SchemaMatchResult


class EmbeddingMatcher:
    """嵌入匹配器 - 用于安全基模的嵌入空间对比
    电网场景优化：添加电网专业术语同义词扩展，提高匹配准确率
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", enable_power_grid_optimization: bool = True):
        self.model = None
        self.model_name = model_name
        self.enable_power_grid_optimization = enable_power_grid_optimization
        self.term_synonyms = POWER_GRID_TERM_SYNONYMS
        if SENTENCE_TRANSFORMER_AVAILABLE:
            try:
                self.model = SentenceTransformer(model_name)
            except Exception as e:
                print(f"Warning: Could not load sentence transformer: {e}")
                self.model = None
    
    def _expand_power_grid_terms(self, text: str) -> str:
        """扩展电网专业术语，添加同义词，提高匹配准确率"""
        if not self.enable_power_grid_optimization:
            return text
        
        expanded = text
        for term, synonyms in self.term_synonyms.items():
            if term in expanded or any(s in expanded for s in synonyms):
                # 如果已有术语，添加所有同义词进去，丰富 embedding
                expanded = expanded + " " + " ".join(synonyms)
        
        return expanded
    
    def embed_text(self, text: str) -> Optional[List[float]]:
        """计算文本嵌入 - 电网优化：扩展专业术语"""
        if self.model is None:
            return None
        
        # 电网场景优化：扩展专业术语
        expanded_text = self._expand_power_grid_terms(text)
        embedding = self.model.encode(expanded_text)
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
