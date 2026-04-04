from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from datetime import datetime


@dataclass
class SecuritySchema:
    """安全基模表示 - 结构化的访问控制规则"""
    schema_id: str
    name: str
    description: str
    
    # 四元组结构: (主体, 客体, 操作, 条件)
    subject_pattern: str  # 主体匹配模式 (正则)
    object_pattern: str   # 客体匹配模式
    action_pattern: str  # 操作匹配模式
    condition_expr: str  # 条件表达式
    
    # 允许/拒绝
    allow: bool = True
    
    # 嵌入向量，用于对比匹配
    embedding: Optional[List[float]] = None
    
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    metadata: Dict = field(default_factory=dict)


@dataclass
class SchemaMatchResult:
    """安全基模匹配结果"""
    schema: SecuritySchema
    subject_match: bool
    object_match: bool
    action_match: bool
    condition_match: bool
    embedding_similarity: float  # 嵌入空间相似度 0-1
    overall_score: float  # 总体匹配分数
    
    @property
    def is_match(self) -> bool:
        """是否完全匹配"""
        return all([
            self.subject_match,
            self.object_match,
            self.action_match,
            self.condition_match,
            self.embedding_similarity >= 0.7
        ])
