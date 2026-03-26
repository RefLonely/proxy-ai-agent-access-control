import re
import json
from typing import Dict, List, Optional, Set
from datetime import datetime

from ..models.security_schema import SecuritySchema


class SchemaManager:
    """安全基模管理器 - 管理访问控制规则的结构化表示"""
    
    def __init__(self):
        self.schemas: Dict[str, SecuritySchema] = {}
    
    def add_schema(self, schema: SecuritySchema) -> None:
        """添加安全基模"""
        self.schemas[schema.schema_id] = schema
    
    def create_schema(
        self,
        name: str,
        description: str,
        subject_pattern: str,
        object_pattern: str,
        action_pattern: str,
        condition_expr: str,
        allow: bool = True,
        schema_id: Optional[str] = None
    ) -> SecuritySchema:
        """创建新安全基模"""
        import uuid
        if schema_id is None:
            schema_id = str(uuid.uuid4())
        
        schema = SecuritySchema(
            schema_id=schema_id,
            name=name,
            description=description,
            subject_pattern=subject_pattern,
            object_pattern=object_pattern,
            action_pattern=action_pattern,
            condition_expr=condition_expr,
            allow=allow
        )
        self.add_schema(schema)
        return schema
    
    def get_schema(self, schema_id: str) -> Optional[SecuritySchema]:
        """获取安全基模"""
        return self.schemas.get(schema_id)
    
    def remove_schema(self, schema_id: str) -> bool:
        """移除安全基模"""
        if schema_id in self.schemas:
            del self.schemas[schema_id]
            return True
        return False
    
    def list_schemas(self) -> List[SecuritySchema]:
        """列出所有安全基模"""
        return list(self.schemas.values())
    
    def match_pattern(self, pattern: str, text: str) -> bool:
        """匹配模式"""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error:
            # 正则错误时进行简单字符串匹配
            return pattern.lower() in text.lower()
    
    def query_schemas(
        self,
        subject: str,
        object: str,
        action: str
    ) -> List[SecuritySchema]:
        """查询匹配的安全基模"""
        results = []
        for schema in self.schemas.values():
            if (self.match_pattern(schema.subject_pattern, subject) and
                self.match_pattern(schema.object_pattern, object) and
                self.match_pattern(schema.action_pattern, action)):
                results.append(schema)
        return results
    
    def export_to_json(self, filepath: str) -> None:
        """导出所有基模到JSON文件"""
        data = []
        for schema in self.schemas.values():
            data.append({
                'schema_id': schema.schema_id,
                'name': schema.name,
                'description': schema.description,
                'subject_pattern': schema.subject_pattern,
                'object_pattern': schema.object_pattern,
                'action_pattern': schema.action_pattern,
                'condition_expr': schema.condition_expr,
                'allow': schema.allow,
                'embedding': schema.embedding,
                'created_at': schema.created_at.isoformat(),
                'updated_at': schema.updated_at.isoformat(),
                'metadata': schema.metadata
            })
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def import_from_json(self, filepath: str) -> int:
        """从JSON文件导入基模"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        count = 0
        for item in data:
            schema = SecuritySchema(
                schema_id=item['schema_id'],
                name=item['name'],
                description=item['description'],
                subject_pattern=item['subject_pattern'],
                object_pattern=item['object_pattern'],
                action_pattern=item['action_pattern'],
                condition_expr=item['condition_expr'],
                allow=item.get('allow', True)
            )
            schema.embedding = item.get('embedding')
            schema.metadata = item.get('metadata', {})
            self.add_schema(schema)
            count += 1
        
        return count
    
    def load_default_industrial_schemas(self) -> List[SecuritySchema]:
        """加载工业互联网默认安全基模"""
        default_schemas = [
            self.create_schema(
                name="允许PLC读取操作",
                description="允许任何域内代理读取PLC数据",
                subject_pattern=r".*",
                object_pattern=r"plc|programmable.*logic",
                action_pattern=r"read|get|fetch",
                condition_expr="domain == 'local' AND trust >= 0.5",
                allow=True
            ),
            self.create_schema(
                name="拒绝PLC写入外部",
                description="禁止外部域代理写入PLC",
                subject_pattern=r".*",
                object_pattern=r"plc|programmable.*logic",
                action_pattern=r"write|set|modify",
                condition_expr="domain != 'local' OR trust < 0.8",
                allow=False
            ),
            self.create_schema(
                name="允许SCADA监控",
                description="允许SCADA代理监控设备状态",
                subject_pattern=r"scada|supervisory",
                object_pattern=r".*",
                action_pattern=r"read|monitor|status",
                condition_expr="trust >= 0.6",
                allow=True
            ),
            self.create_schema(
                name="限制机器人控制",
                description="只允许机器人域代理控制机器人",
                subject_pattern=r".*robot.*|robotics",
                object_pattern=r"robot|arm",
                action_pattern=r"control|move",
                condition_expr="domain == 'robotics' AND trust >= 0.9",
                allow=True
            ),
            self.create_schema(
                name="拒绝配置修改低信任",
                description="禁止低信任代理修改配置",
                subject_pattern=r".*",
                object_pattern=r"config|setting|parameter",
                action_pattern=r"configure|modify|change",
                condition_expr="trust < 0.85",
                allow=False
            )
        ]
        
        return default_schemas
