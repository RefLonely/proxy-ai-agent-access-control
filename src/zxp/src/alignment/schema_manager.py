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
        """匹配模式
        修复ReDoS风险：限制正则长度，异常处理
        策略：如果看起来像是复杂正则，直接降级字符串匹配，从根源避免ReDoS
        """
        # 防御ReDoS:
        # 1. 限制正则最大长度
        # 2. 任何包含括号的pattern都降级，因为括号通常意味着分组，容易出现灾难性回溯
        # 这对于我们项目的使用场景足够了，安全优先
        if len(pattern) > 100 or '(' in pattern:
            # 太长或者包含分组，直接回退到字符串匹配
            # 这会损失一点精确匹配，但从安全角度完全值得
            return pattern.lower() in text.lower()
        
        try:
            # 简单无分组正则正常匹配
            return bool(re.search(pattern, text, re.IGNORECASE))
        except (re.error, RuntimeError):
            # 正则错误或者运行异常，回退到简单字符串匹配
            return pattern.lower() in text.lower()
    
    def query_schemas(
        self,
        subject: str,
        object: str,
        action: str
    ) -> List[SecuritySchema]:
        """查询匹配的安全基模
        改进匹配策略：只要有两个部分匹配就算匹配，最后按分数排序
        """
        results = []
        for schema in self.schemas.values():
            s_match = self.match_pattern(schema.subject_pattern, subject)
            o_match = self.match_pattern(schema.object_pattern, object)
            a_match = self.match_pattern(schema.action_pattern, action)
            
            # 计数匹配的部分
            match_count = sum([s_match, o_match, a_match])
            
            # 至少匹配两个部分，或者其中object模式是.*全匹配
            if match_count >= 2 or (schema.object_pattern in ['.*', r".*"]):
                results.append(schema)
            elif match_count == 1 and a_match:
                # 至少action匹配上也加入
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
    
    def load_default_power_grid_schemas(self) -> List[SecuritySchema]:
        """加载电网默认安全基模 - 符合《电力监控系统安全防护规定》"""
        default_schemas = [
            self.create_schema(
                name="允许台区代理读取光伏数据",
                description="允许同一台区代理读取光伏终端数据",
                subject_pattern=r".*台区.*|district.*area",
                object_pattern=r"光伏|photovoltaic|pv",
                action_pattern=r"read|get|fetch|monitor",
                condition_expr="domain == 'district' AND trust >= 0.5",
                allow=True
            ),
            self.create_schema(
                name="允许储能终端读取本地数据",
                description="允许同一配网域储能终端读取本地数据",
                subject_pattern=r"储能|energy.*storage",
                object_pattern=r".*",
                action_pattern=r"read|get|status",
                condition_expr="domain == 'distribution' AND trust >= 0.5",
                allow=True
            ),
            self.create_schema(
                name="拒绝跨区控制光伏设备",
                description="禁止非本区代理控制光伏设备",
                subject_pattern=r".*",
                object_pattern=r"光伏|photovoltaic|pv",
                action_pattern=r"control|write|set|adjust",
                condition_expr="domain != 'district' OR trust < 0.8",
                allow=False
            ),
            self.create_schema(
                name="允许SCADA系统远程监控",
                description="允许SCADA代理监控全网设备状态",
                subject_pattern=r"scada|supervisory",
                object_pattern=r".*",
                action_pattern=r"read|monitor|status",
                condition_expr="trust >= 0.6",
                allow=True
            ),
            self.create_schema(
                name="拒绝非授权修改电网配置",
                description="禁止低信任代理修改电网设备配置",
                subject_pattern=r".*",
                object_pattern=r"config|setting|parameter|topology",
                action_pattern=r"configure|modify|change|adjust",
                condition_expr="trust < 0.8",
                allow=False
            ),
            self.create_schema(
                name="允许虚拟电厂内部协作",
                description="允许虚拟电厂内部代理协作访问",
                subject_pattern=r".*vpp|virtual.*power.*plant",
                object_pattern=r".*vpp|virtual.*power.*plant",
                action_pattern=r"read|data|exchange",
                condition_expr="domain == 'vpp' AND trust >= 0.5",
                allow=True
            ),
            self.create_schema(
                name="拒绝外部修改虚拟电厂计划",
                description="禁止外部代理修改虚拟电厂发电计划",
                subject_pattern=r".*",
                object_pattern=r".*plan|schedule|dispatch",
                action_pattern=r"modify|change|set",
                condition_expr="domain != 'vpp' OR trust < 0.8",
                allow=False
            ),
            self.create_schema(
                name="三级区域权限隔离",
                description="大区不能直接修改小区设备",
                subject_pattern=r".*region.*",
                object_pattern=r".*district.*|terminal",
                action_pattern=r"control|write|set",
                condition_expr="trust < 0.8",
                allow=False
            ),
            self.create_schema(
                name="允许厂站远程信号采集",
                description="允许厂站代理采集远程信号",
                subject_pattern=r".*station|plant",
                object_pattern=r".*signal|measurement|data",
                action_pattern=r"read|collect|fetch",
                condition_expr="trust >= 0.6",
                allow=True
            ),
            self.create_schema(
                name="拒绝非法控制断路器",
                description="禁止未授权操作断路器",
                subject_pattern=r".*",
                object_pattern=r"breaker|switch|circuit",
                action_pattern=r"open|close|trip",
                condition_expr="trust < 0.9",
                allow=False
            )
        ]
        
        return default_schemas
    
    def load_default_industrial_schemas(self) -> List[SecuritySchema]:
        """兼容旧接口 - 加载工业互联网默认安全基模"""
        return self.load_default_power_grid_schemas()
