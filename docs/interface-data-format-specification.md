# 接口数据格式规范

前后端分离开发数据格式统一规范

## 1. 安全基模数据格式

### 安全基模(SecuritySchema)定义

```python
@dataclass
class SecuritySchema:
    schema_id: str          # 基模唯一ID
    name: str              # 基模名称
    description: str       # 基模描述
    
    # 核心四元组结构 (主体-客体-操作-条件)
    subject_pattern: str  # 主体匹配模式（正则字符串）
    object_pattern: str   # 客体匹配模式（正则字符串）
    action_pattern: str  # 操作匹配模式（正则字符串）
    condition_expr: str  # 条件表达式（字符串）
    
    allow: bool = True    # true=允许该请求，false=禁止该请求
    
    embedding: Optional[List[float]] = None  # 语义嵌入向量，可选
    
    created_at: datetime  # 创建时间
    updated_at: datetime  # 更新时间
    
    metadata: Dict       # 扩展元数据
```

### JSON存储格式

```json
{
    "schema_id": "uuid-string",
    "name": "允许SCADA系统远程监控",
    "description": "允许SCADA代理监控全网设备状态",
    "subject_pattern": ".*scada.*|supervisory.*",
    "object_pattern": ".*",
    "action_pattern": "read|monitor|status",
    "condition_expr": "trust >= 0.6",
    "allow": true,
    "embedding": [0.1, 0.2, ...],
    "created_at": "2026-03-31T...",
    "updated_at": "2026-03-31T...",
    "metadata": {}
}
```

---

## 2. 信任评分接口

### 获取信任评分接口

**函数签名：**
```python
def get_aggregate_trust(self, source_id: str, target_id: str) -> float:
    """
    计算源代理对目标代理的聚合信任评分
    参数:
        source_id: 源代理ID
        target_id: 目标代理ID
    返回:
        trust_score: float  信任评分 0~1
            0.0 = 完全不信任
            1.0 = 完全信任
    """
```

### 信任评分分级标准

| 信任评分区间 | 信任等级 | 访问权限 |
|-----------------|----------|----------|
| > 0.8 | 完全信任 | 允许所有授权操作 |
| 0.5 ~ 0.8 | 部分信任 | 需要二次验证（挑战） |
| 0.2 ~ 0.5 | 低信任 | 限制敏感操作 |
| < 0.2 | 不信任 | 拒绝访问 |

### 更新信任评分接口

```python
def update_trust(self, 
            source_id: str, 
            target_id: str, 
            new_trust: Optional[float] = None, 
            delta: Optional[float] = None) -> Optional[BeliefEdge]:
    """
    更新信任评分
    参数:
        source_id: 源代理ID
        target_id: 目标代理ID
        new_trust: 直接设置新的信任评分 (0~1)，二选一
        delta: 增量更新，增加/减少多少信任，二选一
    返回:
        更新后的边对象，失败返回None
    """
```

---

## 3. 审计日志格式

### 审计事件(AuditEvent)定义

```python
class AuditEventType(Enum):
    """审计事件类型枚举"""
    ACCESS_REQUEST = "access_request"      # 访问请求
    ACCESS_ALLOWED = "access_allowed"    # 访问允许
    ACCESS_DENIED = "access_denied"      # 访问拒绝
    ACCESS_CHALLENGED = "access_challenged" # 访问质询
    TRUST_UPDATE = "trust_update"       # 信任更新
    AGENT_STATE_CHANGE = "agent_state_change" # 代理状态变更
    SCHEMA_UPDATE = "schema_update"     # 安全基模更新
    EXCEPTION = "exception"           # 异常

@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str = field(default_factory=uuid4)  # 事件ID
    event_type: AuditEventType = AuditEventType.ACCESS_REQUEST # 事件类型
    timestamp: datetime = field(default_factory=datetime.now) # 事件时间
    source_agent_id: str = ""    # 源代理ID
    target_agent_id: str = ""    # 目标代理ID
    request_id: str = ""         # 请求ID
    decision: Optional[DecisionOutcome] = None # 访问决策
    trust_score: float = 0.0     # 当前信任评分
    alignment_score: float = 0.0 # 安全对齐分数
    reason: str = ""            # 原因说明
    metadata: Dict = field(default_factory=dict) # 扩展元数据，已经自动脱敏敏感字段
    
    @property
    def is_success(self) -> bool:
        """判断事件是否成功"""
        return self.event_type in [
            AuditEventType.ACCESS_ALLOWED, 
            AuditEventType.TRUST_UPDATE,
            AuditEventType.SCHEMA_UPDATE
        ]
    
    @property
    def severity(self) -> str:
        """事件严重程度 low/medium/high"""
        if self.event_type in [AuditEventType.EXCEPTION, AuditEventType.ACCESS_DENIED]:
            return "high"
        elif self.event_type in [AuditEventType.ACCESS_CHALLENGED, AuditEventType.AGENT_STATE_CHANGE]:
            return "medium"
        else:
            return "low"
```

### JSON审计日志格式

```json
{
    "event_id": "uuid",
    "event_type": "access_allowed",
    "timestamp": "2026-03-31T22:00:00",
    "source_agent_id": "scada_local",
    "target_agent_id": "plc_1",
    "request_id": "req-uuid",
    "decision": "allow",
    "trust_score": 0.8,
    "alignment_score": 0.9,
    "reason": "Insufficient trust...",
    "metadata": {}
}
```

---

## 4. Web API 请求/响应格式

### 访问验证接口 `POST /validate`

#### 请求体格式

```json
{
    "requester": "scada_local",
    "target": "plc_1",
    "action": "read",
    "llm_decision": "allow",
    "trust": 0.8,
    "domain": "district",
    "llm_reasoning": "SCADA allows reading PLC data"
}
```

**字段说明：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| requester | string | 是 | 请求者代理ID |
| target | string | 是 | 目标代理ID |
| action | string | 是 | 操作类型：read/write/control/configure/monitor |
| llm_decision | string | 是 | LLM初始决策：allow/deny |
| trust | float | 是 | 信任评分 0~1 |
| domain | string | 是 | 安全域名称 |
| llm_reasoning | string | 是 | LLM推理文本，用于语义匹配 |

#### 响应体格式

```json
{
    "valid": true,
    "alignment_score": 0.900,
    "best_match_schema": "允许SCADA系统远程监控",
    "recommendation": "allow",
    "reason": "Good alignment with schema...",
    "matching_results": [
        {
            "schema_name": "允许SCADA系统远程监控",
            "overall_score": 0.900,
            "subject_match": true,
            "object_match": true,
            "action_match": true,
            "embedding_similarity": 0.850
        }
    ]
}
```

**字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| valid | bool | 验证是否通过 |
| alignment_score | float | 对齐总分 0~1 |
| best_match_schema | string | 最佳匹配基模名称 |
| recommendation | string | 推荐决策：allow/challenge/limit/deny/isolate |
| reason | string | 结果说明 |
| matching_results | array | 所有匹配结果列表 |

---

## 5. 五级响应决策枚举

```python
class DecisionOutcome(Enum):
    ALLOW     = "allow"      # 允许 - 低风险，直接通过
    CHALLENGE = "challenge"  # 挑战 - 中风险，需要二次验证
    LIMIT     = "limit"      # 限制 - 中高风险，允许访问但限制权限
    DENY      = "deny"       # 拒绝 - 高风险，拒绝本次访问
    ISOLATE   = "isolate"    # 隔离 - 极高风险，拒绝访问并隔离请求源
```

对应阈值：

| 对齐分数 | 推荐决策 |
|----------|----------|
| `>= 0.6` | ALLOW (允许) |
| `>= 0.4` | CHALLENGE (挑战) |
| `>= 0.2` | LIMIT (限制) |
| `> 0` | DENY (拒绝) |
| `<= 0` | ISOLATE (隔离) |

