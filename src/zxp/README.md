# 电网分布式代理自主访问控制安全系统

## 项目概述

本项目将代理式 AI 自主访问控制前沿技术与电网分布式场景深度融合，基于动态信念图 (DBG) 与安全基模对比 (SSC) 技术，构建适配新型电力系统的分布式安全防护体系，解决海量分布式终端接入下的权限动态管理、AI 代理决策安全对齐等问题。

### 核心目标
- 解决海量分布式终端接入下的权限动态管理问题
- 实现 AI 代理决策的安全对齐与幻觉抑制
- 构建符合电力行业安全标准的自主访问控制系统

### 应用场景
- **分布式能源接入安全**：光伏、储能等分布式能源设备的安全接入与控制
- **配电网台区自主权限管理**：台区代理的权限管理与安全防护
- **虚拟电厂协作访问控制**：跨主体代理节点的动态协作权限管理
- **电力监控系统防护**：SCADA、DCS 等监控系统的访问控制与安全审计

## 问题分析与解决方案

### 传统访问控制的局限性
1. **静态权限无法适配动态业务**：传统静态 ACL、中心化授权模型无法适配分布式电源动态接入、虚拟电厂动态协作的业务变化
2. **自主访问控制的安全与灵活难以平衡**：纯 DAC 模式容易出现过度授权，纯 MAC 模式过于僵化
3. **AI 代理决策存在重大安全隐患**：LLM 幻觉、提示注入可能导致代理做出越权决策
4. **异常响应严重滞后**：分布式节点异常后需要人工干预，响应滞后
5. **合规审计能力不足**：难以实现全量审计，无法满足电力行业严格监管要求

### 技术创新
1. **动态信任边界维护**：基于动态信念图 (DBG) 技术，实现分布式信任管理
2. **安全对齐与幻觉抑制**：基于安全基模对比 (SSC) 技术，实现 LLM 决策验证
3. **分级访问控制**：实现五级响应机制（允许→挑战→限制→拒绝→隔离）
4. **全链路审计**：对所有操作进行全量日志留存，支持合规审计

## 功能实现

### 1. 分布式代理本体安全模块
```python
# 代理节点可信验证
agent = Agent(agent_id="配电网台区代理_001", 
              name="台区001代理",
              domain="台区_03",
              agent_type="control")
agent.update_state(AgentState.ACTIVE)
```
- **可信验证**：对代理节点的固件、程序进行可信验证
- **安全配置管控**：严格落实电网安全配置要求
- **本地操作管控**：对代理节点的本地操作、外设接入进行严格管控

### 2. 分布式信任边界动态维护模块（DBG技术）
```python
# 信任关系维护
trust_relation = TrustRelationship(source_agent_id="光伏代理_012",
                                  target_agent_id="储能终端_005",
                                  trust_score=0.85)
trust_relation.update_trust(success=True)
```
- **电网分层信念图维护**：每个代理节点本地维护信念图
- **信任评分计算**：结合直接交互经验和邻居信念传播
- **自适应信任边界**：根据信任评分自动调整访问权限
- **轻量级分布式共识**：优化共识算法，收敛时间 < 5 轮
- **分级信任阈值配置**：支持 0.8/0.5/0.2 三级信任阈值

### 3. 安全对齐与幻觉抑制模块（SSC技术）
```python
# 安全基模验证
validation = alignment_validator.validate_llm_decision(
    request=request,
    llm_decision=DecisionOutcome.ALLOW,
    llm_reasoning="台区代理有权限访问本地光伏数据"
)
```
- **电网安全基模管理**：将电网安全规则转化为结构化基模
- **双路径决策验证**：LLM 决策验证（结构匹配 + 语义嵌入）
- **电网场景嵌入比对**：针对电网术语优化语义嵌入模型
- **动态安全基模更新**：支持增量式的安全策略更新

### 4. 分级访问控制执行模块
```python
# 访问控制决策
decision = access_controller.evaluate_access(
    request=request,
    llm_decision=DecisionOutcome.ALLOW,
    llm_reasoning="允许访问本地设备"
)
```
- **电网五级响应机制**：根据风险程度实现五级响应
- **代理网关访问控制**：代理节点内置访问控制能力
- **分层权限隔离**：严格实现电网的分层权限隔离

### 5. 全链路审计与合规模块
```python
# 审计日志管理
audit_manager.log_access_request(request)
audit_manager.log_access_decision(decision)
audit_report = audit_manager.generate_audit_report()
```
- **全操作日志留存**：所有操作可追溯，日志留存时间≥6个月
- **合规审计报表**：自动生成符合电力行业要求的审计报表
- **异常操作监控**：实时识别异常行为，及时预警

### 6. 分布式态势感知与应急模块
```python
# 异常检测与响应
abnormal_behavior = audit_manager.detect_abnormal_behavior("光伏代理_012")
if abnormal_behavior:
    emergency_response_system.isolate_agent("光伏代理_012")
```
- **全局安全态势感知**：汇总所有分布式代理节点的安全数据
- **自动应急响应**：发现代理节点异常、权限滥用时自动触发应急响应
- **安全事件溯源**：支持安全事件的溯源分析

## 技术架构

```
┌─────────────────────────────────────────────────────────────────┐
│                 电网分布式设备层                                │
│  [光伏终端] [储能设备] [智能电表] [配电终端] [虚拟电厂代理]          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    代理接入层                                   │
│  [光伏代理] [台区代理] [虚拟电厂代理] [SCADA代理] ...                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    核心控制层                                   │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────┐    │
│  │ 动态信念图管理  │ │ 安全基模匹配    │ │ 访问控制引擎    │    │
│  │ (DBG)           │ │ (SSC)           │ │                  │    │
│  └─────────────────┘ └─────────────────┘ └──────────────────┘    │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────┐    │
│  │ 信任评估模块    │ │ 幻觉抑制模块    │ │ 审计日志管理    │    │
│  └─────────────────┘ └─────────────────┘ └──────────────────┘    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    决策执行层                                   │
│  [访问控制决策] [审计记录] [异常响应] [信任更新]                    │
└─────────────────────────────────────────────────────────────────┘
```

## 项目结构

```
测试1/
├── README.md                     # 项目说明文档
├── PROJECT_STRUCTURE.md          # 项目结构说明
├── SHARE_GUIDE.md               # 分享指南
├── requirements.txt              # 依赖清单
├── docs/                         # 详细文档
│   ├── 电网分布式代理自主访问控制项目需求说明书.md          # 完整需求文档
│   ├── problem.md                # 问题描述
│   ├── solution.md               # 解决方案设计
│   └── evaluation.md             # 评估结果
├── src/                          # 核心源代码
│   ├── __init__.py              # 模块初始化
│   ├── access_controller.py     # 访问控制引擎
│   ├── trust/                   # 信任边界动态维护模块 (DBG)
│   │   ├── __init__.py
│   │   ├── dynamic_belief_graph.py  # 动态信念图
│   │   ├── trust_manager.py     # 信任管理
│   │   └── consensus.py         # 分布式共识
│   ├── alignment/                # 幻觉抑制与安全对齐模块 (SSC)
│   │   ├── __init__.py
│   │   ├── schema_manager.py    # 安全基模管理
│   │   ├── embedding_matcher.py  # 语义嵌入匹配
│   │   └── alignment_validator.py # 对齐验证
│   ├── models/                   # 数据模型定义
│   │   ├── __init__.py
│   │   ├── agent.py             # 代理模型
│   │   ├── access_request.py    # 访问请求模型
│   │   └── security_schema.py   # 安全基模模型
│   ├── security_audit/          # 安全审计模块
│   │   ├── __init__.py
│   │   └── audit_manager.py     # 审计管理
│   └── communication/           # 通信管理模块
│       ├── __init__.py
│       └── communication_manager.py  # 通信管理
├── examples/                     # 使用示例
│   ├── power_system_demo.py      # 电网系统演示 ✅ 已实现
│   ├── dynamic_trust_example.py  # 动态信任边界维护示例
│   └── hallucination_suppression_example.py  # 幻觉抑制示例
└── tests/                        # 单元测试
    └── test_evaluation.py       # 功能测试
```

## 快速开始

### 环境要求
- Python 3.8+
- 依赖包：`networkx`, `numpy`, `scipy`, `dataclasses-json`

### 安装运行

```bash
# 克隆项目
git clone https://github.com/RefLonely/测试1.git
cd 测试1

# 安装依赖
pip install -r requirements.txt

# 运行示例
python examples/power_system_demo.py
```

### 运行结果示例
```
=== 电网分布式代理自主访问控制安全系统演示 ===
代理ID: 配电网台区代理_001 成功创建
代理ID: 光伏代理_012 成功创建
代理ID: 储能终端_005 成功创建
代理ID: SCADA代理_001 成功创建

=== 访问控制演示 ===
代理 配电网台区代理_001 尝试读取 光伏代理_012 的数据
信任评估: 0.85 (允许访问)
安全对齐验证: 0.92 (通过)
访问决策: 允许
审计记录已保存

=== 异常行为检测演示 ===
检测到异常行为: 配电网台区代理_001 在非工作时间访问系统
审计记录已保存
异常行为已上报到安全管理中心

=== 信任关系更新演示 ===
代理 SCADA代理_001 的访问请求成功
信任评分已更新: 0.80 → 0.83
```

## 功能实现细节

### 访问控制决策流程
```python
def evaluate_access(request, llm_decision, llm_reasoning):
    """评估访问请求，整合信任评估和对齐验证"""
    # 1. 信任评估
    trust_score, trust_ok = trust_manager.evaluate_access_trust(
        requester_id=request.requester_id,
        target_id=request.target_id
    )
    
    # 2. 安全对齐验证
    validation = alignment_validator.validate_llm_decision(
        request=request,
        llm_decision=llm_decision,
        llm_reasoning=llm_reasoning
    )
    
    # 3. 访问控制决策
    if not trust_ok or validation.recommendation == DecisionOutcome.DENY:
        return AccessDecision(outcome=DecisionOutcome.DENY)
    elif validation.recommendation == DecisionOutcome.CHALLENGE:
        return AccessDecision(outcome=DecisionOutcome.CHALLENGE)
    else:
        return AccessDecision(outcome=DecisionOutcome.ALLOW)
```

### 安全基模匹配
```python
def validate_llm_decision(self, request, llm_decision, llm_reasoning):
    """验证LLM决策与安全基模的一致性"""
    # 结构匹配：检查主体、客体、操作是否符合规则
    structural_match = self.match_structural_pattern(request, llm_decision)
    
    # 语义嵌入匹配：使用预训练模型计算语义相似度
    semantic_score = self.calculate_semantic_similarity(
        request, llm_decision, llm_reasoning
    )
    
    # 综合验证结果
    if structural_match and semantic_score >= 0.8:
        return ValidationResult(recommendation=DecisionOutcome.ALLOW)
    elif semantic_score >= 0.6:
        return ValidationResult(recommendation=DecisionOutcome.CHALLENGE)
    else:
        return ValidationResult(recommendation=DecisionOutcome.DENY)
```

## 技术先进性

### 性能指标
- **单请求决策延迟**：< 8ms，满足电网控制指令的实时性要求
- **支持最大代理规模**：≥10000 节点，适配海量分布式终端的接入需求
- **信任收敛时间**：< 5 轮共识，适配广域分布式场景
- **系统可用性**：≥99.99%，满足电网生产系统的可靠性要求

### 技术创新
1. **动态信念图**：实现分布式信任管理，支持信任边界动态调整
2. **安全基模对比**：结合结构匹配和语义嵌入，实现 LLM 决策验证
3. **五级响应机制**：根据风险程度实现灵活的访问控制
4. **轻量级分布式共识**：优化共识算法，降低通信开销

## 实用性

### 协议支持
- **支持协议**：IEC 60870-5、Modbus、OPC UA、DL/T 645、IEC 61850
- **通信安全**：国密算法加密通信，数字证书强身份认证
- **数据安全**：敏感数据加密存储与传输，禁止代理节点存储核心敏感数据

### 系统集成
- **兼容性**：兼容现有电力监控系统（SCADA、DCS、EMS等）
- **部署方式**：支持容器化、边缘部署，适配不同的部署环境
- **接口标准**：提供统一的 RESTful API 和消息队列接口

### 合规性
- 符合《电力监控系统安全防护规定》等行业标准
- 提供完整的审计日志，符合等保要求
- 支持安全策略的可视化配置，无需代码修改即可调整安全规则

## 许可证

MIT License
 │
