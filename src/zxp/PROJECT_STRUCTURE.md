# 电网卫士平台项目框架文档

## 项目概述

**项目名称：** 电网卫士：面向新型电力系统的分布式智能代理自主访问控制与内生安全防御平台

**选题方向：** 智能与前沿安全 → 代理式AI(Agentic AI)自主访问控制

**赛项：** 2026-A-ST 网络空间与信息安全创意作品赛

---

## 当前项目结构

```
测试1/
├── README.md                           # 项目主README
├── PROJECT_INTRO.md                    # 项目介绍文档
├── PROJECT_PLAN.md                     # 项目开发计划
├── PROJECT_STRUCTURE.md                # 本文件，项目框架说明
├── requirements.txt                    # Python依赖清单
├── LICENSE                             # 许可证 (MIT)
│
├── docs/                               # 详细文档目录
│   ├── problem.md                     # 前沿技术难题详细描述
│   ├── solution.md                    # 创新解决方案详细设计
│   ├── evaluation.md                  # 实验评估与结果分析
│   ├── REFERENCES.md                  # 参考文献与参考资料
│   ├── 问题与解决方案整理.md          # 中文问题与方案整理
│   ├── Agentic AI安全与工业互联网访问控制论文整理.md
│   └── 参考文献需求清单.md
│
├── src/                                # 核心源代码
│   ├── __init__.py
│   ├── access_controller.py           # 主访问控制器，整合DBG和SSC两大模块
│   │
│   ├── models/                         # 核心数据模型
│   │   ├── __init__.py
│   │   ├── agent.py                  # 代理实体模型
│   │   ├── access_request.py         # 访问请求模型
│   │   └── security_schema.py        # 安全基模模型
│   │
│   ├── trust/                          # 信任边界动态维护模块 (DBG)
│   │   ├── __init__.py
│   │   ├── dynamic_belief_graph.py   # 动态信念图实现
│   │   ├── trust_manager.py          # 信任管理器
│   │   └── consensus.py             # 分布式共识实现
│   │
│   └── alignment/                      # 幻觉抑制与安全对齐模块 (SSC)
│       ├── __init__.py
│       ├── schema_manager.py         # 安全基模管理器
│       ├── embedding_matcher.py      # 嵌入比对器
│       └── alignment_validator.py   # 对齐验证器
│
├── examples/                           # 示例代码
│   ├── dynamic_trust_example.py       # 动态信任边界维护示例 ✅ 已实现
│   └── hallucination_suppression_example.py  # 幻觉抑制示例 ✅ 已实现
│
└── tests/                              # 单元测试目录 (待完善)
    └── __init__.py
```

---

## 模块依赖关系

```
examples/
    ↓
src/access_controller.py
    ↓
┌───────────────────┴───────────────────┐
↓                               ↓
src/trust/                     src/alignment/
   ↓                              ↓
dynamic_belief_graph        schema_manager
trust_manager               embedding_matcher
consensus                   alignment_validator
└───────────────────┬───────────────────┘
                   ↓
            输出访问决策
```

---

## 核心模块职责

### 1. src/models/ - 数据模型层

| 文件 | 职责 |
|------|------|
| `agent.py` | 定义代理实体，包含代理ID、类型、信任评分等属性 |
| `access_request.py` | 定义访问请求，包含主体、客体、操作、时间戳、上下文信息 |
| `security_schema.py` | 定义安全基模四元组结构：主体-客体-操作-条件 |

### 2. src/trust/ - 动态信任边界维护 (DBG)

| 文件 | 职责 |
|------|------|
| `dynamic_belief_graph.py` | 实现动态信念图数据结构，支持添加/删除节点、更新边权重、信念传播 |
| `trust_manager.py` | 高层API，管理信任评分计算、异常衰减、阈值判断 |
| `consensus.py` | 轻量级分布式共识算法，保证多节点信任状态一致性 |

**关键算法：**
- 信任聚合：`Trust = α*Direct + (1-α)*Indirect`
- 异常衰减：`Trust = Trust * γ^n`
- 多级阈值：四个信任等级对应不同访问策略

### 3. src/alignment/ - 幻觉抑制与安全对齐 (SSC)

| 文件 | 职责 |
|------|------|
| `schema_manager.py` | 安全基模的增删改查管理，基模嵌入缓存 |
| `embedding_matcher.py` | 调用嵌入模型，计算候选决策与基模的余弦相似度 |
| `alignment_validator.py` | 整合结构匹配+嵌入比对，输出验证结果，决定是否接受LLM决策 |

**关键算法：**
- 一致性评分：`Score = w1*StructureMatch + w2*CosineSim`
- 阈值判断：Score > threshold 接受，否则拒绝

### 4. src/access_controller.py - 主控制器

整合两大模块，对外提供统一API：
```python
class AccessController:
    def evaluate_access_request(self, request) -> Decision
        # 1. 信任评分
        # 2. LLM生成候选决策
        # 3. 安全对齐验证
        # 4. 返回最终决策
```

---

## 示例与测试

| 文件 | 功能 | 状态 |
|------|------|------|
| `examples/dynamic_trust_example.py` | 演示动态信念图构建、信任传播、异常衰减过程 | ✅ 已完成 |
| `examples/hallucination_suppression_example.py` | 演示正常决策和幻觉决策的不同验证结果 | ✅ 已完成 |
| `tests/` | 单元测试目录 | ⚠️ 待完善 |

---

## 创新点对应代码位置

| 创新点 | 代码位置 |
|--------|----------|
| 动态信念图(DBG) | `src/trust/` |
| 安全基模对比(SSC) | `src/alignment/` |
| 整合访问控制 | `src/access_controller.py` |

---

## 入口点

- **命令行演示**：`python examples/full_demo.py`
- **开发导入**：`from src.access_controller import AccessController`
- **API服务**：可基于`AccessController`快速封装REST API

---

## 依赖清单

项目依赖参见 `requirements.txt`，主要包括：

**核心必需依赖：**
- `networkx>=2.8` - 图数据结构与算法
- `numpy>=1.21` - 数值计算
- `scipy>=1.10` - 稀疏矩阵与空间距离计算
- `dataclasses-json>=0.5` - 数据类JSON序列化

**可选依赖（用于句子嵌入）：**
- `sentence-transformers>=2.2` - 文本嵌入生成
- `torch>=1.12` - PyTorch深度学习框架

**开发测试依赖：**
- `pytest>=7.0` - 单元测试框架
- `pytest-cov>=3.0` - 测试覆盖率统计
