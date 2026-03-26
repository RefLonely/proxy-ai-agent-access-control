#!/usr/bin/env python3
"""
示例: 多代理协作信任边界动态维护
演示动态信念图如何自动调整信任边界
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.agent import Agent, AgentState
from src.trust.dynamic_belief_graph import DynamicBeliefGraph
from src.trust.trust_manager import TrustManager


def main():
    print("=" * 60)
print("动态信念图(DBG) - 多代理信任边界维护示例")
print("=" * 60)

# 创建各个域的代理
plc_agent = Agent(
    agent_id="plc_1",
    name="PLC-Agent-1",
    domain="production",
    agent_type="device",
    state=AgentState.ACTIVE
)

scada_agent = Agent(
    agent_id="scada_1", 
    name="SCADA-Agent-1",
    domain="control",
    agent_type="control", 
    state=AgentState.ACTIVE
)

analytics_agent = Agent(
    agent_id="analytics_1",
    name="Analytics-Agent-1", 
    domain="analytics",
    agent_type="analytics",
    state=AgentState.ACTIVE
)

robot_agent = Agent(
    agent_id="robot_1",
    name="Robot-Agent-1",
    domain="robotics", 
    agent_type="device",
    state=AgentState.ACTIVE
)

# 创建本地信任管理器 (以PLC代理为例)
trust_manager = TrustManager(
    local_agent=plc_agent,
    min_trust_threshold=0.5,
    suspicious_threshold=0.3
)

# 添加其他代理，设置初始信任
trust_manager.add_remote_agent(scada_agent, initial_trust=0.8)
trust_manager.add_remote_agent(analytics_agent, initial_trust=0.6)
trust_manager.add_remote_agent(robot_agent, initial_trust=0.7)

print("\n1. 初始状态:")
stats = trust_manager.get_statistics()
print(f"   总代理数: {stats['total_agents']}")
print(f"   可信代理: {stats['trusted_agents']}")
print(f"   不可信: {stats['untrusted_agents']}")

# 检查初始信任评估
print("\n2. 初始信任评估:")
for requester in [scada_agent, analytics_agent, robot_agent]:
    trust_score, allowed = trust_manager.evaluate_access_trust(
        requester.agent_id, plc_agent.agent_id
    )
    print(f"   {requester.name}: 信任={trust_score:.3f}, 允许访问={allowed}")

# 模拟正常交互几次
print("\n3. 模拟成功交互:")
for i in range(3):
    trust_manager.report_interaction_result(scada_agent.agent_id, plc_agent.agent_id, success=True)
print("   SCADA完成3次成功交互后:")
trust_score, allowed = trust_manager.evaluate_access_trust(
    scada_agent.agent_id, plc_agent.agent_id
)
print(f"   SCADA -> PLC: 信任={trust_score:.3f}, 允许访问={allowed}")

# 模拟异常交互
print("\n4. 模拟异常交互 (可疑行为):")
# 分析代理连续失败
for i in range(2):
    trust_manager.report_interaction_result(analytics_agent.agent_id, plc_agent.agent_id, success=False)

print("   分析代理连续2次失败后:")
trust_score, allowed = trust_manager.evaluate_access_trust(
    analytics_agent.agent_id, plc_agent.agent_id
)
print(f"   Analytics -> PLC: 信任={trust_score:.3f}, 允许访问={allowed}")

# 检测异常
anomalies = trust_manager.detect_anomalies()
print(f"   检测到异常代理: {anomalies}")

# 展示信任边界划分
trusted, untrusted = trust_manager.get_trust_boundary()
print(f"\n5. 当前信任边界:")
print(f"   可信域: {trusted}")
print(f"   不可信域: {untrusted}")

# 信念传播
print("\n6. 信念传播后:")
dbg = trust_manager.dbg
beliefs = dbg.propagate_beliefs()
for agent_id, belief in beliefs.items():
    print(f"   {agent_id}: 信念 = {belief:.3f}")

# 输出最终统计
print("\n7. 最终统计:")
stats = trust_manager.get_statistics()
for key, value in stats.items():
    print(f"   {key}: {value}")

print("\n" + "=" * 60)
print("结论: 动态信念图可以根据交互结果自动调整信任，动态伸缩信任边界")
print("当检测到异常行为时，自动降低信任评分，将代理移出可信域")
print("=" * 60)


if __name__ == "__main__":
    main()
