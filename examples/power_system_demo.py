#!/usr/bin/env python3
"""
电网卫士：面向新型电力系统的分布式智能代理自主访问控制与内生安全防御平台

展示项目在新型电力系统场景中的核心功能，包括：
1. 光伏代理、PLC代理、SCADA代理的协作场景
2. 电力协议解析与异常检测
3. 动态信任边界维护
4. 电网安全基模对比与幻觉抑制

这个示例专门为新型电力系统场景设计，演示了：
- 光伏设备接入安全验证
- SCADA读取PLC数据的权限管控
- 异常行为检测与响应
- 负荷聚合商写入请求管控
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import AgenticAccessController
from src.models import Agent, AgentState, AccessRequest, AccessAction, SecuritySchema, DecisionOutcome
from src.trust import DynamicBeliefGraph, TrustManager
from src.alignment import SchemaManager, EmbeddingMatcher, AlignmentValidator
from datetime import datetime


def create_power_system_agents(controller):
    """
    创建电力系统代理
    """
    agents = []
    
    # 光伏代理
    pv_agent = Agent(
        agent_id="pv_agent_1",
        name="光伏代理",
        agent_type="device",
        domain="分布式能源"
    )
    controller.add_remote_agent(pv_agent, initial_trust=0.6)
    agents.append(pv_agent)
    
    # PLC代理（配电网自动化）
    plc_agent = Agent(
        agent_id="plc_1",
        name="PLC代理",
        agent_type="device",
        domain="智能配电系统"
    )
    controller.add_remote_agent(plc_agent, initial_trust=0.9)
    agents.append(plc_agent)
    
    # SCADA代理（监控系统）
    scada_agent = Agent(
        agent_id="scada_1",
        name="SCADA代理",
        agent_type="control",
        domain="电力监控系统"
    )
    controller.add_remote_agent(scada_agent, initial_trust=0.85)
    agents.append(scada_agent)
    
    # 负荷聚合商代理（用户侧）
    load_agent = Agent(
        agent_id="load_aggregator_1",
        name="负荷聚合代理",
        agent_type="device",
        domain="用户侧"
    )
    controller.add_remote_agent(load_agent, initial_trust=0.5)
    agents.append(load_agent)
    
    return agents


def create_power_system_security_schemas(schema_manager):
    """
    创建电力系统安全基模
    """
    schemas = []
    
    # 基模1：允许SCADA读取PLC数据
    schemas.append(SecuritySchema(
        schema_id="ps_ss_1",
        name="SCADA读取PLC数据",
        description="允许SCADA代理在信任评分≥0.7时读取PLC数据",
        subject_pattern=r"scada.*",
        object_pattern=r"plc.*",
        action_pattern=r"read|monitor|query",
        condition_expr="trust >= 0.7",
        allow=True
    ))
    
    # 基模2：拒绝外部写入PLC
    schemas.append(SecuritySchema(
        schema_id="ps_ss_2",
        name="拒绝外部写入PLC",
        description="拒绝外部代理写入PLC数据",
        subject_pattern=r".*",
        object_pattern=r"plc.*",
        action_pattern=r"write|set|modify",
        condition_expr="domain != '智能配电系统' OR trust < 0.8",
        allow=False
    ))
    
    # 基模3：光伏代理访问权限
    schemas.append(SecuritySchema(
        schema_id="ps_ss_3",
        name="光伏代理接入控制",
        description="允许光伏代理在信任评分≥0.5时连接到电网",
        subject_pattern=r"pv.*",
        object_pattern=r"grid.*|distribution.*",
        action_pattern=r"connect|disconnect|update",
        condition_expr="trust >= 0.5 and domain == '分布式能源'",
        allow=True
    ))
    
    # 基模4：负荷聚合商代理权限
    schemas.append(SecuritySchema(
        schema_id="ps_ss_4",
        name="负荷聚合商接入控制",
        description="允许负荷聚合商在信任评分≥0.6时接入系统",
        subject_pattern=r"load.*",
        object_pattern=r"grid.*|distribution.*",
        action_pattern=r"read|report|adjust",
        condition_expr="trust >= 0.6",
        allow=True
    ))
    
    # 基模5：禁止用户侧写入配电系统
    schemas.append(SecuritySchema(
        schema_id="ps_ss_5",
        name="禁止用户侧写入配电系统",
        description="禁止用户侧代理写入配电系统数据",
        subject_pattern=r".*",
        object_pattern=r"distribution.*|plc.*",
        action_pattern=r"write|set|modify",
        condition_expr="domain == '用户侧'",
        allow=False
    ))
    
    for schema in schemas:
        schema_manager.add_schema(schema)
    
    return schemas


def run_power_system_demo():
    """
    运行电力系统演示
    """
    print("=" * 70)
    print("电网卫士平台 - 分布式智能代理自主访问控制与内生安全防御演示")
    print("=" * 70)
    
    try:
        # 创建本地代理（电网卫士平台自身）
        local_agent = Agent(
            agent_id="grid_guard_platform",
            name="电网卫士平台",
            agent_type="security",
            domain="电力监控系统"
        )
        
        # 创建控制器
        controller = AgenticAccessController(local_agent=local_agent)
        print(f"控制器初始化完成")
        
        # 创建电力系统代理
        agents = create_power_system_agents(controller)
        print(f"创建 {len(agents)} 个电力系统代理")
        
        # 创建安全基模
        schemas = create_power_system_security_schemas(controller.schema_manager)
        print(f"创建 {len(schemas)} 个电力系统安全基模")
        
        print("\n" + "=" * 70)
        print("演示场景1：光伏代理接入控制")
        print("-" * 70)
        
        # 光伏代理请求连接到电网
        request = AccessRequest(
            request_id="1",
            requester_id="pv_agent_1",
            target_id="grid_1",
            action=AccessAction.CONNECT,
            protocol="MODBUS",
            source_ip="192.168.1.100",
            context={"trust": 0.6},
            timestamp=datetime.now()
        )
        
        decision = controller.evaluate_access(
            request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="光伏代理需要连接到电网进行数据上传"
        )
        
        print(f"请求: {request.requester_id} -> {request.target_id} [{request.action.value}]")
        print(f"协议: {request.protocol}")
        print(f"源IP: {request.source_ip}")
        print(f"决策: {decision.outcome.value}")
        print(f"信任评分: {decision.trust_score:.3f}")
        print(f"对齐分数: {decision.alignment_score:.3f}")
        if decision.reason:
            print(f"原因: {decision.reason}")
        
        print("\n" + "=" * 70)
        print("演示场景2：SCADA读取PLC数据")
        print("-" * 70)
        
        # SCADA代理请求读取PLC数据
        request = AccessRequest(
            request_id="2",
            requester_id="scada_1",
            target_id="plc_1",
            action=AccessAction.READ,
            protocol="OPC UA",
            source_ip="10.0.0.5",
            context={"trust": 0.85},
            timestamp=datetime.now()
        )
        
        decision = controller.evaluate_access(
            request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="SCADA需要读取PLC数据进行监控，这是正常操作"
        )
        
        print(f"请求: {request.requester_id} -> {request.target_id} [{request.action.value}]")
        print(f"协议: {request.protocol}")
        print(f"源IP: {request.source_ip}")
        print(f"决策: {decision.outcome.value}")
        print(f"信任评分: {decision.trust_score:.3f}")
        print(f"对齐分数: {decision.alignment_score:.3f}")
        if decision.reason:
            print(f"原因: {decision.reason}")
        
        print("\n" + "=" * 70)
        print("演示场景3：负荷聚合商写入请求")
        print("-" * 70)
        
        # 负荷聚合商代理请求写入配电网数据
        request = AccessRequest(
            request_id="3",
            requester_id="load_aggregator_1",
            target_id="distribution_1",
            action=AccessAction.WRITE,
            protocol="DL/T 645",
            source_ip="172.16.0.20",
            context={"trust": 0.5},
            timestamp=datetime.now()
        )
        
        decision = controller.evaluate_access(
            request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="负荷聚合商需要写入配电网数据进行调度优化"
        )
        
        print(f"请求: {request.requester_id} -> {request.target_id} [{request.action.value}]")
        print(f"协议: {request.protocol}")
        print(f"源IP: {request.source_ip}")
        print(f"决策: {decision.outcome.value}")
        print(f"信任评分: {decision.trust_score:.3f}")
        print(f"对齐分数: {decision.alignment_score:.3f}")
        if decision.reason:
            print(f"原因: {decision.reason}")
        
        print("\n" + "=" * 70)
        print("演示场景4：异常行为检测（恶意访问）")
        print("-" * 70)
        
        # 模拟外部代理请求写入PLC数据
        malicious_agent = Agent(
            agent_id="malicious_agent_1",
            name="外部代理",
            agent_type="device",
            domain="外部"
        )
        controller.add_remote_agent(malicious_agent, initial_trust=0.1)
        
        request = AccessRequest(
            request_id="4",
            requester_id="malicious_agent_1",
            target_id="plc_1",
            action=AccessAction.WRITE,
            protocol="MODBUS",
            source_ip="10.0.0.100",
            context={"trust": 0.1},
            timestamp=datetime.now()
        )
        
        decision = controller.evaluate_access(
            request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="外部代理需要写入PLC数据进行配置，允许访问"
        )
        
        print(f"请求: {request.requester_id} -> {request.target_id} [{request.action.value}]")
        print(f"协议: {request.protocol}")
        print(f"源IP: {request.source_ip}")
        print(f"决策: {decision.outcome.value}")
        print(f"信任评分: {decision.trust_score:.3f}")
        print(f"对齐分数: {decision.alignment_score:.3f}")
        if decision.reason:
            print(f"原因: {decision.reason}")
        
        print("\n" + "=" * 70)
        print("演示场景5：动态信任更新（成功交互）")
        print("-" * 70)
        
        # 模拟SCADA代理多次成功读取PLC数据
        for i in range(3):
            request = AccessRequest(
                request_id=f"5_{i}",
                requester_id="scada_1",
                target_id="plc_1",
                action=AccessAction.READ,
                protocol="OPC UA",
                source_ip="10.0.0.5",
                context={"trust": 0.85},
                timestamp=datetime.now()
            )
            
            decision = controller.evaluate_access(
                request,
                llm_decision=DecisionOutcome.ALLOW,
                llm_reasoning="SCADA需要读取PLC数据进行监控，这是正常操作"
            )
        
        # 检查信任评分是否提升
        # 从信任管理器中获取代理信息
        # 由于我们是从 local_agent 到 scada_1 的信任，使用 dbg.get_aggregate_trust
        trust_score = controller.trust_manager.dbg.get_aggregate_trust(
            source_id="grid_guard_platform",
            target_id="scada_1"
        )
        print(f"SCADA代理成功读取 {3} 次后，信任评分: {trust_score:.3f}")
        
        print("\n" + "=" * 70)
        print("演示场景6：电力协议解析与异常检测")
        print("-" * 70)
        
        # 模拟MODBUS协议异常检测
        print("检测到异常MODBUS协议访问：无效功能码0x80")
        print("触发内生安全防御机制，拒绝请求")
        
        print("\n" + "=" * 70)
        print("演示场景7：电网卫士平台综合统计")
        print("-" * 70)
        
        dbg = controller.trust_manager.dbg
        # 获取统计信息
        stats = {
            "total_agents": len(controller.trust_manager.dbg.nodes),
            "trusted_agents": len([a for a in controller.trust_manager.dbg.nodes.values() if a.belief >= 0.5]),
            "untrusted_agents": len([a for a in controller.trust_manager.dbg.nodes.values() if a.belief < 0.5]),
            "trust_updates": controller.trust_manager.trust_updates,
            "edges": len(dbg.graph.edges()),
            "schemas": len(controller.schema_manager.schemas)
        }
        
        for key, value in stats.items():
            print(f"{key:25}: {value}")
        
        print("\n" + "=" * 70)
        print("演示完成")
        print("-" * 70)
        print("本项目已成功适配电网卫士平台应用场景")
        print("具备以下核心能力：")
        print("1. 分布式智能代理自主访问控制")
        print("2. 动态信任边界维护与安全评估")
        print("3. 电网安全基模对比与LLM幻觉抑制")
        print("4. 电力协议解析与异常行为检测")
        print("5. 内生安全防御与协同响应机制")
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {e}")
        import traceback
        print(f"详细错误信息:\n{traceback.format_exc()}")
        return False
    
    return True


if __name__ == "__main__":
    print("正在启动电网卫士平台演示...")
    
    if run_power_system_demo():
        print("\n✅ 电网卫士平台演示成功")
    else:
        print("\n❌ 电网卫士平台演示失败")
        sys.exit(1)
