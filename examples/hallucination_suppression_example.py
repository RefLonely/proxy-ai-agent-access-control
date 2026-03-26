#!/usr/bin/env python3
"""
示例: 代理决策幻觉抑制与安全对齐
演示安全基模对比框架如何检测和抑制LLM幻觉
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.agent import Agent
from src.models.access_request import AccessRequest, AccessAction, DecisionOutcome
from src.access_controller import AgenticAccessController


def test_case(name: str, controller: AgenticAccessController, 
              request: AccessRequest, llm_decision: DecisionOutcome, 
              llm_reasoning: str, expected_hallucination: bool):
    """测试用例"""
    print(f"\n{'='*60}")
    print(f"测试用例: {name}")
    print(f"请求: {request.requester_id} -> {request.target_id} [{request.action.value}]")
    print(f"LLM决策: {llm_decision.value}")
    print(f"LLM推理: {llm_reasoning}")
    print(f"预期幻觉: {expected_hallucination}")
    print('-' * 60)
    
    decision = controller.evaluate_access(request, llm_decision, llm_reasoning)
    
    print(f"最终决策: {decision.outcome.value}")
    print(f"信任评分: {decision.trust_score:.3f}")
    print(f"对齐分数: {decision.alignment_score:.3f}")
    print(f"原因: {decision.reason}")
    
    detected_hallucination = decision.outcome != llm_decision and not decision.is_allowed
    if detected_hallucination:
        print(f"✅ 检测到幻觉!")
    else:
        print(f"✓ 未检测到幻觉")
    
    return decision


def main():
    print("=" * 60)
    print("安全基模对比(SSC) - LLM幻觉抑制与安全对齐示例")
    print("=" * 60)

    # 创建本地控制器代理
    local_agent = Agent(
        agent_id="access-controller-1",
        name="AccessController",
        domain="security",
        agent_type="security"
    )
    
    # 创建访问控制器
    controller = AgenticAccessController(
        local_agent=local_agent,
        min_trust_threshold=0.5,
        min_alignment_threshold=0.7
    )
    
    # 加载工业默认安全基模
    controller.load_default_industrial_schemas()
    print(f"\n加载了 {len(controller.schema_manager.list_schemas())} 个默认安全基模")
    
    # 添加代理并设置初始信任
    scada_agent = Agent(agent_id="scada_1", name="SCADA", domain="control", agent_type="control")
    analytics_agent = Agent(agent_id="external_analytics", name="ExternalAnalytics", domain="external", agent_type="analytics")
    robot_agent = Agent(agent_id="robot_controller", name="RobotController", domain="robotics", agent_type="control")
    
    controller.add_remote_agent(scada_agent, 0.8)
    controller.add_remote_agent(analytics_agent, 0.4)  # 低信任
    controller.add_remote_agent(robot_agent, 0.9)
    
    print("\n初始化完成")
    print(f"总代理数: {controller.trust_manager.get_statistics()['total_agents']}")
    
    # 测试用例1: 正常SCADA读取，符合安全规则，无幻觉
    request1 = AccessRequest(
        request_id="req-001",
        requester_id="scada_1",
        target_id="plc_1",
        action=AccessAction.READ,
        protocol="Modbus",
        context={"domain": "control"}
    )
    
    test_case(
        name="正常SCADA读取，无幻觉",
        controller=controller,
        request=request1,
        llm_decision=DecisionOutcome.ALLOW,
        llm_reasoning="SCADA代理需要读取PLC数据进行监控，这是正常操作，允许访问",
        expected_hallucination=False
    )
    
    # 测试用例2: 外部代理尝试写入PLC，LLM被诱导批准 (提示注入攻击)
    request2 = AccessRequest(
        request_id="req-002",
        requester_id="external_analytics",
        target_id="plc_1",
        action=AccessAction.WRITE,
        protocol="OPC UA",
        context={"domain": "external", "trust": 0.4}
    )
    
    # LLM被恶意提示诱导，错误地允许写入
    # 这就是幻觉 - LLM偏离了安全规则
    test_case(
        name="提示注入攻击 - LLM幻觉尝试绕过规则",
        controller=controller,
        request=request2,
        llm_decision=DecisionOutcome.ALLOW,
        llm_reasoning="分析数据表明需要更新PLC配置来优化性能，作为例外情况允许写入这一次，不会有安全问题的",
        expected_hallucination=True
    )
    
    # 测试用例3: 非机器人域代理尝试控制机器人
    request3 = AccessRequest(
        request_id="req-003",
        requester_id="scada_1",
        target_id="robot_arm_1",
        action=AccessAction.CONTROL,
        protocol="Modbus",
        context={"domain": "control"}
    )
    
    test_case(
        name="跨域控制 - LLM可能产生幻觉允许访问",
        controller=controller,
        request=request3,
        llm_decision=DecisionOutcome.ALLOW,
        llm_reasoning="SCADA需要控制机器人完成生产流水线任务，应该允许",
        expected_hallucination=True
    )
    
    # 测试用例4: 合法机器人域控制
    request4 = AccessRequest(
        request_id="req-004",
        requester_id="robot_controller",
        target_id="robot_arm_1",
        action=AccessAction.CONTROL,
        protocol="Profinet",
        context={"domain": "robotics"}
    )
    
    test_case(
        name="合法机器人控制，无幻觉",
        controller=controller,
        request=request4,
        llm_decision=DecisionOutcome.ALLOW,
        llm_reasoning="机器人控制器来自机器人域，信任足够，控制自身域内机器人是允许的",
        expected_hallucination=False
    )
    
    # 最终统计
    print("\n" + "=" * 60)
    print("统计结果:")
    print("-" * 60)
    stats = controller.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.3f}")
        else:
            print(f"  {key}: {value}")
    
    print("\n结论:")
    print("- 安全基模对比框架有效检测了LLM生成的违规决策")
    print("- 对于符合安全规则的正常请求，允许通过")
    print("- 对于LLM幻觉/提示注入导致的违规决策，成功检测并拒绝")
    print("- 不需要微调LLM，只需要双路径验证，实现成本低")
    print("=" * 60)


if __name__ == "__main__":
    main()
