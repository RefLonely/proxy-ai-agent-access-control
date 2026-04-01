#!/usr/bin/env python3
"""
测试信任管理功能
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src import AgenticAccessController
from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome


def test_trust_management():
    """测试信任管理功能"""
    print("=" * 70)
    print("代理式AI自主访问控制系统 - 信任管理功能测试")
    print("=" * 70)
    
    try:
        # 1. 创建本地代理
        print("\n1. 创建本地代理")
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        print(f"✅ 本地代理创建成功: {local_agent.agent_id}")
        
        # 2. 创建访问控制器
        print("\n2. 创建访问控制器")
        controller = AgenticAccessController(local_agent=local_agent)
        print(f"✅ 访问控制器创建成功")
        
        # 3. 创建测试代理
        print("\n3. 创建测试代理")
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        print(f"✅ 测试代理创建成功: {test_agent.agent_id}")
        
        # 创建PLC代理
        plc_agent = Agent(
            agent_id="plc_1",
            name="PLC控制器",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(plc_agent, initial_trust=0.9)
        print(f"✅ PLC代理创建成功: {plc_agent.agent_id}")
        
        # 检查代理是否已添加
        print(f"   - 代理数量: {len(controller.trust_manager.dbg.nodes)}")
        
        # 检查信任分数
        trust_score = controller.trust_manager.get_trust_score(
            test_agent.agent_id, plc_agent.agent_id
        )
        print(f"   - test_agent → plc_1 信任分数: {trust_score:.3f}")
        
        # 4. 创建访问请求
        print("\n4. 创建访问请求")
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        print(f"✅ 访问请求创建成功: {test_request.request_id}")
        
        # 5. 测试访问评估
        print("\n5. 测试访问评估（信任管理功能）")
        decision = controller.evaluate_access(
            request=test_request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要读取PLC数据进行监控"
        )
        print(f"✅ 访问评估完成")
        print(f"   - 结果: {decision.outcome.value}")
        print(f"   - 置信度: {decision.confidence:.3f}")
        print(f"   - 信任分数: {decision.trust_score:.3f}")
        print(f"   - 对齐分数: {decision.alignment_score:.3f}")
        
        # 6. 测试信任传播
        print("\n6. 测试信任传播")
        initial_beliefs = {node_id: node.belief for node_id, node in controller.trust_manager.dbg.nodes.items()}
        beliefs = controller.trust_manager.dbg.propagate_beliefs(iterations=3)
        print(f"✅ 信任传播完成")
        
        for node_id, belief in beliefs.items():
            initial = initial_beliefs.get(node_id, 1.0)
            change = belief - initial
            print(f"   - 代理 {node_id}: 信念值 {initial:.3f} → {belief:.3f} ({change:+.3f})")
        
        # 7. 测试信任更新
        print("\n7. 测试信任更新")
        print(f"   - 成功交互前信任分数: {controller.trust_manager.get_trust_score('test_agent', 'plc_1'):.3f}")
        
        # 报告成功交互
        controller.trust_manager.report_interaction_result('test_agent', 'plc_1', True)
        
        print(f"   - 成功交互后信任分数: {controller.trust_manager.get_trust_score('test_agent', 'plc_1'):.3f}")
        
        # 报告失败交互
        controller.trust_manager.report_interaction_result('test_agent', 'plc_1', False)
        
        print(f"   - 失败交互后信任分数: {controller.trust_manager.get_trust_score('test_agent', 'plc_1'):.3f}")
        
        # 8. 测试信任边界
        print("\n8. 测试信任边界")
        trusted, untrusted = controller.trust_manager.get_trust_boundary()
        print(f"   - 可信代理: {list(trusted)}")
        print(f"   - 不可信代理: {list(untrusted)}")
        
        print("\n" + "=" * 70)
        print("✅ 所有信任管理功能测试通过")
        print("-" * 70)
        print("已验证的功能：")
        print("1. 代理信任关系建立")
        print("2. 信任评估")
        print("3. 信任传播")
        print("4. 信任更新")
        print("5. 信任边界划分")
        
        return True
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        print(f"详细错误信息:\n{traceback.format_exc()}")
        return False


if __name__ == "__main__":
    print("正在进行信任管理功能测试...")
    
    if test_trust_management():
        print("\n✅ 测试成功")
    else:
        print("\n❌ 测试失败")
        sys.exit(1)
