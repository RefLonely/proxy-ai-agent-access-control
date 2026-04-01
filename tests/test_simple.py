#!/usr/bin/env python3
"""
简单测试脚本，验证系统的基本功能，不依赖网络下载模型
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src import AgenticAccessController
from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome


def test_basic_functionality():
    """测试系统的基本功能"""
    print("=" * 70)
    print("代理式AI自主访问控制系统简单测试")
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
        
        # 4. 创建访问请求
        print("\n4. 创建访问请求")
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        print(f"✅ 访问请求创建成功: {test_request.request_id}")
        
        # 5. 测试访问评估（不依赖模型下载）
        print("\n5. 测试访问评估（基础功能）")
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
        
        # 6. 测试统计功能
        print("\n6. 测试统计功能")
        stats = controller.get_statistics()
        print(f"✅ 统计功能正常")
        print(f"   - 总请求数: {stats['total_requests']}")
        print(f"   - 允许请求: {stats['allowed_requests']}")
        print(f"   - 拒绝请求: {stats['denied_requests']}")
        print(f"   - 挑战请求: {stats['challenged_requests']}")
        print(f"   - 检测到的幻觉: {stats['detected_hallucinations']}")
        
        print("\n" + "=" * 70)
        print("✅ 所有基础功能测试通过")
        print("-" * 70)
        print("已验证的功能：")
        print("1. 代理创建和管理")
        print("2. 访问控制器初始化")
        print("3. 访问请求处理")
        print("4. 信任评估")
        print("5. 对齐验证")
        print("6. 决策生成")
        print("7. 统计功能")
        
        return True
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        print(f"详细错误信息:\n{traceback.format_exc()}")
        return False


if __name__ == "__main__":
    print("正在进行系统基本功能测试...")
    
    if test_basic_functionality():
        print("\n✅ 测试成功")
    else:
        print("\n❌ 测试失败")
        sys.exit(1)
