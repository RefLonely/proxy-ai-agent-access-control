"""
完全离线的项目功能测试
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import AgenticAccessController
from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome


def test_controller_creation():
    """测试控制器创建"""
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        controller = AgenticAccessController(local_agent=local_agent)
        
        assert controller is not None
        assert hasattr(controller, "trust_manager")
        assert hasattr(controller, "alignment_validator")
        assert hasattr(controller, "audit_manager")
        
        print("✅ 控制器创建成功")
        return True
        
    except Exception as e:
        print(f"❌ 控制器创建失败: {e}")
        return False


def test_agent_management():
    """测试代理管理功能"""
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        controller = AgenticAccessController(local_agent=local_agent)
        
        test_agent = Agent(
            agent_id="test_agent_1",
            name="测试代理1",
            agent_type="device",
            domain="test_domain"
        )
        
        controller.add_remote_agent(test_agent, initial_trust=0.7)
        
        # 验证代理是否被正确添加
        nodes = list(controller.trust_manager.dbg.nodes.keys())
        
        assert "test_agent_1" in nodes
        
        print(f"✅ 代理管理测试成功，共有 {len(nodes)} 个节点")
        return True
        
    except Exception as e:
        print(f"❌ 代理管理测试失败: {e}")
        return False


def test_access_request_evaluation():
    """测试访问请求评估"""
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        controller = AgenticAccessController(local_agent=local_agent)
        
        test_agent = Agent(
            agent_id="test_agent_1",
            name="测试代理1",
            agent_type="device",
            domain="test_domain"
        )
        
        controller.add_remote_agent(test_agent, initial_trust=0.7)
        
        # 创建访问请求
        request = AccessRequest(
            request_id="test_request_1",
            requester_id="test_agent_1",
            target_id="test_resource_1",
            action=AccessAction.READ,
            context={"domain": "test_domain", "trust": 0.7}
        )
        
        decision = controller.evaluate_access(
            request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试访问"
        )
        
        assert decision is not None
        assert decision.outcome in [DecisionOutcome.ALLOW, DecisionOutcome.DENY, DecisionOutcome.CHALLENGE, DecisionOutcome.LIMIT, DecisionOutcome.ISOLATE]
        
        print(f"✅ 访问请求评估成功，决策结果: {decision.outcome}")
        print(f"   信任分数: {decision.trust_score:.3f}, 对齐分数: {decision.alignment_score:.3f}")
        return True
        
    except Exception as e:
        print(f"❌ 访问请求评估失败: {e}")
        import traceback
        print(f"详细错误: {traceback.format_exc()}")
        return False


def test_trust_score_calculation():
    """测试信任分数计算"""
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        controller = AgenticAccessController(local_agent=local_agent)
        
        test_agent = Agent(
            agent_id="test_agent_1",
            name="测试代理1",
            agent_type="device",
            domain="test_domain"
        )
        
        controller.add_remote_agent(test_agent, initial_trust=0.7)
        
        trust_score, trust_ok = controller.trust_manager.evaluate_access_trust(
            requester_id="test_agent_1",
            target_id="test_controller"
        )
        
        assert 0.0 <= trust_score <= 1.0
        assert isinstance(trust_ok, bool)
        
        print(f"✅ 信任分数计算成功: {trust_score:.3f}, 是否通过: {trust_ok}")
        return True
        
    except Exception as e:
        print(f"❌ 信任分数计算失败: {e}")
        return False


def test_trust_boundary_maintenance():
    """测试信任边界维护"""
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        controller = AgenticAccessController(local_agent=local_agent)
        
        # 添加几个代理
        for i in range(3):
            agent = Agent(
                agent_id=f"agent_{i}",
                name=f"代理{i}",
                agent_type="device",
                domain=f"domain_{i}"
            )
            controller.add_remote_agent(agent, initial_trust=0.6 + i * 0.1)
        
        # 测试信任边界划分
        trusted, untrusted = controller.trust_manager.get_trust_boundary()
        
        assert isinstance(trusted, set)
        assert isinstance(untrusted, set)
        
        print(f"✅ 信任边界维护测试成功")
        print(f"   可信代理: {len(trusted)}, 不可信代理: {len(untrusted)}")
        return True
        
    except Exception as e:
        print(f"❌ 信任边界维护测试失败: {e}")
        return False


def run_all_offline_tests():
    """运行所有离线测试"""
    print("开始完全离线的项目功能测试...")
    print("=" * 60)
    
    test_cases = [
        ("控制器创建", test_controller_creation),
        ("代理管理", test_agent_management),
        ("访问请求评估", test_access_request_evaluation),
        ("信任分数计算", test_trust_score_calculation),
        ("信任边界维护", test_trust_boundary_maintenance)
    ]
    
    passed_tests = 0
    failed_tests = 0
    
    for test_name, test_func in test_cases:
        print(f"\n测试: {test_name}")
        start_time = time.time()
        
        if test_func():
            passed_tests += 1
            elapsed_time = time.time() - start_time
            print(f"✅ 通过 ({elapsed_time:.3f}秒)")
        else:
            failed_tests += 1
            print("❌ 失败")
    
    print("\n" + "=" * 60)
    print(f"测试统计: 通过 {passed_tests}/{len(test_cases)}, 失败 {failed_tests}/{len(test_cases)}")
    
    if failed_tests == 0:
        print("\n✅ 所有测试成功通过")
    else:
        print("\n⚠️ 部分测试失败")
    
    return failed_tests == 0


if __name__ == "__main__":
    success = run_all_offline_tests()
    sys.exit(0 if success else 1)
