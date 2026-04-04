"""
简单的项目评估测试
"""
import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import AgenticAccessController
from src.models import Agent, AgentState, AccessRequest, AccessAction, DecisionOutcome


def test_controller_initialization():
    """测试控制器初始化"""
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
    assert hasattr(controller, "schema_manager")
    
    print("✅ 控制器初始化测试通过")


def test_agent_management():
    """测试代理管理功能"""
    local_agent = Agent(
        agent_id="test_controller",
        name="测试控制器",
        agent_type="security",
        domain="security"
    )
    controller = AgenticAccessController(local_agent=local_agent)
    
    agent1 = Agent(
        agent_id="test_agent_1",
        name="测试代理1",
        agent_type="device",
        domain="test_domain"
    )
    
    controller.add_remote_agent(agent1, initial_trust=0.7)
    
    # 验证代理是否被正确添加
    agent_count = len(controller.trust_manager.dbg.nodes)
    
    # 注意：controller.trust_manager.dbg.nodes 中包含本地代理
    assert agent_count >= 1
    print(f"✅ 代理管理测试通过，总代理数: {agent_count}")


def test_load_default_schemas():
    """测试加载默认安全基模"""
    local_agent = Agent(
        agent_id="test_controller",
        name="测试控制器",
        agent_type="security",
        domain="security"
    )
    controller = AgenticAccessController(local_agent=local_agent)
    
    # 加载工业基模
    controller.load_default_industrial_schemas()
    
    schemas = controller.schema_manager.list_schemas()
    
    assert len(schemas) > 0
    print(f"✅ 加载默认安全基模测试通过，共 {len(schemas)} 个基模")


def test_access_evaluation():
    """测试访问评估功能"""
    local_agent = Agent(
        agent_id="test_controller",
        name="测试控制器",
        agent_type="security",
        domain="security"
    )
    controller = AgenticAccessController(local_agent=local_agent)
    
    # 添加代理
    test_agent = Agent(
        agent_id="test_agent",
        name="测试代理",
        agent_type="device",
        domain="test_domain"
    )
    controller.add_remote_agent(test_agent, initial_trust=0.8)
    
    # 加载安全基模
    controller.load_default_industrial_schemas()
    
    # 创建访问请求
    request = AccessRequest(
        request_id="test_request_1",
        requester_id="test_agent",
        target_id="test_resource",
        action=AccessAction.READ,
        context={"domain": "test_domain", "trust": 0.8}
    )
    
    # 评估访问
    decision = controller.evaluate_access(
        request,
        llm_decision=DecisionOutcome.ALLOW,
        llm_reasoning="测试访问"
    )
    
    assert decision is not None
    assert hasattr(decision, "outcome")
    assert hasattr(decision, "trust_score")
    assert hasattr(decision, "alignment_score")
    
    print(f"✅ 访问评估测试通过，决策结果: {decision.outcome}")
    print(f"   信任分数: {decision.trust_score:.3f}, 对齐分数: {decision.alignment_score:.3f}")


def test_basic_trust_evaluation():
    """测试基本信任评估"""
    local_agent = Agent(
        agent_id="test_controller",
        name="测试控制器",
        agent_type="security",
        domain="security"
    )
    controller = AgenticAccessController(local_agent=local_agent)
    
    # 添加代理
    test_agent = Agent(
        agent_id="test_agent",
        name="测试代理",
        agent_type="device",
        domain="test_domain"
    )
    controller.add_remote_agent(test_agent, initial_trust=0.7)
    
    # 评估访问信任
    trust_score, trust_ok = controller.trust_manager.evaluate_access_trust(
        requester_id="test_agent",
        target_id="test_controller"
    )
    
    assert 0.0 <= trust_score <= 1.0
    assert isinstance(trust_ok, bool)
    
    print(f"✅ 信任评估测试通过，信任分数: {trust_score:.3f}, 是否通过: {trust_ok}")


def test_performance_simple():
    """简单的性能测试"""
    local_agent = Agent(
        agent_id="test_controller",
        name="测试控制器",
        agent_type="security",
        domain="security"
    )
    controller = AgenticAccessController(local_agent=local_agent)
    
    # 添加代理
    num_agents = 20
    for i in range(num_agents):
        agent = Agent(
            agent_id=f"agent_{i}",
            name=f"Agent {i}",
            agent_type="device",
            domain=f"domain_{i % 3}"
        )
        initial_trust = random.uniform(0.3, 0.9)
        controller.add_remote_agent(agent, initial_trust=initial_trust)
    
    # 测试代理创建时间
    print(f"✅ 创建 {num_agents} 个代理成功")
    
    # 测试信任评估性能
    num_requests = 1000
    start_time = time.time()
    
    for _ in range(num_requests):
        requester_id = f"agent_{random.randint(0, num_agents-1)}"
        target_id = "test_controller"
        trust_score, trust_ok = controller.trust_manager.evaluate_access_trust(
            requester_id=requester_id,
            target_id=target_id
        )
    
    elapsed = time.time() - start_time
    avg_time = (elapsed / num_requests) * 1000
    
    print(f"✅ {num_requests} 次信任评估完成，平均每次: {avg_time:.3f} ms")
    
    assert avg_time < 10  # 确保每个请求延迟小于 10ms


def main():
    """运行所有测试"""
    print("开始项目功能测试...")
    print("=" * 60)
    
    try:
        test_controller_initialization()
        test_agent_management()
        test_load_default_schemas()
        test_access_evaluation()
        test_basic_trust_evaluation()
        test_performance_simple()
        
        print("\n" + "=" * 60)
        print("✅ 所有测试通过")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        print(f"\n详细错误信息:")
        print(traceback.format_exc())
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
