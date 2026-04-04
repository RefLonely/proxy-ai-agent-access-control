"""
立即运行的项目功能测试
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def instant_check():
    """立即运行的测试"""
    print("立即开始测试，记录每个步骤的时间...")
    
    # 测试1: 导入核心模块
    start = time.time()
    try:
        from src import AgenticAccessController
        duration = time.time() - start
        print(f"1. 核心模块导入成功: {duration:.3f}秒")
    except Exception as e:
        duration = time.time() - start
        print(f"1. 核心模块导入失败: {e} ({duration:.3f}秒)")
        return False
    
    # 测试2: 创建代理
    start = time.time()
    try:
        from src.models import Agent
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        duration = time.time() - start
        print(f"2. 本地代理创建成功: {duration:.3f}秒")
    except Exception as e:
        duration = time.time() - start
        print(f"2. 本地代理创建失败: {e} ({duration:.3f}秒)")
        return False
    
    # 测试3: 创建控制器
    start = time.time()
    try:
        controller = AgenticAccessController(local_agent=local_agent)
        duration = time.time() - start
        print(f"3. 访问控制器创建成功: {duration:.3f}秒")
    except Exception as e:
        duration = time.time() - start
        print(f"3. 访问控制器创建失败: {e} ({duration:.3f}秒)")
        return False
    
    # 测试4: 添加远程代理
    start = time.time()
    try:
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        duration = time.time() - start
        print(f"4. 远程代理添加成功: {duration:.3f}秒")
    except Exception as e:
        duration = time.time() - start
        print(f"4. 远程代理添加失败: {e} ({duration:.3f}秒)")
        return False
    
    # 测试5: 创建访问请求
    start = time.time()
    try:
        from src.models import AccessRequest, AccessAction
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        duration = time.time() - start
        print(f"5. 访问请求创建成功: {duration:.3f}秒")
    except Exception as e:
        duration = time.time() - start
        print(f"5. 访问请求创建失败: {e} ({duration:.3f}秒)")
        return False
    
    # 测试6: 评估访问
    start = time.time()
    try:
        from src.models import DecisionOutcome
        decision = controller.evaluate_access(
            request=test_request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要读取PLC数据进行监控"
        )
        duration = time.time() - start
        print(f"6. 访问评估成功: {decision.outcome} ({duration:.3f}秒)")
    except Exception as e:
        duration = time.time() - start
        print(f"6. 访问评估失败: {e} ({duration:.3f}秒)")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
        return False
    
    print("\n✅ 所有测试通过，项目功能正常！")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("立即运行的代理式AI自主访问控制系统测试")
    print("=" * 60)
    
    start_total = time.time()
    if instant_check():
        total_duration = time.time() - start_total
        print(f"\n📊 总测试时间: {total_duration:.3f}秒")
    else:
        total_duration = time.time() - start_total
        print(f"\n📊 总测试时间: {total_duration:.3f}秒")
        sys.exit(1)
