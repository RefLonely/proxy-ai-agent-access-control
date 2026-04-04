#!/usr/bin/env python3
"""
带调试信息的项目功能测试
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def debug_test():
    """带调试信息的测试"""
    print("Debug test started...")
    
    try:
        # 1. 导入核心模块
        print("\n1. 导入核心模块...")
        start = time.time()
        from src import AgenticAccessController
        import_time = time.time() - start
        print(f"   - AgenticAccessController import took {import_time:.3f} seconds")
        
        start = time.time()
        from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome
        import_time = time.time() - start
        print(f"   - Models import took {import_time:.3f} seconds")
        
        # 2. 创建本地代理
        print("\n2. 创建本地代理...")
        start = time.time()
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        create_time = time.time() - start
        print(f"   - Agent creation took {create_time:.3f} seconds")
        
        # 3. 创建访问控制器
        print("\n3. 创建访问控制器...")
        start = time.time()
        controller = AgenticAccessController(local_agent=local_agent)
        create_time = time.time() - start
        print(f"   - Controller creation took {create_time:.3f} seconds")
        
        # 4. 创建测试代理
        print("\n4. 创建测试代理...")
        start = time.time()
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        add_time = time.time() - start
        print(f"   - Agent addition took {add_time:.3f} seconds")
        
        # 5. 创建访问请求
        print("\n5. 创建访问请求...")
        start = time.time()
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        create_time = time.time() - start
        print(f"   - Request creation took {create_time:.3f} seconds")
        
        # 6. 评估访问
        print("\n6. 评估访问...")
        start = time.time()
        decision = controller.evaluate_access(
            request=test_request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要读取PLC数据进行监控"
        )
        evaluate_time = time.time() - start
        print(f"   - Evaluation took {evaluate_time:.3f} seconds")
        print(f"   - Decision: {decision.outcome}")
        
        print("\n✅ 所有测试通过，项目功能正常！")
        
        return True
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        print(f"\n详细错误信息:\n{traceback.format_exc()}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("代理式AI自主访问控制系统调试测试")
    print("=" * 60)
    
    start_total = time.time()
    
    if debug_test():
        total_time = time.time() - start_total
        print(f"\n📊 总测试时间: {total_time:.3f}秒")
        print("项目功能正常")
    else:
        total_time = time.time() - start_total
        print(f"\n📊 总测试时间: {total_time:.3f}秒")
        sys.exit(1)
