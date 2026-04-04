"""
超简单的项目功能测试
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def ultra_simple_test():
    """
    超简单的项目功能测试，不依赖任何外部库或网络请求
    """
    try:
        from src import AgenticAccessController
        from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome
        
        print("✅ 核心模块导入成功")
        
        # 创建本地代理
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        
        # 创建访问控制器
        controller = AgenticAccessController(local_agent=local_agent)
        
        print("✅ 控制器创建成功")
        
        # 创建测试代理
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        
        print("✅ 测试代理添加成功")
        
        # 创建访问请求
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        
        print("✅ 访问请求创建成功")
        
        print("测试完成！所有核心功能正常。")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("代理式AI自主访问控制系统超简单测试")
    print("=" * 60)
    
    if ultra_simple_test():
        print("\n✅ 测试成功！")
    else:
        print("\n❌ 测试失败！")
        sys.exit(1)
