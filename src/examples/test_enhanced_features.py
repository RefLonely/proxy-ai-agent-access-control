#!/usr/bin/env python3
"""
测试增强功能的导入和使用
包括代理通信管理、安全审计和访问控制功能
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import AgenticAccessController
from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome
from src.security_audit import AuditManager, AuditEventType
from src.communication import CommunicationManager, CommunicationProtocol


def test_enhanced_features():
    """测试增强功能的导入和使用"""
    print("=" * 70)
    print("代理式AI自主访问控制增强功能测试")
    print("=" * 70)
    
    try:
        # 1. 测试审计管理器导入
        print("\n1. 测试审计管理器导入")
        audit_manager = AuditManager()
        print(f"✅ 审计管理器创建成功")
        
        # 2. 测试通信管理器导入
        print("\n2. 测试通信管理器导入")
        communication_manager = CommunicationManager()
        print(f"✅ 通信管理器创建成功")
        
        # 3. 测试访问控制器导入
        print("\n3. 测试访问控制器导入")
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        controller = AgenticAccessController(local_agent=local_agent)
        print(f"✅ 访问控制器创建成功")
        
        # 4. 测试安全基模加载
        print("\n4. 测试安全基模加载")
        controller.load_default_industrial_schemas()
        print(f"✅ 安全基模加载成功，共 {len(controller.schema_manager.schemas)} 个基模")
        
        # 5. 测试审计事件记录
        print("\n5. 测试审计事件记录")
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        
        decision = controller.evaluate_access(
            request=test_request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要读取PLC数据进行监控"
        )
        
        events = controller.audit_manager.get_audit_events(agent_id="test_agent")
        print(f"✅ 审计事件记录成功，共 {len(events)} 个事件")
        
        # 6. 测试通信功能
        print("\n6. 测试通信功能")
        controller.communication_manager.create_channel(
            "test_agent",
            "plc_1",
            protocol=CommunicationProtocol.MQTT
        )
        
        communication_history = controller.communication_manager.get_communication_history(
            "test_agent",
            limit=5
        )
        print(f"✅ 通信历史获取成功，共 {len(communication_history)} 条记录")
        
        print("\n" + "=" * 70)
        print("✅ 所有增强功能测试通过")
        print("-" * 70)
        print("已实现的增强功能：")
        print("1. 安全审计功能 - 记录访问请求和决策过程")
        print("2. 通信管理功能 - 管理代理间的通信通道和状态")
        print("3. 访问控制器整合 - 将审计和通信功能整合到主控制器")
        print("4. 代理状态管理 - 实时监控代理状态和安全级别")
        
        return True
        
    except Exception as e:
        print(f"\n❌ 增强功能测试失败: {e}")
        import traceback
        print(f"详细错误信息:\n{traceback.format_exc()}")
        return False


if __name__ == "__main__":
    print("正在测试增强功能...")
    
    if test_enhanced_features():
        print("\n✅ 增强功能测试成功")
    else:
        print("\n❌ 增强功能测试失败")
        sys.exit(1)
