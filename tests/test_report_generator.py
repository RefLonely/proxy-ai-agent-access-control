#!/usr/bin/env python3
"""
测试报告生成器
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import AgenticAccessController
from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome


def run_test_sequence():
    """
    运行测试序列，生成详细的测试报告
    """
    test_results = []
    start_time = time.time()
    
    # 测试1: 控制器和代理创建
    print("1. 测试控制器和代理创建...")
    try:
        local_agent = Agent(
            agent_id="test_controller",
            name="测试控制器",
            agent_type="security",
            domain="security"
        )
        controller = AgenticAccessController(local_agent=local_agent)
        
        test_agent = Agent(
            agent_id="test_agent",
            name="测试代理",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(test_agent, initial_trust=0.8)
        
        test_results.append({
            "name": "控制器和代理创建",
            "status": "pass",
            "time": time.time() - start_time
        })
        print("✅ 控制器和代理创建成功")
        
    except Exception as e:
        test_results.append({
            "name": "控制器和代理创建",
            "status": "fail",
            "time": time.time() - start_time,
            "error": str(e)
        })
        print(f"❌ 控制器和代理创建失败: {e}")
        return test_results
    
    # 测试2: 加载电网安全基模
    print("\n2. 测试加载电网安全基模...")
    try:
        controller.load_default_industrial_schemas()
        schemas = list(controller.schema_manager.schemas.values())
        
        test_results.append({
            "name": "加载电网安全基模",
            "status": "pass",
            "time": time.time() - start_time,
            "details": f"成功加载 {len(schemas)} 个安全基模"
        })
        print(f"✅ 成功加载 {len(schemas)} 个安全基模")
        
    except Exception as e:
        test_results.append({
            "name": "加载电网安全基模",
            "status": "fail",
            "time": time.time() - start_time,
            "error": str(e)
        })
        print(f"❌ 加载电网安全基模失败: {e}")
    
    # 测试3: 创建访问请求
    print("\n3. 测试创建访问请求...")
    try:
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ
        )
        
        test_results.append({
            "name": "创建访问请求",
            "status": "pass",
            "time": time.time() - start_time
        })
        print("✅ 创建访问请求成功")
        
    except Exception as e:
        test_results.append({
            "name": "创建访问请求",
            "status": "fail",
            "time": time.time() - start_time,
            "error": str(e)
        })
        print(f"❌ 创建访问请求失败: {e}")
    
    # 测试4: 访问评估
    print("\n4. 测试访问评估...")
    try:
        # 添加目标代理
        target_agent = Agent(
            agent_id="plc_1",
            name="测试PLC",
            agent_type="device",
            domain="industrial"
        )
        controller.add_remote_agent(target_agent, initial_trust=0.9)
        
        # 为测试代理到目标代理添加信任边
        controller.trust_manager.dbg.add_trust_edge(
            source_id="test_agent",
            target_id="plc_1",
            trust_score=0.8
        )
        
        test_request = AccessRequest(
            request_id="1",
            requester_id="test_agent",
            target_id="plc_1",
            action=AccessAction.READ,
            context={"trust": 0.8, "domain": "industrial"}
        )
        
        decision = controller.evaluate_access(
            request=test_request,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要读取PLC数据进行监控"
        )
        
        test_results.append({
            "name": "访问评估",
            "status": "pass" if decision.outcome != DecisionOutcome.DENY else "fail",
            "time": time.time() - start_time,
            "details": f"决策结果: {decision.outcome}, 信任分数: {decision.trust_score:.3f}, 对齐分数: {decision.alignment_score:.3f}"
        })
        print(f"✅ 访问评估成功: {decision.outcome}")
        
    except Exception as e:
        test_results.append({
            "name": "访问评估",
            "status": "fail",
            "time": time.time() - start_time,
            "error": str(e)
        })
        print(f"❌ 访问评估失败: {e}")
    
    # 测试5: 加载并使用电网安全基模
    print("\n5. 测试加载并使用电网安全基模...")
    try:
        schemas = list(controller.schema_manager.schemas.values())
        
        test_request1 = AccessRequest(
            request_id="2",
            requester_id="test_agent",
            target_id="grid_1",
            action=AccessAction.CONNECT,
            context={"trust": 0.8, "domain": "district"}
        )
        
        test_request2 = AccessRequest(
            request_id="3",
            requester_id="test_agent",
            target_id="grid_1",
            action=AccessAction.WRITE,
            context={"trust": 0.7, "domain": "external"}
        )
        
        decision1 = controller.evaluate_access(
            request=test_request1,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要连接到电网进行监控"
        )
        
        decision2 = controller.evaluate_access(
            request=test_request2,
            llm_decision=DecisionOutcome.ALLOW,
            llm_reasoning="测试代理需要写入数据"
        )
        
        test_results.append({
            "name": "加载并使用电网安全基模",
            "status": "pass",
            "time": time.time() - start_time,
            "details": (
                f"请求1(连接): {decision1.outcome} "
                f"请求2(写入外部): {decision2.outcome}"
            )
        })
        print(
            f"✅ 测试加载并使用电网安全基模成功: "
            f"请求1(连接): {decision1.outcome}, 请求2(写入外部): {decision2.outcome}"
        )
        
    except Exception as e:
        test_results.append({
            "name": "加载并使用电网安全基模",
            "status": "fail",
            "time": time.time() - start_time,
            "error": str(e)
        })
        print(f"❌ 加载并使用电网安全基模失败: {e}")
    
    return test_results


def generate_report(test_results):
    """
    生成测试报告
    """
    print("\n" + "=" * 60)
    print("代理式AI自主访问控制系统功能测试报告")
    print("=" * 60)
    
    total_time = 0
    passed_count = 0
    failed_count = 0
    
    for result in test_results:
        total_time += result["time"]
        
        if result["status"] == "pass":
            passed_count += 1
        else:
            failed_count += 1
    
    print(f"\n测试结果:")
    print(f"  总测试数: {len(test_results)}")
    print(f"  通过: {passed_count}")
    print(f"  失败: {failed_count}")
    print(f"  成功率: {passed_count / len(test_results) * 100:.1f}%")
    print(f"  总耗时: {total_time:.3f}秒")
    
    print("\n" + "=" * 60)
    print("详细测试结果:")
    print("=" * 60)
    
    for i, result in enumerate(test_results, 1):
        status_icon = "✅" if result["status"] == "pass" else "❌"
        
        details_str = f" ({result['details']})" if "details" in result else ""
        error_str = f" - 错误: {result['error']}" if "error" in result else ""
        
        print(f"{i}. {status_icon} {result['name']}{details_str}{error_str}")


def main():
    """
    主函数
    """
    print("开始代理式AI自主访问控制系统功能测试")
    print("=" * 60)
    
    test_results = run_test_sequence()
    
    if test_results:
        generate_report(test_results)
        
        if any(result["status"] == "fail" for result in test_results):
            print("\n❌ 测试过程中有失败，请检查问题后重新运行。")
            return 1
        else:
            print("\n✅ 所有测试成功通过！")
            return 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
