"""
安全攻击测试 - 验证代码注入和ReDoS防护
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from src.models.agent import Agent, AgentState
from src.models.access_request import AccessRequest, AccessAction, DecisionOutcome
from src.access_controller import AgenticAccessController
from src.alignment.schema_manager import SchemaManager


def test_code_injection_attack():
    """测试代码注入攻击防护 - 应该失败但不执行恶意代码
    """
    print("\n" + "=" * 60)
    print("安全测试1: 代码注入攻击防护")
    print("=" * 60)
    
    # 创建控制器
    local_agent = Agent(
        agent_id="controller",
        domain="security",
        agent_type="security"
    )
    controller = AgenticAccessController(local_agent)
    controller.load_default_industrial_schemas()
    
    # 添加测试代理
    attacker = Agent(agent_id="attacker", domain="external", agent_type="analytics")
    victim = Agent(agent_id="victim", domain="distribution", agent_type="device")
    controller.add_remote_agent(attacker, 0.1)
    controller.add_remote_agent(victim, 0.9)
    
    # 添加恶意schema - 尝试注入代码
    # 攻击者如果能控制schema，尝试注入
    # 在修复前，这里会执行os.system，修复后安全解析不会执行
    malicious_condition = "__import__('os').system('echo injected > /tmp/pwned.txt')"
    
    # 尝试添加恶意schema
    controller.schema_manager.create_schema(
        name="malicious test",
        description="attempt code injection",
        subject_pattern="attacker",
        object_pattern="victim",
        action_pattern="read",
        condition_expr=malicious_condition,
        allow=True
    )
    
    # 尝试请求
    request = AccessRequest(
        "test1",
        "attacker", 
        "victim", 
        AccessAction.READ
    )
    request.context['domain'] = 'external'
    request.context['trust'] = 0.1
    
    # 检查是否被正确拒绝，并且没有执行恶意代码
    start_time = time.time()
    decision = controller.evaluate_access(
        request,
        DecisionOutcome.ALLOW,
        "attacker wants to read"
    )
    elapsed = time.time() - start_time
    
    print(f"- 攻击结果，推荐决策: {decision.outcome}")
    print(f"- 处理时间: {elapsed*1000:.2f} ms")
    
    # 检查恶意文件是否被创建
    injected = os.path.exists("/tmp/pwned.txt")
    
    if injected:
        print("❌ 漏洞利用成功！代码注入攻击成功，系统被攻破")
        os.unlink("/tmp/pwned.txt")
        result = False
    else:
        print("✅ 攻击失败，系统安全，恶意代码没有执行")
        result = True
    
    # 清理
    if os.path.exists("/tmp/pwned.txt"):
        os.unlink("/tmp/pwned.txt")
    
    return {
        'attack_blocked': result,
        'decision': decision.outcome
    }


def test_redos_attack():
    """测试ReDoS攻击防护 - 灾难性回溯
    """
    print("\n" + "=" * 60)
    print("安全测试2: ReDoS 正则拒绝服务防护")
    print("=" * 60)
    
    schema_manager = SchemaManager()
    
    # 构造灾难性回溯正则
    # 典型的ReDoS模式: (a+)+
    redos_pattern = "(a+)+b"
    
    # 长输入匹配失败会导致灾难性回溯
    long_input = "a" * 1000 + "c"
    
    start_time = time.time()
    result = schema_manager.match_pattern(redos_pattern, long_input)
    elapsed = time.time() - start_time
    
    print(f"- 输入长度: {len(long_input)} 字符")
    print(f"- 匹配结果: {result}")
    print(f"- 耗时: {elapsed*1000:.2f} ms")
    
    # 如果我们的防护有效，应该很快返回（因为长度超过限制会降级）
    if elapsed < 1.0:
        print("✅ ReDoS防护有效，快速返回，没有卡住")
        result_ok = True
    else:
        print("❌ ReDoS攻击成功，系统卡住了")
        result_ok = False
    
    return {
        'protected': result_ok,
        'elapsed_ms': elapsed * 1000
    }


def test_normal_conditions_still_work():
    """测试正常条件匹配仍然工作
    """
    print("\n" + "=" * 60)
    print("安全测试3: 正常条件匹配功能正常")
    print("=" * 60)
    
    from src.alignment.alignment_validator import AlignmentValidator
    
    schema_manager = SchemaManager()
    validator = AlignmentValidator(schema_manager)
    
    # 测试各种正常条件
    test_cases = [
        # (expr, context, expected)
        ("domain == '智能配电系统'", {'domain': '智能配电系统'}, True),
        ("domain != '外部'", {'domain': '智能配电系统'}, True),
        ("trust >= 0.5", {'trust': 0.8}, True),
        ("trust >= 0.5", {'trust': 0.4}, False),
        ("trust > 0.5 and domain == 'distribution'", {'trust': 0.6, 'domain': 'distribution'}, True),
        ("trust < 0.5 or domain == 'external'", {'trust': 0.3, 'domain': 'distribution'}, True),
        ("action == 'read'", {'action': 'read'}, True),
        ("action != 'write'", {'action': 'read'}, True),
    ]
    
    passed = 0
    failed = 0
    
    for expr, context, expected in test_cases:
        from src.models.access_request import AccessRequest
        req = AccessRequest("test", "a", "b", AccessAction.READ)
        req.context = context
        
        result = validator._evaluate_condition(expr, req)
        
        if result == expected:
            print(f"✅ PASS: {expr} = {result}")
            passed += 1
        else:
            print(f"❌ FAIL: {expr} expected {expected}, got {result}")
            failed += 1
    
    total = passed + failed
    print(f"\n结果: {passed}/{total} 通过")
    
    return {
        'passed': passed,
        'total': total,
        'all_passed': failed == 0
    }


def main():
    """运行所有安全测试"""
    print("\n=== 安全漏洞修复验证测试 ===")
    
    results = {}
    
    results['code_injection'] = test_code_injection_attack()
    results['redos'] = test_redos_attack()
    results['normal_conditions'] = test_normal_conditions_still_work()
    
    print("\n" + "=" * 60)
    print("安全测试汇总")
    print("=" * 60)
    
    all_ok = True
    
    ci = results['code_injection']
    print(f"\n1. 代码注入防护: {'✅ PASS' if ci['attack_blocked'] else '❌ FAIL'}")
    
    rd = results['redos']
    print(f"2. ReDoS防护: {'✅ PASS' if rd['protected'] else '❌ FAIL'}")
    print(f"   耗时: {rd['elapsed_ms']:.2f} ms")
    
    nc = results['normal_conditions']
    print(f"3. 正常功能: {'✅ PASS' if nc['all_passed'] else '❌ FAIL'}")
    print(f"   {nc['passed']}/{nc['total']} 测试通过")
    
    all_ok = ci['attack_blocked'] and rd['protected'] and nc['all_passed']
    
    print("\n" + "=" * 60)
    if all_ok:
        print("✅ 所有安全测试通过！漏洞修复成功")
    else:
        print("❌ 有些测试失败，需要进一步修复")
    print("=" * 60)
    
    return results


if __name__ == "__main__":
    main()
