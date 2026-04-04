"""
动态信念图增量传播测试
验证增量更新功能正确性和性能优化
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.trust.dynamic_belief_graph import DynamicBeliefGraph
from src.models.agent import Agent


class TestIncrementalBeliefPropagation:
    """测试增量信念传播"""
    
    def test_incremental_propagation_exists(self):
        """验证增量传播方法存在"""
        dbg = DynamicBeliefGraph()
        agent1 = Agent(agent_id="agent1", name="Agent 1")
        agent2 = Agent(agent_id="agent2", name="Agent 2")
        agent3 = Agent(agent_id="agent3", name="Agent 3")
        
        dbg.add_agent(agent1)
        dbg.add_agent(agent2)
        dbg.add_agent(agent3)
        dbg.add_trust_edge("agent1", "agent2", 0.8)
        dbg.add_trust_edge("agent2", "agent3", 0.6)
        
        # 增量传播应该存在这个接口
        assert hasattr(dbg, '_incremental_propagation')
        assert hasattr(dbg, '_full_propagate')
        
        # 测试增量传播调用
        result = dbg.propagate_beliefs(
            iterations=3,
            incremental=True,
            changed_nodes=["agent2"]
        )
        
        # 应该返回affected nodes
        assert "agent1" in result
        assert "agent2" in result
        assert "agent3" in result
        assert len(result) <= 3  # 全部三个都受到影响
    
    def test_full_propagation_unchanged(self):
        """验证全量传播功能保持不变"""
        dbg = DynamicBeliefGraph()
        agent1 = Agent(agent_id="agent1", name="Agent 1")
        agent2 = Agent(agent_id="agent2", name="Agent 2")
        
        dbg.add_agent(agent1)
        dbg.add_agent(agent2)
        dbg.add_trust_edge("agent1", "agent2", 0.5)
        
        # 全量传播
        result = dbg.propagate_beliefs(incremental=False)
        assert len(result) == 2
        assert all(agent_id in result for agent_id in ["agent1", "agent2"])
        
        # 节点信念都更新了
        assert all(dbg.nodes[agent_id].last_updated is not None for agent_id in ["agent1", "agent2"])
    
    def test_incremental_only_updates_affected(self):
        """验证增量更新只更新受影响的节点，节省计算量"""
        dbg = DynamicBeliefGraph()
        
        # 创建一个包含10个节点的链
        for i in range(10):
            agent = Agent(agent_id=f"agent{i}", name=f"Agent {i}")
            dbg.add_agent(agent)
            if i > 0:
                dbg.add_trust_edge(f"agent{i-1}", f"agent{i}", 0.8)
        
        # 初始传播全量
        dbg.propagate_beliefs(incremental=False)
        
        # 记录信念值
        original_beliefs = {
            nid: node.belief 
            for nid, node in dbg.nodes.items()
        }
        
        # 改变节点5的信念值，然后增量更新
        dbg.nodes["agent5"].belief = 0.0
        result = dbg.propagate_beliefs(
            iterations=3,
            incremental=True,
            changed_nodes=["agent5"]
        )
        
        # 检查只有受影响的节点信念被更新
        # agent0,1,2 距离太远不应该变化
        for i in [0, 1, 2]:
            assert abs(dbg.nodes[f"agent{i}"].belief - original_beliefs[f"agent{i}"]) < 1e-9
    
    def test_both_methods_give_similar_results(self):
        """验证增量传播和全量传播结果相似"""
        dbg1 = DynamicBeliefGraph()
        dbg2 = DynamicBeliefGraph()
        
        # 构建相同图
        for i in range(5):
            agent = Agent(agent_id=f"agent{i}", name=f"Agent {i}")
            dbg1.add_agent(agent)
            dbg2.add_agent(agent)
        
        for i in range(4):
            dbg1.add_trust_edge(f"agent{i}", f"agent{i+1}", 0.5 + i * 0.1)
            dbg2.add_trust_edge(f"agent{i}", f"agent{i+1}", 0.5 + i * 0.1)
        
        # 全量计算
        full_result = dbg1.propagate_beliefs(incremental=False, iterations=5)
        
        # 增量计算（假设全图改变，结果应该和全量一致）
        all_nodes = list(dbg2.nodes.keys())
        inc_result = dbg2.propagate_beliefs(
            incremental=True, 
            changed_nodes=all_nodes,
            iterations=5
        )
        
        # 结果应该接近
        for nid in full_result:
            assert abs(full_result[nid] - inc_result[nid]) < 1e-5
