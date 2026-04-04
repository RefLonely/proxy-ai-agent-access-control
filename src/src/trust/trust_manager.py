from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import logging

from ..models.agent import Agent, AgentState, TrustRelationship
from ..models.access_request import AccessRequest, AccessDecision, DecisionOutcome
from .dynamic_belief_graph import DynamicBeliefGraph
from .consensus import DistributedConsensus

logger = logging.getLogger(__name__)


class TrustManager:
    """信任管理器 - 管理多代理协作中的信任边界"""
    
    def __init__(self, 
                 local_agent: Agent,
                 min_trust_threshold: float = 0.5,
                 suspicious_threshold: float = 0.3,
               consensus_enabled: bool = True):
        self.local_agent = local_agent
        self.dbg = DynamicBeliefGraph()
        self.consensus = DistributedConsensus(local_agent.agent_id) if consensus_enabled else None
        self.min_trust_threshold = min_trust_threshold
        self.suspicious_threshold = suspicious_threshold
        
        # 将本地代理加入信念图
        self.dbg.add_agent(local_agent)
        
        # 信任统计
        self.trust_updates = 0
        self.anomaly_detected = 0
    
    def add_remote_agent(self, agent: Agent, initial_trust: float) -> None:
        """添加远程代理并设置初始信任"""
        self.dbg.add_agent(agent)
        self.dbg.add_trust_edge(
            source_id=self.local_agent.agent_id,
            target_id=agent.agent_id,
            trust_score=initial_trust
        )
        logger.info(f"Added remote agent {agent.agent_id} with initial trust {initial_trust}")
    
    def evaluate_access_trust(self, requester_id: str, target_id: str) -> Tuple[float, bool]:
        """
        评估请求者对目标的访问信任
        返回 (聚合信任分数, 是否满足最低信任要求)
        """
        trust_score = self.dbg.get_aggregate_trust(requester_id, target_id)
        meets_requirement = trust_score >= self.min_trust_threshold
        return trust_score, meets_requirement
    
    def report_interaction_result(self, source_id: str, target_id: str, success: bool) -> None:
        """报告交互结果，用于更新信任"""
        # 更新直接信任
        self.dbg.update_trust(source_id, target_id, 
                              delta=0.05 if success else -0.15)
        
        # 如果交互失败，传播信念
        if not success:
            # 使用增量更新，只传播和source_id/target_id相关的节点
            self.dbg.propagate_beliefs(
                iterations=3, 
                incremental=True, 
                changed_nodes=[source_id, target_id]
            )
            self.anomaly_detected += 1
            
            # 检查是否需要收缩信任边界
            edge = self.dbg.edges.get((source_id, target_id))
            if edge and edge.trust_score < self.suspicious_threshold:
                updated = self.dbg.contract_boundary(target_id, decay_factor=0.8)
                logger.warning(f"Contracted trust boundary around {target_id}, updated {updated} edges")
        
        self.trust_updates += 1
    
    def detect_anomalies(self) -> List[str]:
        """检测异常代理"""
        return self.dbg.detect_anomalous_trust(threshold=self.suspicious_threshold)
    
    def get_trust_boundary(self) -> Tuple[Set[str], Set[str]]:
        """获取当前信任边界划分"""
        return self.dbg.get_trust_boundary(min_trust=self.min_trust_threshold)
    
    async def run_consensus(self, messages: List) -> Tuple[Dict[str, float], bool]:
        """运行分布式共识同步信任状态"""
        if not self.consensus:
            return {}, False
        
        result = await self.consensus.synchronize_beliefs(
            dbg=self.dbg,
            messages=messages
        )
        
        # 更新本地信念图
        for agent_id, belief in result.beliefs.items():
            if agent_id in self.dbg.nodes:
                self.dbg.nodes[agent_id].belief = belief
        
        logger.info(f"Consensus completed, updated {len(result.beliefs)} beliefs")
        return result.beliefs, result.converged
    
    def get_trust_score(self, source_id: str, target_id: str) -> float:
        """获取源代理对目标代理的信任评分"""
        return self.dbg.get_aggregate_trust(source_id, target_id)
    
    def get_statistics(self) -> Dict:
        """获取信任管理统计信息"""
        trusted, untrusted = self.get_trust_boundary()
        return {
            'total_agents': len(self.dbg.nodes),
            'trusted_agents': len(trusted),
            'untrusted_agents': len(untrusted),
            'trust_updates': self.trust_updates,
            'anomalies_detected': self.anomaly_detected,
            'edges': len(self.dbg.edges)
        }
