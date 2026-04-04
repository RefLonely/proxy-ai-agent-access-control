from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import asyncio
import logging

from .dynamic_belief_graph import DynamicBeliefGraph

logger = logging.getLogger(__name__)


@dataclass
class ConsensusMessage:
    """共识消息"""
    sender_id: str
    round: int
    beliefs: Dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ConsensusResult:
    """共识结果"""
    converged: bool
    beliefs: Dict[str, float]
    rounds: int
    tolerance: float


class DistributedConsensus:
    """分布式信念共识 - 部分同步模型下的一致性算法"""
    
    def __init__(self, 
                 local_agent_id: str,
                 max_rounds: int = 10,
                 tolerance: float = 0.01,
                 alpha: float = 0.2):
        self.local_agent_id = local_agent_id
        self.max_rounds = max_rounds
        self.tolerance = tolerance
        self.alpha = alpha  # 融合系数
        self.current_round = 0
        self.last_beliefs: Dict[str, float] = {}
    
    def _compute_difference(self, old: Dict[str, float], new: Dict[str, float]) -> float:
        """计算两轮信念的最大差异"""
        max_diff = 0.0
        all_keys = set(old.keys()).union(set(new.keys()))
        for key in all_keys:
            v_old = old.get(key, 0.0)
            v_new = new.get(key, 0.0)
            diff = abs(v_old - v_new)
            max_diff = max(max_diff, diff)
        return max_diff
    
    async def synchronize_beliefs(self, 
                                  dbg: DynamicBeliefGraph, 
                                  messages: List[ConsensusMessage]) -> ConsensusResult:
        """
        同步信念状态
        使用加权平均共识算法
        """
        # 获取当前本地信念
        current_beliefs = {
            node.agent_id: node.belief
            for node in dbg.nodes.values()
        }
        
        # 如果是第一轮，初始化
        if self.current_round == 0:
            self.last_beliefs = current_beliefs
        
        # 融合来自其他节点的信念
        for msg in messages:
            for agent_id, remote_belief in msg.beliefs.items():
                if agent_id in current_beliefs:
                    # 加权融合
                    current_beliefs[agent_id] = (
                        (1 - self.alpha) * current_beliefs[agent_id] + 
                        self.alpha * remote_belief
                    )
        
        # 检查收敛
        diff = self._compute_difference(self.last_beliefs, current_beliefs)
        converged = diff < self.tolerance or self.current_round >= self.max_rounds - 1
        
        # 更新本地信念图
        for agent_id, belief in current_beliefs.items():
            if agent_id in dbg.nodes:
                dbg.nodes[agent_id].belief = belief
        
        result = ConsensusResult(
            converged=converged,
            beliefs=current_beliefs,
            rounds=self.current_round + 1,
            tolerance=diff
        )
        
        if converged:
            logger.info(f"Consensus converged after {result.rounds} rounds, final diff: {diff:.4f}")
            self.current_round = 0
        else:
            self.current_round += 1
            self.last_beliefs = current_beliefs
        
        return result
    
    def prepare_message(self, dbg: DynamicBeliefGraph) -> ConsensusMessage:
        """准备要发送的共识消息"""
        beliefs = {
            node.agent_id: node.belief
            for node in dbg.nodes.values()
        }
        return ConsensusMessage(
            sender_id=self.local_agent_id,
            round=self.current_round,
            beliefs=beliefs
        )
