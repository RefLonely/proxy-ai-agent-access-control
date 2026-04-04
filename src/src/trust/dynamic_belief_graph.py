import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import networkx as nx
import numpy as np

from ..models.agent import Agent, TrustRelationship

logger = logging.getLogger(__name__)


@dataclass
class BeliefNode:
    """信念图节点"""
    agent_id: str
    agent: Agent
    belief: float = 1.0  # 节点自身信念值
    last_updated: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class BeliefEdge:
    """信念图边 - 表示信任关系"""
    source_id: str
    target_id: str
    trust_score: float  # 源对目标的信任评分 0-1
    evidence_count: int = 0  # 支持该信任评分的证据数量
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def weight(self) -> float:
        """将信任评分转换为图权重 (0-1)"""
        return self.trust_score


class DynamicBeliefGraph:
    """动态信念图 - 用于维护多代理信任关系"""
    
    def __init__(self):
        self.nodes: Dict[str, BeliefNode] = {}
        self.edges: Dict[Tuple[str, str], BeliefEdge] = {}
        self.graph = nx.DiGraph()
        self.last_consensus = datetime.now()
    
    def add_agent(self, agent: Agent) -> BeliefNode:
        """添加代理到信念图"""
        node = BeliefNode(agent_id=agent.agent_id, agent=agent)
        self.nodes[agent.agent_id] = node
        self.graph.add_node(agent.agent_id, belief=node.belief)
        return node
    
    def add_trust_edge(self, source_id: str, target_id: str, trust_score: float) -> BeliefEdge:
        """添加信任边"""
        edge = BeliefEdge(
            source_id=source_id,
            target_id=target_id,
            trust_score=trust_score
        )
        key = (source_id, target_id)
        self.edges[key] = edge
        self.graph.add_edge(
            source_id, 
            target_id, 
            weight=edge.weight,
            trust_score=trust_score
        )
        return edge
    
    def update_trust(self, source_id: str, target_id: str, 
                     new_trust: Optional[float] = None, 
                     delta: Optional[float] = None) -> Optional[BeliefEdge]:
        """更新信任评分"""
        key = (source_id, target_id)
        edge = self.edges.get(key)
        if edge is None:
            return None
        
        if new_trust is not None:
            edge.trust_score = max(0.0, min(1.0, new_trust))
        elif delta is not None:
            edge.trust_score = max(0.0, min(1.0, edge.trust_score + delta))
        
        edge.last_updated = datetime.now()
        edge.evidence_count += 1
        self.graph[source_id][target_id]['weight'] = edge.weight
        self.graph[source_id][target_id]['trust_score'] = edge.trust_score
        return edge
    
    def get_trust_path(self, source_id: str, target_id: str) -> Optional[List[BeliefEdge]]:
        """获取从源到目标的最高信任路径"""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        
        try:
            # 使用信任评分作为权重找最长路径 (最高信任)
            path = nx.dijkstra_path(
                self.graph, 
                source_id, 
                target_id, 
                weight=lambda u, v, d: 1.0 - d['weight']
            )
        except nx.NetworkXNoPath:
            return None
        
        edges = []
        for i in range(len(path) - 1):
            key = (path[i], path[i+1])
            edge = self.edges.get(key)
            if edge:
                edges.append(edge)
        return edges
    
    def compute_min_trust_on_path(self, path: List[BeliefEdge]) -> float:
        """计算路径上的最小信任值 (最弱链路)"""
        if not path:
            return 0.0
        return min(edge.trust_score for edge in path)
    
    def get_aggregate_trust(self, source_id: str, target_id: str) -> float:
        """计算源对目标的聚合信任值"""
        # 直接信任
        direct_key = (source_id, target_id)
        direct_edge = self.edges.get(direct_key)
        direct_trust = direct_edge.trust_score if direct_edge else 0.0
        
        # 间接信任 - 通过多路径传播
        path = self.get_trust_path(source_id, target_id)
        if not path:
            return direct_trust
        
        indirect_trust = self.compute_min_trust_on_path(path)
        
        # 加权聚合: 直接信任权重更高
        if direct_edge:
            alpha = 0.7  # 直接信任权重
            return alpha * direct_trust + (1 - alpha) * indirect_trust
        else:
            return indirect_trust
    
    def propagate_beliefs(self, iterations: int = 5, damping: float = 0.85, 
                           incremental: bool = True, changed_nodes: List[str] = None) -> Dict[str, float]:
        """信念传播 - 更新节点信念值
        Args:
            iterations: 传播迭代次数
            damping: 阻尼系数
            incremental: 是否启用增量更新（默认启用，提高大规模节点性能
            changed_nodes: 仅这些节点发生了变化，如果为None则全量更新
        """
        n = len(self.nodes)
        if n == 0:
            return {}
        
        # 如果不是增量更新或者没有变更节点，或节点数量较少，直接全量计算
        if not incremental or changed_nodes is None or n <= 100:
            return self._full_propagate(iterations, damping)
        
        # 增量更新：只更新与变更节点相关的部分
        return self._incremental_propagation(changed_nodes, iterations, damping)
    
    def _full_propagate(self, iterations: int, damping: float) -> Dict[str, float]:
        """全量信念传播（原始实现）"""
        node_list = list(self.nodes.keys())
        node_idx = {nid: i for i, nid in enumerate(node_list)}
        
        # PageRank风格的信念传播
        A = nx.adjacency_matrix(self.graph, weight='weight').todense()
        # 归一化
        A = A / (A.sum(axis=1, keepdims=True) + 1e-8)
        
        # 初始信念
        beliefs = np.array([self.nodes[nid].belief for nid in node_list])
        
        for _ in range(iterations):
            new_beliefs = damping * A.T.dot(beliefs) + (1 - damping) * (1.0 / len(self.nodes))
            beliefs = new_beliefs
        
        # 更新节点信念
        for i, nid in enumerate(node_list):
            self.nodes[nid].belief = float(beliefs[i])
            self.nodes[nid].last_updated = datetime.now()
        
        return {nid: self.nodes[nid].belief for nid in node_list}
    
    def _incremental_propagation(self, changed_nodes: List[str], iterations: int, damping: float) -> Dict[str, float]:
        """增量信念传播 - 仅传播发生变化的节点及其邻居
        显著提升大规模图性能，只更新相关区域，节省计算量
        """
        # 找到需要更新的节点集合：变更节点 + 所有邻居
        affected_nodes = set(changed_nodes)
        for nid in changed_nodes:
            # 添加前驱和后继
            affected_nodes.update(self._get_predecessors(nid))
            affected_nodes.update(self._get_successors(nid))
        
        affected_list = list(affected_nodes)
        m = len(affected_list)
        if m == 0:
            return {}
        
        # 提取子图进行计算
        node_idx = {nid: i for i, nid in enumerate(affected_list)}
        sub_beliefs = np.array([self.nodes[nid].belief for nid in affected_list])
        
        # 只构建子图邻接矩阵
        adj_matrix = np.zeros((m, m))
        for i, source_id in enumerate(affected_list):
            out_edges = [(s, t) for (s, t) in self.edges.keys() if s == source_id and t in affected_nodes]
            total_weight = sum(self.edges[(s, t)].weight for (s, t) in out_edges)
            if total_weight > 0:
                for (s, t) in out_edges:
                    j = node_idx[t]
                    adj_matrix[j][i] = self.edges[(s, t)].weight / (total_weight + 1e-8)
        
        # 迭代传播
        n_total = len(self.nodes)
        for _ in range(iterations):
            new_beliefs = damping * adj_matrix.dot(sub_beliefs) + (1 - damping) * (1.0 / n_total)
            sub_beliefs = new_beliefs
        
        # 更新信念
        result = {}
        for i, nid in enumerate(affected_list):
            self.nodes[nid].belief = float(sub_beliefs[i])
            self.nodes[nid].last_updated = datetime.now()
            result[nid] = float(sub_beliefs[i])
        
        logger.debug(f"Incremental propagation updated {len(result)} nodes out of {len(self.nodes)} total")
        return result
    
    def _get_predecessors(self, nid: str) -> List[str]:
        """获取节点的所有前驱节点"""
        predecessors = []
        for (source, target) in self.edges.keys():
            if target == nid:
                predecessors.append(source)
        return predecessors
    
    def _get_successors(self, nid: str) -> List[str]:
        """获取节点的所有后继节点"""
        successors = []
        for (source, target) in self.edges.keys():
            if source == nid:
                successors.append(target)
        return successors
    
    def detect_anomalous_trust(self, threshold: float = 0.3) -> List[str]:
        """检测异常低信任的代理"""
        return [
            node.agent_id 
            for node in self.nodes.values() 
            if node.belief < threshold
        ]
    
    def get_trust_boundary(self, min_trust: float = 0.5) -> Tuple[Set[str], Set[str]]:
        """划分信任边界: 可信域和不可信域"""
        trusted = set()
        untrusted = set()
        for node_id, node in self.nodes.items():
            if node.belief >= min_trust:
                trusted.add(node_id)
            else:
                untrusted.add(node_id)
        return trusted, untrusted
    
    def contract_boundary(self, agent_id: str, decay_factor: float = 0.5) -> int:
        """收缩信任边界 - 降低所有指向该代理的信任评分"""
        updated = 0
        for (source, target), edge in list(self.edges.items()):
            if target == agent_id or source == agent_id:
                edge.trust_score *= decay_factor
                edge.last_updated = datetime.now()
                self.graph[source][target]['weight'] = edge.weight
                updated += 1
        return updated
    
    def to_networkx(self) -> nx.DiGraph:
        """导出为NetworkX图"""
        return self.graph.copy()
