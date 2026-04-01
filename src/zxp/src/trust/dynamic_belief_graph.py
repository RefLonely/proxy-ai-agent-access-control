from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import networkx as nx
import numpy as np

from ..models.agent import Agent, TrustRelationship


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
    
    def propagate_beliefs(self, iterations: int = 5, damping: float = 0.85) -> Dict[str, float]:
        """信念传播 - 更新所有节点的信念值"""
        n = len(self.nodes)
        if n == 0:
            return {}
        
        # 构建邻接矩阵
        node_list = list(self.nodes.keys())
        node_idx = {nid: i for i, nid in enumerate(node_list)}
        
        # PageRank风格的信念传播
        A = nx.adjacency_matrix(self.graph, weight='weight').todense()
        # 归一化
        A = A / (A.sum(axis=1, keepdims=True) + 1e-8)
        
        # 初始信念
        beliefs = np.array([self.nodes[nid].belief for nid in node_list])
        
        for _ in range(iterations):
            new_beliefs = damping * A.T.dot(beliefs) + (1 - damping) * (1.0 / n)
            beliefs = new_beliefs
        
        # 更新节点信念
        for i, nid in enumerate(node_list):
            self.nodes[nid].belief = float(beliefs[i])
            self.nodes[nid].last_updated = datetime.now()
        
        return {nid: self.nodes[nid].belief for nid in node_list}
    
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
