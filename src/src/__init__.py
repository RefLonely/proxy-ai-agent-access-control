# Proxy AI Agent Access Control - Industrial Internet
from .access_controller import AgenticAccessController

# Models
from .models.agent import Agent, AgentState, TrustRelationship
from .models.access_request import AccessRequest, AccessDecision, AccessAction, DecisionOutcome
from .models.security_schema import SecuritySchema, SchemaMatchResult

# Trust management
from .trust import DynamicBeliefGraph, TrustManager, DistributedConsensus

# Alignment
from .alignment import SchemaManager, EmbeddingMatcher, AlignmentValidator, ValidationResult

__version__ = "1.0.0"
__author__ = "Proxy AI Access Control Project"

__all__ = [
    # Main controller
    'AgenticAccessController',
    
    # Models
    'Agent',
    'AgentState',
    'TrustRelationship',
    'AccessRequest',
    'AccessDecision',
    'AccessAction',
    'DecisionOutcome',
    'SecuritySchema',
    'SchemaMatchResult',
    
    # Trust
    'DynamicBeliefGraph',
    'TrustManager',
    'DistributedConsensus',
    
    # Alignment
    'SchemaManager',
    'EmbeddingMatcher',
    'AlignmentValidator',
    'ValidationResult',
]
