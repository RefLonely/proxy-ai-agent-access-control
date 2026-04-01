"""
电网分布式代理自主访问控制 - 网页演示
"""
from flask import Flask, render_template, request, jsonify
import sys
import os

sys.path.append('..')

from src.alignment.schema_manager import SchemaManager
from src.alignment.alignment_validator import AlignmentValidator
from src.alignment.embedding_matcher import EmbeddingMatcher
from src.models.access_request import AccessRequest, AccessAction, DecisionOutcome

app = Flask(__name__)

# 初始化模块
schema_manager = SchemaManager()
# 加载电网默认安全基模
schema_manager.load_default_power_grid_schemas()
embedding_matcher = EmbeddingMatcher(enable_power_grid_optimization=True)
validator = AlignmentValidator(
    schema_manager=schema_manager,
    embedding_matcher=embedding_matcher,
    min_alignment_threshold=0.8,
    challenge_threshold=0.5,
    limit_threshold=0.2
)

# 决策结果描述
OUTCOME_DESCRIPTIONS = {
    DecisionOutcome.ALLOW: {
        "name": "允许",
        "color": "#10b981",
        "description": "低风险，直接允许访问"
    },
    DecisionOutcome.CHALLENGE: {
        "name": "挑战",
        "color": "#f59e0b",
        "description": "中等风险，需要二次验证"
    },
    DecisionOutcome.LIMIT: {
        "name": "限制",
        "color": "#f97316",
        "description": "中高风险，允许访问但限制权限"
    },
    DecisionOutcome.DENY: {
        "name": "拒绝",
        "color": "#ef4444",
        "description": "高风险，拒绝本次访问"
    },
    DecisionOutcome.ISOLATE: {
        "name": "隔离",
        "color": "#7f1d1d",
        "description": "极高风险，拒绝访问并隔离源节点"
    }
}


@app.route('/')
def index():
    return render_template('index.html', outcomes=OUTCOME_DESCRIPTIONS)


@app.route('/validate', methods=['POST'])
def validate():
    data = request.get_json()
    
    requester = data.get('requester', '').strip()
    target = data.get('target', '').strip()
    action = data.get('action', '').strip()
    llm_decision = data.get('llm_decision', 'allow')
    llm_reasoning = data.get('llm_reasoning', '').strip()
    
    # 映射动作
    action_map = {
        'read': AccessAction.READ,
        'write': AccessAction.WRITE,
        'control': AccessAction.CONTROL,
        'configure': AccessAction.CONFIGURE,
        'monitor': AccessAction.MONITOR,
    }
    action_enum = action_map.get(action.lower(), AccessAction.READ)
    
    # 映射LLM决策
    decision_map = {
        'allow': DecisionOutcome.ALLOW,
        'deny': DecisionOutcome.DENY,
    }
    llm_decision_enum = decision_map.get(llm_decision.lower(), DecisionOutcome.ALLOW)
    
    # 创建访问请求
    import uuid
    from datetime import datetime
    request_obj = AccessRequest(
        request_id=str(uuid.uuid4()),
        requester_id=requester,
        target_id=target,
        action=action_enum,
        context={
            'trust': float(data.get('trust', 0.5)),
            'domain': data.get('domain', 'district'),
        },
        timestamp=datetime.now()
    )
    
    # 验证
    result = validator.validate_llm_decision(
        request=request_obj,
        llm_decision=llm_decision_enum,
        llm_reasoning=llm_reasoning
    )
    
    # 整理匹配结果
    matches = []
    for match in result.matching_results:
        matches.append({
            'schema_name': match.schema.name,
            'overall_score': round(match.overall_score, 3),
            'subject_match': match.subject_match,
            'object_match': match.object_match,
            'action_match': match.action_match,
            'embedding_similarity': round(match.embedding_similarity, 3),
        })
    
    response = {
        'valid': result.valid,
        'alignment_score': round(result.alignment_score, 3),
        'best_match_schema': result.best_match_schema.name if result.best_match_schema else None,
        'matching_results': matches,
        'reason': result.reason,
        'recommendation': result.recommendation.value,
        'recommendation_info': OUTCOME_DESCRIPTIONS[result.recommendation],
    }
    
    return jsonify(response)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
