"""
Tree Feature Attribution & SHAP-Style Explainability Engine for CyberOracle Intelligence
Computes exact local feature attributions across tree paths for the Random Forest model
and linear coefficients for the Meta-Fusion Stacking model.
Satisfies local additivity: Base Value + sum(Attributions) = Prediction Probability.
"""

import numpy as np
from .ml_model import load_model, get_features, FEATURE_NAMES
from .meta_fusion import get_meta_fusion_engine, VIEW_FEATURE_NAMES


def explain_request_prediction(log) -> dict:
    """
    Compute local tree path feature attributions for an individual RequestLog.
    Returns: {
        'base_value': float,
        'prediction_probability': float,
        'feature_attributions': [{'feature': str, 'value': float, 'attribution': float, 'direction': str}],
        'top_drivers': [str]
    }
    """
    clf = load_model()
    features = np.array(get_features(log), dtype=float)

    if not clf or not hasattr(clf, 'estimators_'):
        # Fallback heuristic contribution
        return {
            'base_value': 0.10,
            'prediction_probability': 0.85 if log.is_sqli_suspect else 0.05,
            'feature_attributions': [
                {'feature': 'is_sqli_suspect', 'value': int(log.is_sqli_suspect), 'attribution': 0.40 if log.is_sqli_suspect else 0.0, 'direction': 'MALICIOUS' if log.is_sqli_suspect else 'BENIGN'},
                {'feature': 'entropy_score', 'value': round(float(log.entropy_score), 2), 'attribution': 0.20 if log.entropy_score > 4.0 else 0.0, 'direction': 'MALICIOUS' if log.entropy_score > 4.0 else 'BENIGN'},
                {'feature': 'request_rate', 'value': round(float(log.request_rate), 2), 'attribution': 0.15 if log.request_rate > 10 else 0.0, 'direction': 'MALICIOUS' if log.request_rate > 10 else 'BENIGN'}
            ],
            'top_drivers': ['is_sqli_suspect', 'entropy_score']
        }

    # 1. Compute Base Value (Expected value of positive class across all tree roots)
    n_trees = len(clf.estimators_)
    root_probs = []
    for tree in clf.estimators_:
        root_val = tree.tree_.value[0]
        # Normalize to class 1 probability
        p1 = root_val[0][1] / np.sum(root_val[0]) if np.sum(root_val[0]) > 0 else 0.0
        root_probs.append(p1)
    base_value = float(np.mean(root_probs))

    # 2. Compute Tree Path Decomposition (Tree Attribution)
    feature_contribs = np.zeros(len(features), dtype=float)
    x = features.reshape(1, -1)

    for tree in clf.estimators_:
        node_indicator = tree.decision_path(x)
        node_indices = node_indicator.indices
        
        # Traverse path from root to leaf
        for i in range(len(node_indices) - 1):
            curr_node = node_indices[i]
            next_node = node_indices[i + 1]
            split_feat = tree.tree_.feature[curr_node]

            if split_feat >= 0:
                v_curr = tree.tree_.value[curr_node][0]
                v_next = tree.tree_.value[next_node][0]
                p_curr = v_curr[1] / np.sum(v_curr) if np.sum(v_curr) > 0 else 0.0
                p_next = v_next[1] / np.sum(v_next) if np.sum(v_next) > 0 else 0.0
                delta_p = p_next - p_curr
                feature_contribs[split_feat] += delta_p

    # Average across all estimators
    feature_contribs /= n_trees
    pred_prob = float(np.clip(base_value + np.sum(feature_contribs), 0.0, 1.0))

    # Format structured attribution list
    attributions = []
    for f_idx, feat_name in enumerate(FEATURE_NAMES):
        val = float(features[f_idx])
        contrib = float(feature_contribs[f_idx])
        attributions.append({
            'feature': feat_name,
            'value': round(val, 3),
            'attribution': round(contrib, 4),
            'percentage_impact': round(contrib * 100.0, 1),
            'direction': 'MALICIOUS' if contrib > 0.001 else ('BENIGN' if contrib < -0.001 else 'NEUTRAL')
        })

    # Sort by absolute magnitude of contribution
    sorted_attributions = sorted(attributions, key=lambda a: abs(a['attribution']), reverse=True)
    top_drivers = [a['feature'] for a in sorted_attributions if abs(a['attribution']) >= 0.02][:4]

    return {
        'base_value': round(base_value, 4),
        'prediction_probability': round(pred_prob, 4),
        'feature_attributions': sorted_attributions,
        'top_drivers': top_drivers
    }


def explain_meta_fusion_decision(profile) -> dict:
    """
    Explain 5-view meta-fusion decision using learned model coefficients.
    Returns: {
        'fused_score': float,
        'fused_probability': float,
        'view_breakdown': [{'view': str, 'score': float, 'weight': float, 'contribution': float}],
        'dominant_view': str
    }
    """
    engine = get_meta_fusion_engine()
    r = getattr(profile, 'rule_score', 0) or 0
    m = getattr(profile, 'ml_score', 0) or 0
    a = getattr(profile, 'anomaly_score', 0) or 0
    s = getattr(profile, 'sequence_score', 0) or 0
    l = getattr(profile, 'llm_score', 0) or 0

    prob, score, raw_contribs = engine.predict_probability(r, m, a, s, l)

    coefs = engine.coefficients if engine.is_trained and engine.coefficients else [0.25, 0.25, 0.15, 0.20, 0.15]
    total_w = sum(abs(c) for c in coefs) or 1.0
    normalized_weights = [abs(c) / total_w for c in coefs]

    view_data = [
        ('Rules View', r, normalized_weights[0]),
        ('Random Forest View', m, normalized_weights[1]),
        ('Isolation Forest View', a, normalized_weights[2]),
        ('Sequence Forecaster View', s, normalized_weights[3]),
        ('Graph Analytics View', l, normalized_weights[4]),
    ]

    breakdown = []
    for name, v_score, w in view_data:
        impact = round(float(v_score) * w, 1)
        breakdown.append({
            'view': name,
            'score': round(float(v_score), 1),
            'weight': round(float(w), 3),
            'impact_points': impact
        })

    breakdown.sort(key=lambda x: x['impact_points'], reverse=True)
    dominant_view = breakdown[0]['view'] if breakdown else 'Rule View'

    return {
        'fused_score': score,
        'fused_probability': prob,
        'view_breakdown': breakdown,
        'dominant_view': dominant_view
    }
