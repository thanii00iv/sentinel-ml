"""
Proxy interface for monitor.llm_layer to ensure complete backward compatibility.
"""

from .llm_layer import (
    generate_threat_explanation,
    analyze_threat_with_llm,
    trigger_async_llm_analysis,
    get_mitre_retriever,
    sanitize_untrusted_payload,
)