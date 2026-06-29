import inspect, asyncio
from knowledge_base.knowledge_base import KnowledgeBase
sig = inspect.signature(KnowledgeBase.get_cross_component_insights)
params = list(sig.parameters.keys())
assert 'completed_component_id' in params
assert 'next_component_type' in params
print('Signature OK:', params)
