import asyncio
from agents.recon_agent import ReconAgent

async def test():
    agent = ReconAgent(client_id='test-client', scan_id='test-scan-001')
    manifest = {
        'components': [
            {'endpoint': 'http://localhost:8080/chat', 'framework': 'fastapi'}
        ]
    }
    result = await agent.build_component_map(manifest)
    print('Component map:', result)
    assert len(result) == 1
    assert 'component_id' in result[0]
    assert 'estimated_attack_domains' in result[0]
    print('PASS')

asyncio.run(test())