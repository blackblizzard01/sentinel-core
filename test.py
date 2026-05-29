import asyncio
from agents.orchestrator import SentinelOrchestrator

async def test():
    orchestrator = SentinelOrchestrator()
    final_state = await orchestrator.run_scan(
        client_id='test-client-001',
        scan_id='test-scan-001'
    )
    print('Final phase  :', final_state['phase'])
    print('Logs         :', final_state['logs'])
    print('Attack results:', len(final_state['attack_results']))
    print('Report path  :', final_state['report_path'])
    print('SCAN COMPLETE OK')

asyncio.run(test())