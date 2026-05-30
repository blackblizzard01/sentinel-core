import asyncio
from agents.orchestrator import SentinelOrchestrator

async def run():
    o = SentinelOrchestrator()
    final = await o.run_scan(
        client_id='a5dd7c5b-c9ed-474d-afbd-06c3f0eb9a21',
        scan_id='963cc47c-dd82-4d4c-bc3a-11f0e67de7f3'
    )
    print('Phase      :', final['phase'])
    print('Logs       :', final['logs'])
    print('Attacks    :', len(final['attack_results']))
    print('Report path:', final['report_path'])

asyncio.run(run())