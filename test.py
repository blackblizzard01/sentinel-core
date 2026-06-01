import asyncio
from agents.orchestrator import run_scan

async def main():
    # Tell Sentinel where your dummy target lives
    manifest = {
        "components": [
            {
                "endpoint": "http://localhost:8002/chat",
                "type": "llm_model",          # ReconAgent will trust this
                "framework": "mistral"
            }
        ]
    }

    final_state = await run_scan(
        client_id="survival_client",
        scan_id="survival_scan",
        manifest=manifest
    )

    print("\n=== SCAN COMPLETE ===")
    print(f"Phase         : {final_state['phase']}")
    print(f"Components    : {len(final_state.get('components', []))}")
    print(f"Attack results: {len(final_state.get('all_attack_results', []))}")
    print(f"Critical halt : {final_state.get('critical_halt', False)}")

if __name__ == "__main__":
    asyncio.run(main())