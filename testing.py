# test_connections.py
# ============================================================
# SENTINEL AI — Connection Test Script
# Run this to verify all your API keys and services work.
# Command: python test_connections.py
# ============================================================

import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

async def test_supabase():
    try:
        import asyncpg
        conn = await asyncpg.connect(os.getenv("DATABASE_URL"))
        await conn.close()
        print("  Supabase PostgreSQL")
    except Exception as e:
        print(f"  Supabase PostgreSQL  ERROR: {e}")

async def test_redis():
    try:
        import redis
        r = redis.from_url(os.getenv("REDIS_URL"))
        r.ping()
        print("  Upstash Redis")
    except Exception as e:
        print(f"  Upstash Redis  ERROR: {e}")

async def test_groq():
    try:
        from groq import Groq
        key = os.getenv("GROQ_API_KEY_1")
        if not key or "paste" in key:
            print("  Groq  MISSING KEY")
            return
        client = Groq(api_key=key)
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": "say hi"}],
            max_tokens=5
        )
        print("  Groq Llama")
    except Exception as e:
        print(f"  Groq  ERROR: {e}")

async def test_gemini():
    try:
        from google import genai
        key = os.getenv("GEMINI_API_KEY_1")
        if not key or "paste" in key:
            print("  Gemini  MISSING KEY")
            return
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents="say hi"
        )
        print("  Google Gemini")
    except Exception as e:
        print(f"  Gemini  ERROR: {e}")

async def test_deepseek():
    try:
        from openai import OpenAI
        key = os.getenv("DEEPSEEK_API_KEY_1")
        if not key or "paste" in key:
            print("  DeepSeek  MISSING KEY")
            return
        client = OpenAI(
            api_key=key,
            base_url="https://api.deepseek.com"
        )
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": "say hi"}],
            max_tokens=5
        )
        print("  DeepSeek")
    except Exception as e:
        print(f"  DeepSeek  ERROR: {e}")

async def test_env_keys():
    print("  Checking .env keys...")
    keys = [
        "GROQ_API_KEY_1",
        "GEMINI_API_KEY_1",
        "DEEPSEEK_API_KEY_1",
        "DATABASE_URL",
        "REDIS_URL",
        "GITHUB_TOKEN",
        "SECRET_KEY",
    ]
    all_good = True
    for k in keys:
        val = os.getenv(k)
        if val and "paste" not in val and len(val) > 5:
            print(f"    OK  {k}")
        else:
            print(f"    MISSING  {k}")
            all_good = False
    return all_good

async def main():
    print()
    print("=" * 50)
    print("  SENTINEL AI — CONNECTION TEST")
    print("=" * 50)
    print()

    print("[ 1 ] Environment Variables")
    await test_env_keys()
    print()

    print("[ 2 ] Database & Cache")
    await test_supabase()
    await test_redis()
    print()

    print("[ 3 ] LLM APIs")
    await test_groq()
    await test_gemini()
    await test_deepseek()
    print()

    print("=" * 50)
    print("  TEST COMPLETE")
    print("  Any ERROR above = paste it in Discord")
    print("=" * 50)
    print()

asyncio.run(main())