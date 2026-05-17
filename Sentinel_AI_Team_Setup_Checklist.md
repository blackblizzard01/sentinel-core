# SENTINEL AI — TEAM SETUP CHECKLIST
# ============================================================
# Every teammate completes this BEFORE the first line of code.
# Go top to bottom. Do not skip steps.
# Post in Discord when fully done: "SETUP COMPLETE ✅ [name]"
# ============================================================

---

## PART 1 — INSTALLS
Do these in order. Verify each before moving on.

### 1. Git
- Download: git-scm.com/downloads
- Verify: open terminal → git --version
- Should show: git version 2.x.x

### 2. Python 3.11
- Download: python.org/downloads
- Windows: check "Add to PATH" during install
- Verify: python --version
- Should show: Python 3.11.x

### 3. Node.js 20
- Download: nodejs.org (LTS version)
- Verify: node --version
- Should show: v20.x.x

### 4. Cursor
- Download: cursor.com
- Sign up with GitHub account
- Verify: opens without error

### 5. Ollama
- Download: ollama.com
- After install open terminal and run:
  ollama pull mistral
- Verify: ollama list
- Should show mistral in the list

### 6. VS Code (optional but recommended)
- Download: code.visualstudio.com
- Install these extensions inside VS Code:
  → Live Share (Microsoft)
  → Python (Microsoft)
  → Pylance (Microsoft)
  → GitLens
  → Thunder Client

---

## PART 2 — ACCOUNTS
Create all of these. Takes 15 minutes total.

### 1. GitHub
- Sign up: github.com
- Use your college email
- After signup: education.github.com/pack
  → Apply for Student Developer Pack
  → Gets you: free Copilot, cloud credits, domain

### 2. Groq
- Sign up: console.groq.com
- No credit card needed
- Go to API Keys → Create new key
- Save the key somewhere safe

### 3. Anthropic
- Sign up: console.anthropic.com
- Get $5 free credit on signup
- Go to API Keys → Create new key
- Save the key somewhere safe

### 4. OpenAI
- Sign up: platform.openai.com
- Get $5 free credit on signup
- Go to API Keys → Create new key
- Save the key somewhere safe

### 5. Supabase (PostgreSQL)
- Sign up: supabase.com
- Use GitHub login
- No setup needed yet — just create account

### 6. Upstash (Redis)
- Sign up: upstash.com
- Use GitHub login
- No setup needed yet — just create account

### 7. Vercel (Frontend hosting)
- Sign up: vercel.com
- Use GitHub login

### 8. Railway (Backend hosting)
- Sign up: railway.app
- Use GitHub login

### 9. Sentry (Error monitoring)
- Sign up: sentry.io
- Use GitHub login

### 10. Doppler (Secrets management)
- Sign up: doppler.com
- Use GitHub login
- Wait for team invite from founder

---

## PART 3 — REPO SETUP
Do this after founder confirms repo is live on GitHub.

### 1. Accept GitHub org invite
- Check email for invite from sentinel-ai org
- Accept it

### 2. Clone the repo
```
git clone https://github.com/sentinel-ai/sentinel-core
cd sentinel-core
```

### 3. Create virtual environment
```
python -m venv venv
```

### 4. Activate virtual environment
```
Windows:   venv\Scripts\activate
Mac/Linux: source venv/bin/activate
```
- Verify: terminal prompt shows (venv)

### 5. Install dependencies
```
pip install -r requirements.txt
```
- This takes 3-5 minutes
- Wait for it to finish completely

### 6. Verify all packages installed
```
python -c "import fastapi, langchain, chromadb, groq, anthropic, openai"
```
- Should print nothing
- No output = success
- If error: paste in Discord #errors-help

### 7. Set up environment file
```
cp .env.example .env
```
- Open .env in any text editor
- Fill in your API keys:
  GROQ_API_KEY=your key here
  ANTHROPIC_API_KEY=your key here
  OPENAI_API_KEY=your key here
- Leave DATABASE_URL and REDIS_URL blank for now
- Founder will share these via Doppler

### 8. Verify .env is working
```
python -c "
from dotenv import load_dotenv
import os
load_dotenv()
print('Groq key:', 'SET' if os.getenv('GROQ_API_KEY') else 'MISSING')
print('Anthropic key:', 'SET' if os.getenv('ANTHROPIC_API_KEY') else 'MISSING')
print('OpenAI key:', 'SET' if os.getenv('OPENAI_API_KEY') else 'MISSING')
"
```
- All three should print SET

---

## PART 4 — CURSOR SETUP
Do this after repo is cloned.

### 1. Open Cursor
### 2. Open the sentinel-core folder in Cursor
- File → Open Folder → select sentinel-core

### 3. Set Project Rules
- Mac: Cursor → Settings → Project Rules
- Windows: File → Preferences → Cursor Settings → Project Rules
- Click Add Rule
- Paste the ENTIRE content of .cursorrules file
- Save

### 4. Add Anthropic API key to Cursor
- Cursor Settings → Models
- Add API key for Anthropic
- Select claude-sonnet as default model

### 5. Verify Cursor has context
- Open any .py file
- Press Ctrl+K (or Cmd+K on Mac)
- Type: what project are we building
- Cursor should respond mentioning Sentinel AI
- If it responds generically: project rules not set correctly

---

## PART 5 — TEAM TOOLS SETUP

### 1. Join Discord server
- Click invite link shared by founder
- Introduce yourself in #general
- Read pinned messages

### 2. Join Notion workspace
- Click invite link shared by founder
- Read the Build Board
- Read the Cursor Prompts page
- Read the Project Bible page

### 3. Join Doppler
- Click invite link shared by founder
- Accept invite
- Install Doppler CLI:
  Mac:     brew install dopplerhq/cli/doppler
  Windows: scoop install doppler
  Linux:   see doppler.com/docs/cli/installation
- Login: doppler login
- Setup: doppler setup → select sentinel-core → development

### 4. Save the Project Bible
- Open Notion → Project Bible page
- Copy the full content
- Save it somewhere you can access quickly
  (Notion bookmark, browser bookmark, Notes app)
- You will paste this at the start of EVERY Claude chat

---

## PART 6 — FINAL VERIFICATION
Run all of this before posting setup complete.

```
# 1. Python version
python --version
# Must show 3.11.x

# 2. All packages
python -c "import fastapi, langchain, chromadb, groq, anthropic, openai; print('All packages OK')"
# Must print: All packages OK

# 3. API keys
python -c "
from dotenv import load_dotenv; import os; load_dotenv()
keys = ['GROQ_API_KEY','ANTHROPIC_API_KEY','OPENAI_API_KEY']
[print(k, '✅') if os.getenv(k) else print(k, '❌ MISSING') for k in keys]
"
# All three must show ✅

# 4. Ollama
ollama list
# Must show mistral

# 5. Node
node --version
# Must show v20.x.x

# 6. Git
git status
# Must show: On branch main (or your branch)
```

---

## PART 7 — POST IN DISCORD
When every single item above is done, post this in #general:

```
SETUP COMPLETE ✅
Name: [your name]
Module: [your module — Orchestrator/Attack/KB/Frontend]
Python: [version]
All packages: ✅
API keys: ✅
Ollama: ✅
Cursor rules: ✅
Ready to build 🚀
```

---

## COMMON ERRORS AND FIXES

### "python not found" on Windows
→ Reinstall Python, check "Add to PATH" during install
→ Restart terminal after install

### "pip install fails on some packages"
→ Make sure venv is activated (see (venv) in terminal)
→ Try: pip install --upgrade pip first
→ Then retry: pip install -r requirements.txt

### "import chromadb fails"
→ pip install chromadb --upgrade

### "Cursor project rules not working"
→ Close and reopen Cursor completely
→ Make sure sentinel-core folder is open, not a subfolder

### "ollama pull mistral hangs"
→ Mistral is ~4GB, takes time on slow internet
→ Leave it running, do other setup steps meanwhile

### "git clone fails"
→ Make sure you accepted the GitHub org invite
→ Try: git clone with HTTPS not SSH

---

## RULES EVERYONE MUST FOLLOW FROM DAY 1

1. NEVER commit .env to GitHub
2. NEVER share API keys in WhatsApp or Discord
   → Use Doppler for all secret sharing
3. NEVER push directly to main branch
   → Always create a branch and open a PR
4. NEVER hardcode any value that exists in constants.py
5. Post a handoff note in #handoffs Discord channel
   whenever you stop working midway on a task
6. Run your code before opening a PR
   → If it errors on your machine it will error on everyone's
7. Paste Project Bible at start of EVERY new Claude chat
