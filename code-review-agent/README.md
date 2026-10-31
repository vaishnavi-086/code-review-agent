# Multi-Agent Code Review & Security Scanner Pipeline

An automated AI-driven Static Application Security Testing (SAST) and Pull Request review pipeline powered by **Google GenAI SDK** and the **`gemini-2.5-flash`** model.

---

## 🏗️ Architecture: The 3 Agents

```
 ┌────────────────────────┐
 │  Target Source File    │
 │    (sample_code.py)    │
 └───────────┬────────────┘
             │
             ▼
 ┌────────────────────────┐
 │ Agent 1: Ingestion     │  • Reads file & simulates PR context
 │          Agent         │  • Validates AST syntax & lines
 └───────────┬────────────┘
             │ IngestedPayload
             ▼
 ┌────────────────────────┐
 │ Agent 2: Security &    │  • Analyzes vulnerabilities via Google GenAI SDK
 │     Bug Scanner Agent  │  • Model: gemini-2.5-flash
 │                        │  • Categorizes: Critical, High, Medium, Low
 └───────────┬────────────┘
             │ ScanResult
             ▼
 ┌────────────────────────┐
 │ Agent 3: Summarizer &  │  • Synthesizes findings
 │     Reporter Agent     │  • Generates GitHub PR review markdown
 └───────────┬────────────┘
             │
             ▼
 ┌────────────────────────┐
 │ pull_request_review.md │
 └────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install google-genai python-dotenv
```

### 2. Configure Environment Variables
Create a `.env` file in the root folder (or copy from `.env.example`):
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
```
> Get your API key from [Google AI Studio](https://aistudio.google.com/app/apikey).

### 3. Run the Pipeline
```bash
python pipeline.py
```

You can also specify a custom target file and custom output markdown:
```bash
python pipeline.py path/to/your_file.py my_review.md
```
