"""AI / LLM service catalog: recognise generative-AI traffic from names (TLS SNI, QUIC SNI, DNS, HTTP Host,
certificate CN/SAN) and from API request shapes (OpenAI-compatible, Anthropic, Gemini, Ollama, MCP, inference
servers over gRPC)."""
from __future__ import annotations

import re

# (provider, category, suffix patterns). Category: "LLM API", "Chat assistant", "Coding assistant", "Model hub",
# "AI search", "Inference platform".
CATALOG = [
    ("OpenAI", "LLM API", ("api.openai.com",)),
    ("OpenAI ChatGPT", "Chat assistant", ("chatgpt.com", "chat.openai.com", "oaiusercontent.com", "oaistatic.com", "sora.com")),
    ("Anthropic", "LLM API", ("api.anthropic.com",)),
    ("Anthropic Claude", "Chat assistant", ("claude.ai", "claude.com", "claudeusercontent.com")),
    ("Google Gemini API", "LLM API", ("generativelanguage.googleapis.com",)),
    ("Google Vertex AI", "LLM API", ("aiplatform.googleapis.com",)),
    ("Google Gemini", "Chat assistant", ("gemini.google.com", "bard.google.com", "aistudio.google.com", "notebooklm.google.com")),
    ("Azure OpenAI", "LLM API", ("openai.azure.com", "cognitiveservices.azure.com", "services.ai.azure.com", "models.ai.azure.com")),
    ("Microsoft Copilot", "Chat assistant", ("copilot.microsoft.com", "copilot.cloud.microsoft", "sydney.bing.com")),
    ("GitHub Copilot", "Coding assistant", ("githubcopilot.com", "copilot-proxy.githubusercontent.com",
                                            "copilot-telemetry.githubusercontent.com")),
    ("AWS Bedrock", "LLM API", (re.compile(r"(^|\.)bedrock(-runtime|-agent-runtime)?(-fips)?\.[a-z0-9-]+\.amazonaws\.com$"),)),
    ("Mistral AI", "LLM API", ("api.mistral.ai", "codestral.mistral.ai")),
    ("Mistral Le Chat", "Chat assistant", ("chat.mistral.ai",)),
    ("Cohere", "LLM API", ("api.cohere.ai", "api.cohere.com")),
    ("Hugging Face", "Model hub", ("huggingface.co", "hf.co", "hf.space", "cdn-lfs.huggingface.co")),
    ("Perplexity", "AI search", ("perplexity.ai",)),
    ("DeepSeek", "Chat assistant", ("deepseek.com",)),
    ("xAI Grok", "Chat assistant", ("x.ai", "grok.com")),
    ("Groq", "Inference platform", ("api.groq.com", "groq.com")),
    ("Together AI", "Inference platform", ("together.xyz", "together.ai")),
    ("Fireworks AI", "Inference platform", ("fireworks.ai",)),
    ("Replicate", "Inference platform", ("replicate.com", "replicate.delivery")),
    ("OpenRouter", "Inference platform", ("openrouter.ai",)),
    ("Meta AI", "Chat assistant", ("meta.ai",)),
    ("Character.AI", "Chat assistant", ("character.ai",)),
    ("Cursor", "Coding assistant", ("cursor.sh", "cursor.com", "cursorapi.com")),
    ("Codeium / Windsurf", "Coding assistant", ("codeium.com", "windsurf.com")),
    ("Tabnine", "Coding assistant", ("tabnine.com",)),
]
# OpenAI-compatible and vendor API paths (cleartext or decrypted HTTP)
API_PATHS = [
    (re.compile(r"^/(v\d+/)?chat/completions"), "chat.completions"), (re.compile(r"^/(v\d+/)?completions"), "completions"),
    (re.compile(r"^/(v\d+/)?embeddings"), "embeddings"), (re.compile(r"^/(v\d+/)?responses"), "responses"),
    (re.compile(r"^/v1/messages"), "anthropic.messages"), (re.compile(r":(stream)?[gG]enerateContent"), "gemini.generateContent"),
    (re.compile(r"^/api/(generate|chat|embed|embeddings)\b"), "ollama"), (re.compile(r"^/v2/models/[^/]+(/versions/[^/]+)?/infer"), "kserve.infer"),
    (re.compile(r"^/(v\d+/)?images/generations"), "images"), (re.compile(r"^/(v\d+/)?audio/(transcriptions|speech)"), "audio"),
    (re.compile(r"/invoke(-with-response-stream)?$"), "bedrock.invoke"), (re.compile(r"/converse(-stream)?$"), "bedrock.converse"),
]
GRPC_INFERENCE = {"inference.GRPCInferenceService": "Triton / KServe v2", "tensorflow.serving.PredictionService": "TensorFlow Serving",
                  "vllm": "vLLM", "tritonserver": "Triton"}
LOCAL_PORTS = {11434: "Ollama", 1234: "LM Studio", 8080: None, 8000: None, 5000: None, 7860: "Gradio", 3000: None}
MCP_METHODS = ("initialize", "tools/list", "tools/call", "resources/list", "resources/read", "prompts/list", "prompts/get",
               "notifications/initialized", "sampling/createMessage")
_MCP = re.compile(r'"jsonrpc"\s*:\s*"2\.0".*?"method"\s*:\s*"([a-z/_A-Z]+)"', re.S)


def match(name: str | None):
    """(provider, category) for a host name, or None."""
    if not name:
        return None
    n = name.lower().rstrip(".")
    for provider, cat, pats in CATALOG:
        for pat in pats:
            if isinstance(pat, str):
                if n == pat or n.endswith("." + pat):
                    return provider, cat
            elif pat.search(n):
                return provider, cat
    return None


def api_kind(path: str | None) -> str | None:
    if not path:
        return None
    for rx, kind in API_PATHS:
        if rx.search(path):
            return kind
    return None


def mcp_method(body: str | None) -> str | None:
    m = _MCP.search(body or "")
    return m.group(1) if m and m.group(1) in MCP_METHODS else None


def grpc_inference(path: str | None) -> str | None:
    svc = (path or "").lstrip("/").split("/", 1)[0]
    return next((v for k, v in GRPC_INFERENCE.items() if svc.startswith(k)), None)
