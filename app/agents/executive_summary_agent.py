import httpx
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from app.models.executive_summary import ExecutiveSummary
from app.core.utils import sanitize_text, sanitize_for_json

# HTTP client with timeout
ollama_http_client = httpx.AsyncClient(
    timeout=httpx.Timeout(
        connect=10.0,
        read=300.0,
        write=30.0,
        pool=10.0,
    )
)

ollama_provider = OpenAIProvider(
    base_url="http://127.0.0.1:11434/v1/",
    api_key="ollama",
    http_client=ollama_http_client,
)

local_model = OpenAIChatModel(
    model_name="qwen3:4b",
    provider=ollama_provider,
)

SYSTEM_PROMPT = """
You are a Senior SOC Manager.
Generate an executive summary for security leadership.
Do NOT explain technical payloads.
Summarize:
- Overall security posture
- Number of incidents
- Overall business risk
- Key attack trends
- Immediate actions
Return ONLY structured output.

/no_think
"""

executive_summary_agent = Agent(
    model=local_model,
    output_type=ExecutiveSummary,
    system_prompt=SYSTEM_PROMPT,
)


# Override the run method to include sanitization
original_run = executive_summary_agent.run


def sanitized_run(prompt: str):
    """Run the agent with sanitized prompt."""
    sanitized_prompt = sanitize_text(prompt)
    return original_run(sanitized_prompt)


executive_summary_agent.run = sanitized_run
