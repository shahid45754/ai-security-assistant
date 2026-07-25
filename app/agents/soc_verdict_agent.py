import httpx
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from app.models.verdict import SOCVerdict
from app.core.prompts import SOC_VERDICT_PROMPT
from app.core.utils import sanitize_text, sanitize_for_json

# HTTP client with timeout
ollama_http_client = httpx.AsyncClient(
    timeout=httpx.Timeout(
        connect=10.0,
        read=900.0,
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

soc_verdict_agent = Agent(
    model=local_model,
    output_type=SOCVerdict,
    system_prompt=SOC_VERDICT_PROMPT,
)


# Override the run method to include sanitization
original_run = soc_verdict_agent.run


def sanitized_run(prompt: str):
    """Run the agent with sanitized prompt."""
    sanitized_prompt = sanitize_text(prompt)
    return original_run(sanitized_prompt)


soc_verdict_agent.run = sanitized_run
