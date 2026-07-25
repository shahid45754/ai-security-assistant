import httpx
import json
import asyncio
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from app.models.response import IncidentAnalysis
from app.core.prompts import SYSTEM_PROMPT
from app.core.utils import sanitize_text, sanitize_for_json, remove_control_chars

# Ollama HTTP client with timeout
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

security_agent = Agent(
    model=local_model,
    output_type=IncidentAnalysis,
    system_prompt=SYSTEM_PROMPT,
)


# Override the run method to include sanitization
original_run = security_agent.run


def sanitized_run(prompt: str):
    """Run the agent with sanitized prompt."""
    # Sanitize the prompt
    sanitized_prompt = sanitize_text(prompt)
    sanitized_prompt = remove_control_chars(sanitized_prompt)
    
    # If the prompt is too long, truncate it
    if len(sanitized_prompt) > 4000:
        sanitized_prompt = sanitized_prompt[:4000] + "..."
    
    return original_run(sanitized_prompt)


def sanitized_run_sync(prompt: str):
    """Run the agent synchronously with sanitized prompt."""
    # Sanitize the prompt
    sanitized_prompt = sanitize_text(prompt)
    sanitized_prompt = remove_control_chars(sanitized_prompt)
    
    # If the prompt is too long, truncate it
    if len(sanitized_prompt) > 4000:
        sanitized_prompt = sanitized_prompt[:4000] + "..."
    
    # Run the agent synchronously
    try:
        # Try to get the current event loop
        try:
            loop = asyncio.get_running_loop()
            # If we're in a running loop, we need to handle it differently
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: asyncio.run(original_run(sanitized_prompt)))
                return future.result()
        except RuntimeError:
            # No running loop, create a new one
            return asyncio.run(original_run(sanitized_prompt))
    except Exception as e:
        print(f"❌ Error running agent synchronously: {e}")
        # Fallback to a simple sync call
        return original_run(sanitized_prompt)


# Replace the run method with the sanitized version
security_agent.run = sanitized_run
security_agent.run_sync = sanitized_run_sync
