import os
from typing import Optional
from langchain_anthropic import ChatAnthropic
from loguru import logger

def create_anthropic_client(temperature: float = 0.3, model: str = "claude-3-sonnet-20240229") -> Optional[ChatAnthropic]:
    """Create Anthropic client with fallback options"""
    
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not found in environment")
        return None
    
    # Try different initialization methods
    init_methods = [
        # Method 1: New style
        lambda: ChatAnthropic(
            model=model,
            temperature=temperature,
            anthropic_api_key=api_key
        ),
        # Method 2: Old style  
        lambda: ChatAnthropic(
            model=model,
            temperature=temperature,
            api_key=api_key
        ),
        # Method 3: Environment variable only
        lambda: ChatAnthropic(
            model=model,
            temperature=temperature
        )
    ]
    
    for i, method in enumerate(init_methods, 1):
        try:
            client = method()
            logger.info(f"ChatAnthropic initialized successfully (method {i})")
            return client
        except Exception as e:
            logger.warning(f"ChatAnthropic init method {i} failed: {e}")
            continue
    
    logger.error("All ChatAnthropic initialization methods failed")
    return None

def test_anthropic_client(client: ChatAnthropic) -> bool:
    """Test if the Anthropic client works"""
    try:
        response = client.invoke("Hello, respond with just 'OK'")
        return "OK" in str(response.content)
    except Exception as e:
        logger.error(f"Anthropic client test failed: {e}")
        return False