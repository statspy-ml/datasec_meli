# TODO:  ainda não implementado. Preferi seguir com anthropic por enquanto.

import os

import openai
from loguru import logger


class OpenAIClient:
    """OpenAI client similar to DirectAnthropicClient"""

    def __init__(self, temperature: float = 0.3, model: str = "gpt-4"):
        self.temperature = temperature
        self.model = model
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise Exception("OPENAI_API_KEY not found in environment")

        try:
            openai.api_key = api_key
            self.client = openai
            logger.info("OpenAI client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise

    def invoke(self, prompt: str, max_tokens: int = 2000) -> str:
        """Invoke OpenAI API"""
        try:
            response = self.client.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=self.temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            raise
