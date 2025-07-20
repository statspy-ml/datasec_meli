import os
import json
from typing import Dict, Any, Optional
import anthropic
from loguru import logger

class DirectAnthropicClient:
    """Direct Anthropic client without LangChain dependencies"""
    
    def __init__(self, temperature: float = 0.3):
        self.temperature = temperature
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise Exception("ANTHROPIC_API_KEY not found in environment")
        
        try:
            self.client = anthropic.Anthropic(api_key=api_key)
            logger.info("Direct Anthropic client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            raise
    
    def invoke(self, prompt: str, max_tokens: int = 2000) -> str:
        """Invoke Anthropic API directly"""
        try:
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=max_tokens,
                temperature=self.temperature,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract content from response
            if response.content and len(response.content) > 0:
                return response.content[0].text
            else:
                return ""
                
        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise
    
    def format_and_invoke(self, template: str, **kwargs) -> str:
        """Format template and invoke"""
        try:
            formatted_prompt = template.format(**kwargs)
            return self.invoke(formatted_prompt)
        except Exception as e:
            logger.error(f"Template formatting or API call failed: {e}")
            raise