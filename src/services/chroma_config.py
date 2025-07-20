import os
import warnings
import logging

def configure_chroma_silent():
    """Configure ChromaDB to run silently"""
    
    # Suppress ChromaDB telemetry warnings
    os.environ["ANONYMIZED_TELEMETRY"] = "False"
    os.environ["CHROMA_TELEMETRY"] = "False"
    
    # Suppress HuggingFace warnings
    os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    
    # Configure logging levels
    logging.getLogger("chromadb").setLevel(logging.ERROR)
    logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
    logging.getLogger("transformers").setLevel(logging.ERROR)
    logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
    
    # Suppress specific warnings
    warnings.filterwarnings("ignore", category=FutureWarning, module="huggingface_hub")
    warnings.filterwarnings("ignore", category=UserWarning, module="chromadb")
    warnings.filterwarnings("ignore", message=".*resume_download.*")
    warnings.filterwarnings("ignore", message=".*telemetry.*")