#!/usr/bin/env python3
"""FastAPI Main Application for DataSec Challenge"""

import json
import uuid
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Suprimir warnings do Pydantic
warnings.filterwarnings("ignore", "Pydantic serializer warnings")

# Import project modules
from src.agents.orchestrator_agent import OrchestratorAgent
from src.database_init import init_db
from src.services.logging_service import LoggingService

# Initialize FastAPI app
app = FastAPI(
    title="DataSec Challenge API",
    description="Multi-Agent Security Analysis System with Community MITRE ATT&CK MCP",
    version="1.0.0",
)


@app.on_event("startup")
async def startup_event():
    """Initialize database on application startup"""
    try:
        success = await init_db()
        if success:
            print("Database initialized successfully")
        else:
            print("Database initialization failed")
            raise Exception("Database initialization failed")
    except Exception as e:
        print(f"Error during startup: {e}")
        raise


# Create necessary directories
Path("logs").mkdir(exist_ok=True)
Path("results").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("data/mitre-attack").mkdir(exist_ok=True)


class SecurityAnalysisRequest(BaseModel):
    ecosystem_description: str
    additional_context: Optional[Dict[str, Any]] = None
    scenario_name: str = "custom"


class SecurityAnalysisResponse(BaseModel):
    session_id: str
    status: str
    report: Dict[str, Any]
    message: str


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "DataSec Challenge API",
        "version": "1.0.0",
        "status": "running",
        "features": [
            "Multi-Agent Security Analysis",
            "Community MITRE ATT&CK MCP Integration",
            "Automated Risk Assessment",
            "Detection Engineering",
        ],
    }


@app.get("/health")  # TODO: implementar health ; despriorizado por falta de tempo
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "community_mcp": "integrated",
        "timestamp": "2025-01-01T00:00:00Z",
    }


@app.post("/analyze")
async def analyze_security(request: SecurityAnalysisRequest):
    """Perform security analysis using multi-agent system"""
    try:
        session_id = str(uuid.uuid4())
        logging_service = LoggingService()
        logging_service.create_session(
            session_id,
            {
                "scenario": request.scenario_name,
                "timestamp": "2025-01-01T00:00:00Z",
            },
        )

        orchestrator = OrchestratorAgent(session_id)
        orchestrator.initialize_agents()

        result = await orchestrator.process_user_input(request.ecosystem_description)

        # Save result
        output_file = f"results/analysis_{request.scenario_name}_{session_id[:8]}.json"

        response_data = {
            "session_id": session_id,
            "scenario": request.scenario_name,
            "input": request.ecosystem_description,
            "result": result,
            "additional_context": request.additional_context or {},
            "timestamp": "2025-01-01T00:00:00Z",
        }

        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(
                response_data, f, indent=2, ensure_ascii=False, default=json_serializer
            )

        def clean_for_json(obj):
            """Remove objetos não serializáveis recursivamente"""
            from enum import Enum

            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, dict):
                cleaned_dict = {}
                for k, v in obj.items():
                    if not k.startswith("_") and k != "__objclass__":
                        cleaned_dict[k] = clean_for_json(v)
                return cleaned_dict
            if isinstance(obj, list):
                return [clean_for_json(item) for item in obj]
            if hasattr(obj, "__dict__"):
                try:
                    if hasattr(obj, "model_dump"):
                        return clean_for_json(obj.model_dump())
                    if hasattr(obj, "dict"):
                        return clean_for_json(obj.dict())
                    clean_dict = {}
                    for k, v in obj.__dict__.items():
                        if not k.startswith("_"):
                            clean_dict[k] = clean_for_json(v)
                    return clean_dict
                except:
                    return str(obj)
            elif str(type(obj)).startswith("<"):
                return str(obj)
            else:
                return obj

        clean_result = clean_for_json(result)

        return {
            "session_id": session_id,
            "status": "completed",
            "report": clean_result,
            "message": f"Analysis completed successfully. Results saved to {output_file}",
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {e!s}",
        )


@app.get("/session/{session_id}/logs")
async def get_session_logs(session_id: str):
    """Get logs for a specific session"""
    try:
        logging_service = LoggingService()
        logs = logging_service.get_session_logs(session_id)

        return {
            "session_id": session_id,
            "logs": logs,
            "summary": {
                "interactions": len(logs.get("interactions", [])),
                "decisions": len(logs.get("decisions", [])),
            },
        }
    except Exception as e:
        raise HTTPException(
            status_code=404,
            detail=f"Session not found or error retrieving logs: {e!s}",
        )


@app.get("/mitre/status")
async def mitre_status():
    """Get MITRE ATT&CK Community MCP status"""
    try:
        from src.services.mitre_service import MitreService

        mitre_service = MitreService()

        stats = mitre_service.get_statistics()

        return {
            "community_mcp_available": mitre_service.community_mcp.is_available(),
            "community_mcp_info": mitre_service.community_mcp.get_server_info(),
            "mitre_statistics": stats,
        }
    except Exception as e:
        return {
            "error": f"Failed to get MITRE status: {e!s}",
            "community_mcp_available": False,
        }


@app.post("/test-request")
async def test_request(request: SecurityAnalysisRequest):
    """Test endpoint to verify request parsing"""
    return {
        "status": "request_parsed_successfully",
        "ecosystem_description": request.ecosystem_description[:100] + "..."
        if len(request.ecosystem_description) > 100
        else request.ecosystem_description,
        "additional_context": request.additional_context,
        "scenario_name": request.scenario_name,
        "test_datetime": datetime.now().isoformat(),
        "test_timestamp": "2025-01-01T00:00:00Z",
    }


@app.get("/test-serialization")
async def test_serialization():
    """Test JSON serialization with datetime objects"""
    from enum import Enum

    # Simular enum Priority
    class Priority(Enum):
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"

    test_data = {
        "current_time": datetime.now(),
        "iso_time": datetime.now().isoformat(),
        "sample_priority": Priority.HIGH,
        "sample_technique": {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "description": "Test technique",
            "tactics": ["initial-access"],
            "platforms": ["windows"],
        },
        "nested_datetime": {
            "created_at": datetime.now(),
            "data": ["test1", "test2"],
        },
        "complex_priority": {
            "priority": Priority.HIGH,
            "nested": {
                "another_priority": Priority.MEDIUM,
                "timestamp": datetime.now(),
            },
        },
    }

    def clean_for_json(obj):
        from enum import Enum

        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, dict):
            cleaned_dict = {}
            for k, v in obj.items():
                if not k.startswith("_") and k != "__objclass__":
                    cleaned_dict[k] = clean_for_json(v)
            return cleaned_dict
        if isinstance(obj, list):
            return [clean_for_json(item) for item in obj]
        if hasattr(obj, "__dict__"):
            try:
                if hasattr(obj, "model_dump"):
                    return clean_for_json(obj.model_dump())
                if hasattr(obj, "dict"):
                    return clean_for_json(obj.dict())
                clean_dict = {}
                for k, v in obj.__dict__.items():
                    if not k.startswith("_"):
                        clean_dict[k] = clean_for_json(v)
                return clean_dict
            except:
                return str(obj)
        elif str(type(obj)).startswith("<"):
            return str(obj)
        else:
            return obj

    clean_data = clean_for_json(test_data)

    return {
        "status": "serialization_test_successful",
        "data": clean_data,
        "original_types": {
            "current_time": str(type(test_data["current_time"])),
            "sample_priority": str(type(test_data["sample_priority"])),
            "complex_priority": str(type(test_data["complex_priority"]["priority"])),
        },
        "cleaned_types": {
            "current_time": str(type(clean_data["current_time"])),
            "sample_priority": str(type(clean_data["sample_priority"])),
            "complex_priority": str(type(clean_data["complex_priority"]["priority"])),
        },
    }


@app.get("/examples")
async def get_examples():
    """Get example system descriptions for testing"""
    return {
        "examples": {
            "ecommerce": """
            Temos uma plataforma de e-commerce com arquitetura de microserviços rodando na AWS.
            O sistema possui:
            - API Gateway para roteamento
            - 15 microserviços em containers Docker
            - Base de dados PostgreSQL e Redis
            - Sistema de pagamentos integrado com Stripe
            - Frontend React.js
            - Autenticação via JWT
            - Processamento de dados sensíveis (PII, cartões de crédito)
            - Compliance com PCI-DSS
            """,
            "fintech": """
            Aplicação fintech para transferências bancárias com as seguintes características:
            - Backend em Python/Django
            - API REST para aplicações mobile (iOS/Android)
            - Banco de dados MySQL com dados financeiros sensíveis
            - Integração com APIs de bancos via Open Banking
            - Sistema de KYC (Know Your Customer)
            - Compliance com LGPD e normas do Banco Central
            """,
            "healthcare": """
            Sistema de gestão hospitalar com:
            - Aplicação web monolítica em Java/Spring
            - Base de dados Oracle com registros médicos
            - Integração com equipamentos médicos via HL7
            - Portal do paciente para acesso a exames
            - Conformidade com HIPAA e LGPD  
            """,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
