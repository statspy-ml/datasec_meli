from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import uuid

class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    ANALYZER = "analyzer"
    RISK_ASSESSOR = "risk_assessor"
    REPORT_GENERATOR = "report_generator"

class MitreAttackTechnique(BaseModel):
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    
    class Config:
        """Pydantic config for JSON serialization"""
        json_encoders = {
            # Add any custom encoders if needed
        }

class SecurityDetector(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    priority: Priority
    mitre_techniques: List[MitreAttackTechnique] = []
    risk_score: float = Field(ge=0.0, le=10.0)
    impact_level: str
    implementation_effort: str
    rationale: str

class EcosystemContext(BaseModel):
    description: str
    technologies: List[str] = []
    architecture_type: str
    security_controls: List[str] = []
    data_sensitivity: str
    compliance_requirements: List[str] = []

class AgentMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    from_agent: AgentRole
    to_agent: Optional[AgentRole] = None
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)

class SecurityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    ecosystem_context: EcosystemContext
    priority_detectors: List[SecurityDetector]
    executive_summary: str
    implementation_roadmap: List[Dict[str, Any]]
    created_at: datetime = Field(default_factory=datetime.now)