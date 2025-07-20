import json
import os
from typing import Any, Dict, List, Optional

from loguru import logger

from src.agents.base_agent import BaseAgent
from src.models.base import AgentMessage, AgentRole, EcosystemContext, SecurityDetector
from src.services.dbir_service import DBIRService
from src.utils.direct_anthropic import DirectAnthropicClient

try:
    from src.services.rag_service import RAGService
except ImportError:
    from src.services.rag_service_simple import RAGServiceSimple as RAGService

class AnalyzerAgent(BaseAgent):
    def __init__(self, session_id: str):
        super().__init__(AgentRole.ANALYZER, session_id)
        self.dbir_service = DBIRService()
        self.rag_service = RAGService()
        self.llm = DirectAnthropicClient(temperature=0.3)

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process incoming messages"""
        if message.message_type == "analyze_ecosystem":
            return await self._analyze_ecosystem(message)
        if message.message_type == "identify_detectors":
            return await self._identify_detectors(message)

        return None

    async def _analyze_ecosystem(self, message: AgentMessage) -> AgentMessage:
        """Analyze ecosystem context from description"""
        description = message.content["description"]

        prompt_template = """
        Analyze the following system description and extract structured information:
        
        Description: {description}
        
        Extract and return JSON with:
        - technologies: List of technologies mentioned
        - architecture_type: Type of architecture (monolith, microservices, serverless, etc.)
        - security_controls: Current security controls mentioned
        - data_sensitivity: Level of data sensitivity (low, medium, high)
        - compliance_requirements: Any compliance requirements mentioned
        
        Return only valid JSON:
        """

        response = self.llm.format_and_invoke(prompt_template, description=description)

        try:
            parsed_context = json.loads(response)
            parsed_context.setdefault("architecture_type", "unknown")
            parsed_context.setdefault("technologies", [])
            parsed_context.setdefault("security_controls", [])
            parsed_context.setdefault("data_sensitivity", "medium")
            parsed_context.setdefault("compliance_requirements", [])

            ecosystem_context = EcosystemContext(
                description=description,
                **parsed_context,
            )

            await self.log_decision(
                "ecosystem_analyzed",
                f"Successfully analyzed ecosystem with {len(parsed_context.get('technologies', []))} technologies",
                parsed_context,
            )

            return await self.send_message(
                message.from_agent,
                "ecosystem_analysis_complete",
                {"context": ecosystem_context.dict()},
            )
        except json.JSONDecodeError:
            await self.log_decision(
                "ecosystem_analysis_failed",
                "Failed to parse LLM response as JSON",
                {"raw_response": response},
            )

            basic_context = self._basic_ecosystem_analysis(description)
            ecosystem_context = EcosystemContext(**basic_context)
            return await self.send_message(
                message.from_agent,
                "ecosystem_analysis_complete",
                {"context": ecosystem_context.dict()},
            )

    async def _identify_detectors(self, message: AgentMessage) -> AgentMessage:
        """Identify priority detectors based on context and DBIR data"""
        context = EcosystemContext(**message.content["context"])

        dbir_insights = await self.dbir_service.get_relevant_threats(
            context.technologies,
            context.architecture_type,
        )

        similar_patterns = await self.rag_service.query_attack_patterns(
            context.description,
            top_k=10,
        )

        detectors = await self._generate_detector_recommendations(
            context, dbir_insights, similar_patterns,
        )

        await self.log_decision(
            "detectors_identified",
            f"Identified {len(detectors)} priority detectors",
            {"detector_count": len(detectors), "context_type": context.architecture_type},
        )

        # Convert detectors to serializable format
        detectors_dict = []
        for detector in detectors:
            detector_dict = detector.dict()
            # Convert MITRE techniques to dict if they exist
            if detector_dict.get("mitre_techniques"):
                detector_dict["mitre_techniques"] = [
                    t.dict() if hasattr(t, "dict") else t
                    for t in detector_dict["mitre_techniques"]
                ]
            detectors_dict.append(detector_dict)

        return await self.send_message(
            message.from_agent,
            "detectors_identified",
            {"detectors": detectors_dict},
        )

    async def _generate_detector_recommendations(self,
                                               context: EcosystemContext,
                                               dbir_insights: List[Dict],
                                               attack_patterns: List[Dict]) -> List[SecurityDetector]:
        """Generate detector recommendations using LLM"""
        prompt_template = """
        Based on the following information, recommend priority security detectors:
        
        System Context:
        {context}
        
        DBIR 2025 Relevant Threats:
        {dbir_insights}
        
        Similar Attack Patterns:
        {attack_patterns}
        
        You MUST respond with ONLY a valid JSON array containing 8-12 comprehensive security detectors. Do not include any explanatory text before or after the JSON.
        
        REQUIRED COVERAGE AREAS (include detectors for each):
        1. Authentication & Access Control
        2. API Security & Gateway Protection  
        3. Database Security & Data Protection
        4. Container & Kubernetes Security
        5. Network & Service Mesh Security
        6. Payment & Transaction Security (if applicable)
        7. Application Security & Code Protection
        8. Infrastructure & Cloud Security
        
        Format exactly like this:
        [
            {{
                "name": "Detector Name",
                "description": "What it detects",
                "priority": "high",
                "risk_score": 8.5,
                "impact_level": "high",
                "implementation_effort": "medium",
                "rationale": "Why this detector is important"
            }}
        ]
        
        Requirements:
        - risk_score must be a decimal number between 0.0-10.0 (e.g., 8.5, 9.2)
        - priority must be exactly "high", "medium", or "low"
        - impact_level must be exactly "critical", "high", "medium", or "low"
        - implementation_effort must be exactly "low", "medium", or "high"
        """

        response = self.llm.format_and_invoke(
            prompt_template,
            context=json.dumps(context.dict()),
            dbir_insights=json.dumps(dbir_insights[:3]),  # Limit context
            attack_patterns=json.dumps(attack_patterns[:5]),
        )

        logger.debug(f"LLM response for detector recommendations: {response[:500]}...")

        try:
            json_start = response.find("[")
            json_end = response.rfind("]") + 1

            if json_start >= 0 and json_end > json_start:
                json_response = response[json_start:json_end]
                detector_data = json.loads(json_response)
            else:
                # Fallback to parsing entire response
                detector_data = json.loads(response)

            detectors = []
            for d in detector_data:
                d_clean = d.copy()
                d_clean["mitre_techniques"] = []  # Will be populated later by RiskAssessor

                # Normalize risk_score if it's outside expected range
                risk_score = d_clean.get("risk_score", 5.0)
                if isinstance(risk_score, (int, float)) and risk_score > 10.0:
                    # Convert from 0-100 scale to 0-10 scale
                    d_clean["risk_score"] = min(10.0, risk_score / 10.0)
                    logger.debug(f"Normalized risk_score from {risk_score} to {d_clean['risk_score']}")

                detectors.append(SecurityDetector(**d_clean))
            return detectors
        except Exception as e:
            await self.log_decision(
                "detector_parsing_failed",
                f"Failed to parse detector recommendations: {e}",
                {"error": str(e), "response": response[:200]},
            )
            return self._get_default_detectors(context)

    def _basic_ecosystem_analysis(self, description: str) -> Dict[str, Any]:
        """Enhanced ecosystem analysis with architecture detection"""
        technologies = []
        architecture_type = "monolithic"  # Default
        deployment_type = "cloud"  # Default
        compliance_requirements = []
        data_sensitivity = "medium"

        description_lower = description.lower()

        tech_keywords = {
            "python": ["python", "django", "flask", "fastapi"],
            "javascript": ["javascript", "node.js", "react", "angular", "vue"],
            "java": ["java", "spring", "tomcat"],
            "web": ["web", "http", "html", "frontend"],
            "api": ["api", "rest", "graphql", "endpoint"],
            "database": ["database", "sql", "mysql", "postgres", "mongodb", "redis"],
            "cloud": ["aws", "azure", "gcp", "cloud"],
            "mobile": ["mobile", "ios", "android", "app"],
            "container": ["docker", "container"],
            "kubernetes": ["kubernetes", "k8s"],
            "celery": ["celery", "worker", "task queue"],
            "ml": ["machine learning", "ml", "ai", "model"],
            "payment": ["payment", "stripe", "paypal", "transaction"],
            "biometric": ["biometric", "fingerprint", "face recognition"],
        }

        for tech, terms in tech_keywords.items():
            if any(term in description_lower for term in terms):
                technologies.append(tech)

        # Architecture detection
        if any(term in description_lower for term in ["microservice", "service mesh", "15 microserviços"]):
            architecture_type = "microservices"
        elif any(term in description_lower for term in ["monolith", "django", "single application"]):
            architecture_type = "monolithic"
        elif "kubernetes" in description_lower or "container" in description_lower:
            architecture_type = "containerized"

        # Deployment detection
        if any(term in description_lower for term in ["on-premise", "on premise", "datacenter"]):
            deployment_type = "on-premise"
        elif any(term in description_lower for term in ["cloud", "aws", "azure", "gcp"]):
            deployment_type = "cloud"

        # Compliance detection
        if "pci" in description_lower:
            compliance_requirements.append("PCI-DSS")
        if "lgpd" in description_lower:
            compliance_requirements.append("LGPD")
        if "gdpr" in description_lower:
            compliance_requirements.append("GDPR")
        if "sox" in description_lower:
            compliance_requirements.append("SOX")
        if any(term in description_lower for term in ["banco central", "bacen", "financial regulation"]):
            compliance_requirements.append("Financial Regulation")

        # Data sensitivity detection
        if any(term in description_lower for term in ["credit card", "financial", "payment", "biometric", "pii"]):
            data_sensitivity = "high"
        elif any(term in description_lower for term in ["personal data", "user data", "customer"]):
            data_sensitivity = "medium"

        return {
            "description": description,
            "technologies": technologies,
            "architecture_type": architecture_type,
            "deployment_type": deployment_type,
            "security_controls": [],
            "data_sensitivity": data_sensitivity,
            "compliance_requirements": compliance_requirements,
        }

    def _get_default_detectors(self, context: EcosystemContext) -> List[SecurityDetector]:
        """Return adaptive default detectors based on context"""
        defaults = []

        defaults.extend([
            SecurityDetector(
                name="Unusual Login Patterns",
                description="Detect suspicious authentication attempts and credential stuffing",
                priority="high",
                risk_score=8.5,
                impact_level="high",
                implementation_effort="medium",
                rationale="Authentication attacks are common according to DBIR 2025",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="Data Exfiltration Detection",
                description="Monitor for unusual data access patterns and data transfer anomalies",
                priority="high",
                risk_score=9.2,
                impact_level="critical",
                implementation_effort="high",
                rationale="Data breaches have high impact on business and compliance",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="API Gateway Anomaly Detection",
                description="Detect API abuse, rate limiting violations, and injection attacks",
                priority="high",
                risk_score=8.8,
                impact_level="high",
                implementation_effort="medium",
                rationale="API attacks are prevalent in microservices architectures",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="Container Runtime Monitoring",
                description="Monitor for malicious container activity and escape attempts",
                priority="high",
                risk_score=8.0,
                impact_level="high",
                implementation_effort="medium",
                rationale="Container security is critical in Kubernetes environments",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="Database Anomaly Detection",
                description="Detect SQL injection, data harvesting, and unauthorized queries",
                priority="high",
                risk_score=8.7,
                impact_level="critical",
                implementation_effort="medium",
                rationale="Database attacks threaten core business data",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="Payment Fraud Detection",
                description="Monitor for fraudulent transactions and payment anomalies",
                priority="high",
                risk_score=9.5,
                impact_level="critical",
                implementation_effort="high",
                rationale="Payment fraud directly impacts business and PCI-DSS compliance",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="Service Mesh Security Monitoring",
                description="Monitor inter-service communication for suspicious patterns",
                priority="medium",
                risk_score=7.5,
                impact_level="high",
                implementation_effort="medium",
                rationale="Service-to-service attacks can bypass perimeter security",
                mitre_techniques=[],
            ),
            SecurityDetector(
                name="CDN and DDoS Protection",
                description="Detect DDoS attacks, content poisoning, and traffic anomalies",
                priority="medium",
                risk_score=7.8,
                impact_level="high",
                implementation_effort="low",
                rationale="CDN attacks can impact availability and content integrity",
                mitre_techniques=[],
            ),
        ])

        try:
            from src.agents.analyzer_agent_adaptive import get_adaptive_detectors
            adaptive_detectors = get_adaptive_detectors(context)
            return adaptive_detectors
        except ImportError:
            pass

        return defaults

