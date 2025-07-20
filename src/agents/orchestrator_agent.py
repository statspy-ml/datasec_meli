from typing import Dict, Any, List, Optional
from src.agents.base_agent import BaseAgent
from src.models.base import AgentMessage, AgentRole, EcosystemContext
from src.agents.analyzer_agent import AnalyzerAgent
from src.agents.risk_assessor_agent import RiskAssessorAgent
from src.agents.report_generator_agent import ReportGeneratorAgent
from src.utils.json_utils import make_json_serializable, convert_detector_for_json

class OrchestratorAgent(BaseAgent):
    def __init__(self, session_id: str):
        super().__init__(AgentRole.ORCHESTRATOR, session_id)
        self.agents = {}
        self.workflow_state = "initialized"
        
    def initialize_agents(self):
        """Initialize all specialized agents"""
        self.agents = {
            AgentRole.ANALYZER: AnalyzerAgent(self.session_id),
            AgentRole.RISK_ASSESSOR: RiskAssessorAgent(self.session_id),
            AgentRole.REPORT_GENERATOR: ReportGeneratorAgent(self.session_id)
        }
        
    async def process_user_input(self, ecosystem_description: str) -> Dict[str, Any]:
        """Main entry point for processing user input"""
        await self.log_decision(
            "start_analysis", 
            "Starting multi-agent security analysis",
            {"input_length": len(ecosystem_description)}
        )
        
        # Step 1: Parse and analyze ecosystem context
        ecosystem_context = await self._analyze_ecosystem(ecosystem_description)
        
        # Step 2: Identify priority detectors
        detectors = await self._identify_detectors(ecosystem_context)
        
        # Step 3: Assess risks and map to MITRE
        risk_analysis = await self._assess_risks(detectors, ecosystem_context)
        
        # Step 4: Generate final report
        report = await self._generate_report(ecosystem_context, risk_analysis)
        
        return report
    
    async def _analyze_ecosystem(self, description: str) -> EcosystemContext:
        """Analyze ecosystem using AnalyzerAgent"""
        message = await self.send_message(
            AgentRole.ANALYZER,
            "analyze_ecosystem",
            {"description": description}
        )
        
        # Route to actual agent
        if AgentRole.ANALYZER in self.agents:
            analyzer = self.agents[AgentRole.ANALYZER]
            response = await analyzer.process_message(message)
            if response and "context" in response.content:
                return EcosystemContext(**response.content["context"])
        
        # Fallback to basic analysis
        return self._basic_ecosystem_analysis(description)
    
    async def _identify_detectors(self, context: EcosystemContext) -> List[Dict[str, Any]]:
        """Identify priority detectors"""
        message = await self.send_message(
            AgentRole.ANALYZER,
            "identify_detectors",
            {"context": context.dict()}
        )
        
        # Route to actual agent
        if AgentRole.ANALYZER in self.agents:
            analyzer = self.agents[AgentRole.ANALYZER]
            response = await analyzer.process_message(message)
            if response and "detectors" in response.content:
                return response.content["detectors"]
        
        # Fallback to basic detectors
        return self._get_basic_detectors(context)
    
    async def _assess_risks(self, detectors: List[Dict], context: EcosystemContext) -> Dict[str, Any]:
        """Assess risks using RiskAssessorAgent"""
        message = await self.send_message(
            AgentRole.RISK_ASSESSOR,
            "assess_risks",
            {"detectors": detectors, "context": context.dict()}
        )
        
        # Route to actual agent
        if AgentRole.RISK_ASSESSOR in self.agents:
            risk_assessor = self.agents[AgentRole.RISK_ASSESSOR]
            response = await risk_assessor.process_message(message)
            if response and "enhanced_detectors" in response.content:
                return response.content
        
        # Fallback - ensure JSON serializable
        safe_detectors = [convert_detector_for_json(d) for d in detectors]
        return {"enhanced_detectors": safe_detectors, "risk_summary": {"message": "Basic risk assessment"}}
    
    async def _generate_report(self, context: EcosystemContext, risk_analysis: Dict) -> Dict[str, Any]:
        """Generate final report"""
        message = await self.send_message(
            AgentRole.REPORT_GENERATOR,
            "generate_report",
            {"context": context.dict(), "analysis": risk_analysis}
        )
        
        # Route to actual agent
        if AgentRole.REPORT_GENERATOR in self.agents:
            report_generator = self.agents[AgentRole.REPORT_GENERATOR]
            response = await report_generator.process_message(message)
            if response and "report" in response.content:
                return response.content["report"]
        
        # Fallback to basic report
        basic_report = self._generate_basic_report(context, risk_analysis)
        return make_json_serializable(basic_report)
    
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process messages from other agents"""
        if message.message_type == "request_additional_info":
            # Handle requests for additional information
            return await self.send_message(
                message.from_agent,
                "additional_info_response",
                {"info": "requested information"}
            )
        
        return None
    
    def _basic_ecosystem_analysis(self, description: str) -> EcosystemContext:
        """Basic ecosystem analysis fallback"""
        technologies = []
        keywords = {
            "web": ["web", "http", "html", "javascript", "react", "angular"],
            "api": ["api", "rest", "graphql", "endpoint"],
            "database": ["database", "sql", "mysql", "postgres", "mongodb"],
            "cloud": ["aws", "azure", "gcp", "cloud"],
            "mobile": ["mobile", "ios", "android", "app"],
            "microservices": ["microservices", "kubernetes", "docker", "container"]
        }
        
        description_lower = description.lower()
        for tech, terms in keywords.items():
            if any(term in description_lower for term in terms):
                technologies.append(tech)
        
        # Detect architecture type
        arch_type = "monolith"
        if "microservices" in technologies or "kubernetes" in description_lower:
            arch_type = "microservices"
        elif "serverless" in description_lower or "lambda" in description_lower:
            arch_type = "serverless"
        
        # Detect data sensitivity
        data_sensitivity = "medium"
        if any(term in description_lower for term in ["pii", "financial", "medical", "credit", "payment"]):
            data_sensitivity = "high"
        
        return EcosystemContext(
            description=description,
            technologies=technologies,
            architecture_type=arch_type,
            security_controls=["authentication", "authorization"],
            data_sensitivity=data_sensitivity,
            compliance_requirements=[]
        )
    
    def _get_basic_detectors(self, context: EcosystemContext) -> List[Dict[str, Any]]:
        """Get basic detectors based on context"""
        detectors = []
        
        # Web-based detectors
        if "web" in context.technologies:
            detectors.append({
                "name": "Web Application Attack Detection",
                "description": "Detect common web application attacks like SQL injection, XSS",
                "priority": "high",
                "risk_score": 8.0,
                "impact_level": "high",
                "implementation_effort": "medium",
                "rationale": "Web applications are common attack vectors",
                "mitre_techniques": []
            })
        
        # API-based detectors
        if "api" in context.technologies:
            detectors.append({
                "name": "API Abuse Detection",
                "description": "Monitor for API rate limiting bypass and abuse patterns",
                "priority": "high",
                "risk_score": 7.5,
                "impact_level": "medium",
                "implementation_effort": "low",
                "rationale": "APIs are frequently targeted in modern attacks",
                "mitre_techniques": []
            })
        
        # Database detectors
        if "database" in context.technologies:
            detectors.append({
                "name": "Database Access Anomaly",
                "description": "Detect unusual database access patterns and privilege escalation",
                "priority": "high",
                "risk_score": 8.5,
                "impact_level": "critical",
                "implementation_effort": "medium",
                "rationale": "Database breaches have severe business impact",
                "mitre_techniques": []
            })
        
        # Authentication detectors (always include)
        detectors.append({
            "name": "Authentication Anomaly Detection",
            "description": "Detect credential stuffing, brute force, and suspicious login patterns",
            "priority": "high",
            "risk_score": 8.0,
            "impact_level": "high",
            "implementation_effort": "medium",
            "rationale": "Authentication is the first line of defense",
            "mitre_techniques": []  # Will be populated by risk assessor
        })
        
        return detectors
    
    def _generate_basic_report(self, context: EcosystemContext, risk_analysis: Dict) -> Dict[str, Any]:
        """Generate basic report fallback"""
        detectors = risk_analysis.get("enhanced_detectors", [])
        
        return {
            "ecosystem_context": context.dict(),
            "priority_detectors": detectors,
            "executive_summary": f"Análise identificou {len(detectors)} detectores prioritários para sistema {context.architecture_type} com tecnologias {', '.join(context.technologies)}. Recomenda-se implementação em fases baseada no nível de risco.",
            "implementation_roadmap": [
                {
                    "phase": 1,
                    "name": "Detectores Críticos",
                    "timeline": "4 semanas",
                    "priority": "high",
                    "detectors": [d.get("name", "") for d in detectors[:3]]
                }
            ],
            "actionable_items": [
                {
                    "detector_name": d.get("name", ""),
                    "priority": d.get("priority", "medium"),
                    "actions": [
                        {
                            "step": 1,
                            "description": f"Implementar {d.get('name', '')}",
                            "owner": "Security Team",
                            "timeline": "2 semanas"
                        }
                    ]
                } for d in detectors[:5]
            ],
            "metadata": {
                "generated_at": "2025-01-15T10:00:00Z",
                "total_detectors": len(detectors),
                "fallback_mode": True
            }
        }