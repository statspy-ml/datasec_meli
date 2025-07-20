from typing import Dict, Any, List, Optional
import json
from datetime import datetime, timedelta
import os

from src.agents.base_agent import BaseAgent
from src.models.base import AgentMessage, AgentRole, SecurityDetector, SecurityReport, EcosystemContext
from src.utils.direct_anthropic import DirectAnthropicClient

class ReportGeneratorAgent(BaseAgent):
    def __init__(self, session_id: str):
        super().__init__(AgentRole.REPORT_GENERATOR, session_id)
        self.llm = DirectAnthropicClient(temperature=0.1)
        
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process incoming messages"""
        if message.message_type == "generate_report":
            return await self._generate_report(message)
        
        return None
    
    async def _generate_report(self, message: AgentMessage) -> AgentMessage:
        """Generate comprehensive security report"""
        
        context = EcosystemContext(**message.content["context"])
        enhanced_detectors_data = message.content["analysis"]["enhanced_detectors"]
        risk_summary = message.content["analysis"]["risk_summary"]
        
        # Convert detector data back to objects
        enhanced_detectors = [SecurityDetector(**d) for d in enhanced_detectors_data]
        
        await self.log_decision(
            "report_generation_started",
            f"Starting report generation for {len(enhanced_detectors)} detectors",
            {"detector_count": len(enhanced_detectors), "context_type": context.architecture_type}
        )
        
        # Generate different sections of the report
        executive_summary = await self._generate_executive_summary(context, enhanced_detectors, risk_summary)
        implementation_roadmap = await self._generate_implementation_roadmap(enhanced_detectors)
        actionable_items = await self._generate_actionable_items(enhanced_detectors)
        
        # Create final report
        report = SecurityReport(
            session_id=self.session_id,
            ecosystem_context=context,
            priority_detectors=enhanced_detectors,
            executive_summary=executive_summary,
            implementation_roadmap=implementation_roadmap
        )
        
        # Add actionable items to the report dict
        report_dict = report.dict()
        report_dict["actionable_items"] = actionable_items
        report_dict["risk_analysis"] = risk_summary
        report_dict["metadata"] = {
            "generated_at": datetime.now().isoformat(),
            "total_detectors": len(enhanced_detectors),
            "high_priority_count": len([d for d in enhanced_detectors if d.priority == "high"]),
            "average_risk_score": risk_summary.get("average_risk_score", 0),
            "estimated_implementation_time": self._estimate_total_implementation_time(enhanced_detectors)
        }
        
        await self.log_decision(
            "report_generated",
            "Security report generated successfully",
            {
                "sections_included": ["executive_summary", "detectors", "roadmap", "actionables"],
                "executive_summary_length": len(executive_summary),
                "roadmap_phases": len(implementation_roadmap)
            }
        )
        
        return await self.send_message(
            message.from_agent,
            "report_generation_complete",
            {"report": report_dict}
        )
    
    async def _generate_executive_summary(self, 
                                        context: EcosystemContext, 
                                        detectors: List[SecurityDetector],
                                        risk_summary: Dict) -> str:
        """Generate executive summary using LLM"""
        
        prompt_template = """
        Generate a concise executive summary for a security analysis report.
        
        System Context:
        - Architecture: {architecture_type}
        - Technologies: {technologies}
        - Data Sensitivity: {data_sensitivity}
        - Compliance: {compliance_requirements}
        
        Analysis Results:
        - Total Detectors: {total_detectors}
        - High Priority: {high_priority_count}
        - Average Risk Score: {avg_risk_score}/10
        - Top Risk: {highest_risk_detector}
        
        Risk Summary:
        {risk_summary}
        
        Write a professional executive summary (3-4 paragraphs) that:
        1. Summarizes key findings and risk level
        2. Highlights the most critical security gaps
        3. Provides high-level implementation recommendation
        4. Mentions business impact and timeline
        
        Focus on business language, not technical details. Target audience: Security leadership and management.
        """
        
        high_priority_count = len([d for d in detectors if d.priority == "high"])
        avg_risk_score = sum(d.risk_score for d in detectors) / len(detectors) if detectors else 0
        
        response = self.llm.format_and_invoke(
            prompt_template,
            architecture_type=context.architecture_type,
            technologies=", ".join(context.technologies),
            data_sensitivity=context.data_sensitivity,
            compliance_requirements=", ".join(context.compliance_requirements),
            total_detectors=len(detectors),
            high_priority_count=high_priority_count,
            avg_risk_score=round(avg_risk_score, 1),
            highest_risk_detector=detectors[0].name if detectors else "N/A",
            risk_summary=json.dumps(risk_summary, indent=2)
        )
        
        return response
    
    async def _generate_implementation_roadmap(self, detectors: List[SecurityDetector]) -> List[Dict[str, Any]]:
        """Generate phased implementation roadmap"""
        
        if not detectors:
            return []
        
        # Sort detectors by priority and risk score
        sorted_detectors = sorted(detectors, key=lambda d: (
            {"high": 3, "medium": 2, "low": 1}[d.priority],
            d.risk_score
        ), reverse=True)
        
        # Create phases based on priority and complexity
        phases = []
        
        # Phase 1: Critical and high-priority detectors (first 4 weeks)
        phase1_detectors = [d for d in sorted_detectors[:5] if d.priority == "high"]
        if phase1_detectors:
            phases.append({
                "phase": 1,
                "name": "Critical Security Controls",
                "timeline": "4 weeks",
                "priority": "critical",
                "detectors": [d.id for d in phase1_detectors],
                "detector_names": [d.name for d in phase1_detectors],
                "estimated_effort": f"{len(phase1_detectors) * 40} horas",
                "required_tools": self._get_required_tools(phase1_detectors),
                "success_metrics": [
                    "Detecção ativa de ameaças críticas",
                    "Redução de 80% em falsos positivos",
                    "Tempo de resposta < 5 minutos"
                ],
                "budget_estimate": f"R$ {len(phase1_detectors) * 25000:,}",
                "key_milestones": [
                    "Configuração de logs e fontes de dados",
                    "Desenvolvimento de regras de detecção",
                    "Testes e ajuste fino",
                    "Deploy em produção"
                ]
            })
        
        # Phase 2: Medium priority detectors (weeks 5-12)
        phase2_detectors = [d for d in sorted_detectors[5:] if d.priority in ["high", "medium"]][:6]
        if phase2_detectors:
            phases.append({
                "phase": 2,
                "name": "Enhanced Monitoring",
                "timeline": "8 weeks",
                "priority": "high",
                "detectors": [d.id for d in phase2_detectors],
                "detector_names": [d.name for d in phase2_detectors],
                "estimated_effort": f"{len(phase2_detectors) * 30} horas",
                "required_tools": self._get_required_tools(phase2_detectors),
                "success_metrics": [
                    "Cobertura de detecção expandida",
                    "Integração com SIEM estabelecida",
                    "Alertas automatizados funcionando"
                ],
                "budget_estimate": f"R$ {len(phase2_detectors) * 20000:,}",
                "dependencies": ["Conclusão da Fase 1"]
            })
        
        # Phase 3: Remaining detectors (weeks 13-24)
        remaining_detectors = sorted_detectors[11:]
        if remaining_detectors:
            phases.append({
                "phase": 3,
                "name": "Comprehensive Coverage",
                "timeline": "12 weeks",
                "priority": "medium",
                "detectors": [d.id for d in remaining_detectors],
                "detector_names": [d.name for d in remaining_detectors],
                "estimated_effort": f"{len(remaining_detectors) * 25} horas",
                "required_tools": self._get_required_tools(remaining_detectors),
                "success_metrics": [
                    "Detecção completa implementada",
                    "Processos de resposta estabelecidos",
                    "Métricas de segurança ativas"
                ],
                "budget_estimate": f"R$ {len(remaining_detectors) * 15000:,}",
                "dependencies": ["Conclusão da Fase 2"]
            })
        
        return phases
    
    async def _generate_actionable_items(self, detectors: List[SecurityDetector]) -> List[Dict[str, Any]]:
        """Generate specific actionable items for each detector"""
        
        actionable_items = []
        
        for detector in detectors[:8]:  # Focus on top 8 detectors
            steps = await self._generate_implementation_steps(detector)
            
            actionable_items.append({
                "detector_id": detector.id,
                "detector_name": detector.name,
                "priority": detector.priority,
                "estimated_total_time": f"{len(steps) * 2} semanas",
                "required_skills": self._get_required_skills(detector),
                "actions": steps
            })
        
        return actionable_items
    
    async def _generate_implementation_steps(self, detector: SecurityDetector) -> List[Dict[str, Any]]:
        """Generate specific implementation steps for a detector"""
        
        prompt_template = """
        Generate 4-6 specific implementation steps for this security detector:
        
        Detector: {detector_name}
        Description: {detector_description}
        MITRE Techniques: {mitre_techniques}
        
        Return as JSON array with this format:
        [
            {{
                "step": 1,
                "description": "Configure log collection from relevant sources",
                "owner": "Security Engineering Team",
                "timeline": "1 week",
                "complexity": "low|medium|high",
                "prerequisites": ["Access to log sources", "SIEM configuration"],
                "deliverables": ["Log ingestion configured", "Data validation completed"]
            }}
        ]
        
        Focus on practical, actionable steps. Include timeline, complexity, and ownership.
        Only return valid JSON:
        """
        
        mitre_info = []
        for technique in detector.mitre_techniques:
            if isinstance(technique, dict):
                mitre_info.append(f"{technique.get('technique_id', '')}: {technique.get('name', '')}")
            else:
                mitre_info.append(f"{technique.technique_id}: {technique.name}")
        
        response = self.llm.format_and_invoke(
            prompt_template,
            detector_name=detector.name,
            detector_description=detector.description,
            mitre_techniques=", ".join(mitre_info)
        )
        
        try:
            steps = json.loads(response)
            return steps
        except json.JSONDecodeError:
            # Fallback to generic steps
            return self._get_generic_implementation_steps(detector)
    
    def _get_generic_implementation_steps(self, detector: SecurityDetector) -> List[Dict[str, Any]]:
        """Fallback generic implementation steps"""
        return [
            {
                "step": 1,
                "description": f"Analisar fontes de dados para {detector.name}",
                "owner": "Security Team",
                "timeline": "1 semana",
                "complexity": "low"
            },
            {
                "step": 2,
                "description": f"Desenvolver regras de detecção para {detector.name}",
                "owner": "Security Engineering",
                "timeline": "2 semanas",
                "complexity": "medium"
            },
            {
                "step": 3,
                "description": f"Testar e ajustar {detector.name}",
                "owner": "Security Operations",
                "timeline": "1 semana",
                "complexity": "medium"
            },
            {
                "step": 4,
                "description": f"Deploy em produção de {detector.name}",
                "owner": "DevOps Team",
                "timeline": "1 semana",
                "complexity": "low"
            }
        ]
    
    def _get_required_tools(self, detectors: List[SecurityDetector]) -> List[str]:
        """Get required tools based on detector types"""
        tools = set()
        
        for detector in detectors:
            # Basic tools for all detectors
            tools.update(["SIEM", "Log Management", "Alerting System"])
            
            # Specific tools based on detector name/type
            name_lower = detector.name.lower()
            if "api" in name_lower:
                tools.update(["API Gateway Logs", "Rate Limiting"])
            if "authentication" in name_lower or "login" in name_lower:
                tools.update(["Identity Management", "Authentication Logs"])
            if "network" in name_lower:
                tools.update(["Network Monitoring", "Firewall Logs"])
            if "database" in name_lower or "data" in name_lower:
                tools.update(["Database Activity Monitoring", "DLP"])
            if "web" in name_lower:
                tools.update(["Web Application Firewall", "Application Logs"])
        
        return list(tools)
    
    def _get_required_skills(self, detector: SecurityDetector) -> List[str]:
        """Get required skills for implementing a detector"""
        skills = ["Security Analysis", "Log Analysis"]
        
        name_lower = detector.name.lower()
        if "api" in name_lower:
            skills.extend(["API Security", "Rate Limiting"])
        if "network" in name_lower:
            skills.extend(["Network Security", "Traffic Analysis"])
        if "database" in name_lower:
            skills.extend(["Database Security", "SQL"])
        if "web" in name_lower:
            skills.extend(["Web Security", "OWASP"])
        
        return skills
    
    def _estimate_total_implementation_time(self, detectors: List[SecurityDetector]) -> str:
        """Estimate total implementation time"""
        total_weeks = 0
        
        for detector in detectors:
            if detector.implementation_effort == "low":
                total_weeks += 2
            elif detector.implementation_effort == "medium":
                total_weeks += 4
            else:  # high
                total_weeks += 6
        
        # Assume some parallelization
        estimated_weeks = int(total_weeks * 0.7)
        
        if estimated_weeks <= 4:
            return "1 mês"
        elif estimated_weeks <= 12:
            return f"{estimated_weeks // 4} meses"
        else:
            return f"{estimated_weeks // 4} meses"