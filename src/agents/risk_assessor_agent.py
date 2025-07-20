from typing import Dict, Any, List, Optional
import json
import os

from src.agents.base_agent import BaseAgent
from src.models.base import AgentMessage, AgentRole, SecurityDetector, MitreAttackTechnique
from src.services.mitre_service import MitreService
from src.utils.direct_anthropic import DirectAnthropicClient

class RiskAssessorAgent(BaseAgent):
    def __init__(self, session_id: str):
        super().__init__(AgentRole.RISK_ASSESSOR, session_id)
        self.mitre_service = MitreService()
        self.llm = DirectAnthropicClient(temperature=0.2)
        
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process incoming messages"""
        if message.message_type == "assess_risks":
            return await self._assess_risks(message)
        elif message.message_type == "map_mitre_techniques":
            return await self._map_mitre_techniques(message)
        
        return None
    
    async def _assess_risks(self, message: AgentMessage) -> AgentMessage:
        """Assess risks and map to MITRE ATT&CK"""
        detectors = message.content["detectors"]
        context = message.content["context"]
        
        # Map each detector to MITRE techniques
        enhanced_detectors = []
        for detector_data in detectors:
            detector = SecurityDetector(**detector_data) if isinstance(detector_data, dict) else detector_data
            
            # Get MITRE techniques for this detector
            mitre_techniques = await self._get_mitre_techniques(detector, context)
            
            # Calculate enhanced risk score (while techniques are still objects)
            enhanced_risk_score = await self._calculate_risk_score(detector, mitre_techniques, context)
            
            # Update detector with calculated score first
            detector.risk_score = enhanced_risk_score
            
            # Convert MITRE techniques to dict for serialization
            detector.mitre_techniques = [t.dict() for t in mitre_techniques] if mitre_techniques else []
            
            enhanced_detectors.append(detector)
            
            await self.log_decision(
                "detector_risk_assessed",
                f"Mapped {detector.name} to {len(mitre_techniques)} MITRE techniques",
                {
                    "detector_name": detector.name,
                    "techniques_count": len(mitre_techniques),
                    "risk_score": enhanced_risk_score
                }
            )
        
        # Sort by risk score (highest first)
        enhanced_detectors.sort(key=lambda d: d.risk_score, reverse=True)
        
        await self.log_decision(
            "risk_assessment_completed",
            f"Completed risk assessment for {len(enhanced_detectors)} detectors",
            {
                "total_detectors": len(enhanced_detectors),
                "high_risk_count": len([d for d in enhanced_detectors if d.risk_score >= 7.0]),
                "avg_risk_score": sum(d.risk_score for d in enhanced_detectors) / len(enhanced_detectors)
            }
        )
        
        # Convert detectors to dict format for JSON serialization
        enhanced_detectors_dict = []
        for detector in enhanced_detectors:
            detector_dict = detector.dict()
            # mitre_techniques are already in dict format from line 45
            enhanced_detectors_dict.append(detector_dict)
        
        return await self.send_message(
            message.from_agent,
            "risk_assessment_complete",
            {
                "enhanced_detectors": enhanced_detectors_dict,
                "risk_summary": self._generate_risk_summary(enhanced_detectors)
            }
        )
    
    async def _get_mitre_techniques(self, detector: SecurityDetector, context: Dict) -> List[MitreAttackTechnique]:
        """Map detector to MITRE ATT&CK techniques using LLM"""
        
        # Get relevant MITRE techniques from service
        potential_techniques = await self.mitre_service.search_techniques(detector.name, detector.description)
        
        # Use LLM to select most relevant techniques
        prompt_template = """
        Given this security detector and system context, select the most relevant MITRE ATT&CK techniques:
        
        Detector:
        Name: {detector_name}
        Description: {detector_description}
        
        System Context:
        {context}
        
        Available MITRE Techniques:
        {techniques}
        
        Select the 2-4 most relevant techniques and return as JSON array:
        [
            {{
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials...",
                "tactics": ["persistence", "privilege-escalation"],
                "platforms": ["web", "network"],
                "relevance_score": 0.95
            }}
        ]
        
        Only return valid JSON:
        """
        
        response = self.llm.format_and_invoke(
            prompt_template,
            detector_name=detector.name,
            detector_description=detector.description,
            context=json.dumps(context),
            techniques=json.dumps([t.dict() if hasattr(t, 'dict') else t for t in potential_techniques[:10]])  # Limit context
        )
        
        try:
            techniques_data = json.loads(response)
            valid_techniques = []
            
            for t in techniques_data:
                # Clean data to match MitreAttackTechnique model
                clean_data = {
                    'technique_id': t.get('technique_id', 'T0000'),
                    'name': t.get('name', 'Unknown Technique'),
                    'description': t.get('description', ''),
                    'tactics': t.get('tactics', ['unknown']),
                    'platforms': t.get('platforms', ['unknown'])
                }
                
                # Ensure tactics and platforms are lists
                if not isinstance(clean_data['tactics'], list):
                    clean_data['tactics'] = [clean_data['tactics']] if clean_data['tactics'] else ['unknown']
                if not isinstance(clean_data['platforms'], list):
                    clean_data['platforms'] = [clean_data['platforms']] if clean_data['platforms'] else ['unknown']
                
                valid_techniques.append(MitreAttackTechnique(**clean_data))
            
            return valid_techniques
            
        except json.JSONDecodeError:
            # Fallback to service-provided techniques
            return potential_techniques[:2] if potential_techniques else []
        except Exception as e:
            logger.error(f"Failed to process MITRE techniques: {e}")
            # Return fallback techniques
            return potential_techniques[:2] if potential_techniques else []
    
    async def _calculate_risk_score(self, 
                                   detector: SecurityDetector, 
                                   mitre_techniques: List[MitreAttackTechnique],
                                   context: Dict) -> float:
        """Calculate enhanced risk score based on MITRE mapping and context"""
        
        base_score = detector.risk_score if detector.risk_score > 0 else 5.0
        
        # Factors that increase risk
        risk_multipliers = []
        
        # More MITRE techniques = higher risk
        technique_multiplier = 1.0 + (len(mitre_techniques) * 0.1)
        risk_multipliers.append(technique_multiplier)
        
        # Critical tactics increase risk
        critical_tactics = ["initial-access", "execution", "persistence", "privilege-escalation", "exfiltration"]
        for technique in mitre_techniques:
            # technique is still a MitreAttackTechnique object here (before conversion)
            tactics = technique.tactics if hasattr(technique, 'tactics') else []
            if any(tactic in critical_tactics for tactic in tactics):
                risk_multipliers.append(1.2)
                break
        
        # Context-based multipliers
        if context.get("data_sensitivity") == "high":
            risk_multipliers.append(1.3)
        
        if "financial" in context.get("industry", "").lower():
            risk_multipliers.append(1.2)
        
        # Calculate final score
        final_score = base_score
        for multiplier in risk_multipliers:
            final_score *= multiplier
        
        # Cap at 10.0
        return min(final_score, 10.0)
    
    def _generate_risk_summary(self, detectors: List[SecurityDetector]) -> Dict[str, Any]:
        """Generate risk assessment summary"""
        
        if not detectors:
            return {"message": "No detectors to assess"}
        
        # Risk distribution
        high_risk = [d for d in detectors if d.risk_score >= 7.0]
        medium_risk = [d for d in detectors if 4.0 <= d.risk_score < 7.0]
        low_risk = [d for d in detectors if d.risk_score < 4.0]
        
        # Most common MITRE tactics
        all_tactics = []
        for detector in detectors:
            for technique in detector.mitre_techniques:
                # technique is now a dict, not an object
                if isinstance(technique, dict):
                    all_tactics.extend(technique.get("tactics", []))
                else:
                    all_tactics.extend(technique.tactics)
        
        tactic_counts = {}
        for tactic in all_tactics:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        top_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_detectors": len(detectors),
            "risk_distribution": {
                "high": len(high_risk),
                "medium": len(medium_risk),
                "low": len(low_risk)
            },
            "average_risk_score": round(sum(d.risk_score for d in detectors) / len(detectors), 2),
            "highest_risk_detector": detectors[0].name if detectors else None,
            "top_mitre_tactics": [{"tactic": tactic, "count": count} for tactic, count in top_tactics],
            "total_mitre_techniques": sum(len(d.mitre_techniques) for d in detectors),
            "recommendation": self._get_risk_recommendation(high_risk, medium_risk, low_risk)
        }
    
    def _get_risk_recommendation(self, high_risk: List, medium_risk: List, low_risk: List) -> str:
        """Generate risk-based recommendation"""
        
        if len(high_risk) >= 5:
            return "CRÍTICO: Múltiplos detectores de alto risco identificados. Priorize implementação imediata dos detectores de maior score."
        elif len(high_risk) >= 2:
            return "ALTO: Detectores críticos identificados. Implemente detectores de alto risco nas próximas 2-4 semanas."
        elif len(medium_risk) >= 5:
            return "MÉDIO: Vários detectores de risco moderado. Planeje implementação em fases ao longo de 2-3 meses."
        else:
            return "BAIXO: Riscos bem distribuídos. Implemente detectores seguindo cronograma padrão de segurança."