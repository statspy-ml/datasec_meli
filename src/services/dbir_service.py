import json
import requests
from typing import List, Dict, Any
from pathlib import Path
import pandas as pd
from loguru import logger
from src.services.pdf_processor import DBIRPDFProcessor

class DBIRService:
    """Service for processing and querying DBIR 2025 report data"""
    
    def __init__(self, dbir_path: str = None):
        self.dbir_path = dbir_path or "data/mitre-attack/2025-dbir-data-breach-investigations-report.pdf"
        self.processed_data = None
        self.pdf_processor = None
        self._load_dbir_data()
    
    def _load_dbir_data(self):
        """Load and process DBIR 2025 data from real PDF"""
        
        # Try to load real DBIR data from PDF
        if Path(self.dbir_path).exists():
            try:
                logger.info(f"Processing real DBIR PDF: {self.dbir_path}")
                self.pdf_processor = DBIRPDFProcessor(self.dbir_path)
                
                # Extract real data from PDF
                attack_patterns = self.pdf_processor.extract_attack_patterns()
                industry_data = self.pdf_processor.extract_industry_data()
                threat_actors = self.pdf_processor.extract_threat_actor_data()
                
                if attack_patterns:
                    # Use real extracted data
                    self.processed_data = {
                        "attack_patterns": self._format_attack_patterns(attack_patterns),
                        "threat_actors": threat_actors if threat_actors else self._get_mock_threat_actors(),
                        "data_types": self._get_mock_data_types(),  # Keep mock for now
                        "industry_data": industry_data,
                        "source": "DBIR 2025 PDF (Real)",
                        "extraction_method": "automated_pdf_parsing"
                    }
                    
                    logger.info(f"Successfully loaded {len(attack_patterns)} real attack patterns from DBIR PDF")
                    
                    # Save extracted data for future use
                    cache_path = "data/mitre-attack/dbir_extracted_data.json"
                    self.pdf_processor.save_extracted_data(cache_path)
                    
                    return
                else:
                    logger.warning("No attack patterns extracted from PDF, falling back to mock data")
                    
            except Exception as e:
                logger.error(f"Error processing DBIR PDF: {e}")
                logger.info("Falling back to mock DBIR data")
        else:
            logger.warning(f"DBIR PDF not found at {self.dbir_path}, using mock data")
        
        # Fallback to mock data if PDF processing fails
        self.processed_data = {
            "attack_patterns": [
                {
                    "name": "Web Application Attacks",
                    "frequency": 0.43,
                    "industries": ["financial", "retail", "healthcare"],
                    "techniques": ["SQL Injection", "XSS", "CSRF"],
                    "detection_methods": ["WAF logs", "Application logs", "Database monitoring"]
                },
                {
                    "name": "System Intrusion",
                    "frequency": 0.32,
                    "industries": ["manufacturing", "professional", "public"],
                    "techniques": ["Lateral movement", "Privilege escalation", "Persistence"],
                    "detection_methods": ["Network monitoring", "Endpoint detection", "Log analysis"]
                },
                {
                    "name": "Social Engineering",
                    "frequency": 0.28,
                    "industries": ["all"],
                    "techniques": ["Phishing", "Pretexting", "Baiting"],
                    "detection_methods": ["Email security", "User behavior analytics", "Training metrics"]
                },
                {
                    "name": "Denial of Service",
                    "frequency": 0.15,
                    "industries": ["financial", "retail", "gaming"],
                    "techniques": ["Volumetric attacks", "Protocol attacks", "Application layer attacks"],
                    "detection_methods": ["Traffic analysis", "Rate limiting", "Network monitoring"]
                }
            ],
            "threat_actors": [
                {
                    "type": "External",
                    "frequency": 0.83,
                    "motivations": ["financial", "espionage", "ideology"]
                },
                {
                    "type": "Internal",
                    "frequency": 0.20,
                    "motivations": ["financial", "grievance", "convenience"]
                }
            ],
            "data_types": [
                {
                    "type": "Personal",
                    "frequency": 0.45,
                    "industries": ["healthcare", "financial", "retail"]
                },
                {
                    "type": "Credentials",
                    "frequency": 0.38,
                    "industries": ["all"]
                },
                {
                    "type": "Internal",
                    "frequency": 0.25,
                    "industries": ["manufacturing", "professional"]
                }
            ]
        }
        
        logger.info("DBIR 2025 mock data loaded successfully")
    
    def _format_attack_patterns(self, raw_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format extracted attack patterns for compatibility with existing code"""
        formatted_patterns = []
        
        for pattern in raw_patterns:
            formatted = {
                "name": pattern.get("name", "Unknown Attack"),
                "frequency": pattern.get("frequency", 0.0),
                "industries": self._extract_industries_from_pattern(pattern),
                "techniques": pattern.get("mitre_techniques", []),
                "detection_methods": pattern.get("detection_methods", []),
                "severity": pattern.get("severity", "Medium"),
                "source": pattern.get("source", "DBIR 2025"),
                "id": pattern.get("id", "unknown")
            }
            formatted_patterns.append(formatted)
        
        return formatted_patterns
    
    def _extract_industries_from_pattern(self, pattern: Dict[str, Any]) -> List[str]:
        """Extract industry information from pattern data"""
        # This could be enhanced based on actual PDF content
        return ["financial", "retail", "healthcare", "manufacturing"]  # Default industries
    
    def _get_mock_threat_actors(self) -> List[Dict[str, Any]]:
        """Return mock threat actor data"""
        return [
            {
                "type": "External",
                "frequency": 0.83,
                "motivations": ["financial", "espionage", "ideology"]
            },
            {
                "type": "Internal", 
                "frequency": 0.20,
                "motivations": ["financial", "grievance", "convenience"]
            }
        ]
    
    def _get_mock_data_types(self) -> List[Dict[str, Any]]:
        """Return mock data types information"""
        return [
            {
                "type": "Personal",
                "frequency": 0.45,
                "industries": ["healthcare", "financial", "retail"]
            },
            {
                "type": "Credentials",
                "frequency": 0.38, 
                "industries": ["all"]
            },
            {
                "type": "Internal",
                "frequency": 0.25,
                "industries": ["manufacturing", "professional"]
            }
        ]
    
    async def get_relevant_threats(self, technologies: List[str], architecture_type: str) -> List[Dict[str, Any]]:
        """Get relevant threats based on system characteristics"""
        relevant_threats = []
        
        # Map technologies to threat patterns
        tech_threat_mapping = {
            "web": ["Web Application Attacks", "Denial of Service"],
            "api": ["Web Application Attacks", "System Intrusion"],
            "database": ["System Intrusion", "Web Application Attacks"],
            "cloud": ["System Intrusion", "Web Application Attacks"],
            "mobile": ["Web Application Attacks", "Social Engineering"]
        }
        
        # Get threats based on technologies
        for tech in technologies:
            if tech in tech_threat_mapping:
                for threat_name in tech_threat_mapping[tech]:
                    threat = self._get_threat_by_name(threat_name)
                    if threat and threat not in relevant_threats:
                        relevant_threats.append(threat)
        
        # Add architecture-specific threats
        if architecture_type == "microservices":
            relevant_threats.extend([
                {
                    "name": "Service-to-Service Attacks",
                    "frequency": 0.20,
                    "techniques": ["API abuse", "Service impersonation", "Network segmentation bypass"],
                    "detection_methods": ["Service mesh monitoring", "API gateway logs", "Network traffic analysis"]
                }
            ])
        
        # Sort by frequency (most common first)
        relevant_threats.sort(key=lambda x: x.get("frequency", 0), reverse=True)
        
        return relevant_threats[:5]  # Return top 5 most relevant
    
    def _get_threat_by_name(self, threat_name: str) -> Dict[str, Any]:
        """Get threat details by name"""
        for threat in self.processed_data["attack_patterns"]:
            if threat["name"] == threat_name:
                return threat
        return None
    
    async def get_industry_threats(self, industry: str) -> List[Dict[str, Any]]:
        """Get threats specific to an industry"""
        industry_threats = []
        
        for threat in self.processed_data["attack_patterns"]:
            if industry in threat["industries"] or "all" in threat["industries"]:
                industry_threats.append(threat)
        
        return sorted(industry_threats, key=lambda x: x["frequency"], reverse=True)
    
    async def get_detection_recommendations(self, threat_patterns: List[str]) -> List[Dict[str, Any]]:
        """Get detection method recommendations for specific threats"""
        recommendations = []
        
        for pattern in threat_patterns:
            threat = self._get_threat_by_name(pattern)
            if threat:
                for method in threat["detection_methods"]:
                    if method not in [r["method"] for r in recommendations]:
                        recommendations.append({
                            "method": method,
                            "threat_patterns": [pattern],
                            "priority": "high" if threat["frequency"] > 0.3 else "medium"
                        })
                    else:
                        # Add to existing recommendation
                        for rec in recommendations:
                            if rec["method"] == method:
                                rec["threat_patterns"].append(pattern)
                                break
        
        return recommendations
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get overall threat statistics from DBIR"""
        return {
            "total_attack_patterns": len(self.processed_data["attack_patterns"]),
            "most_common_attack": max(self.processed_data["attack_patterns"], key=lambda x: x["frequency"]),
            "external_threat_percentage": self.processed_data["threat_actors"][0]["frequency"],
            "data_breach_trends": self.processed_data["data_types"]
        }