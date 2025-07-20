from typing import List, Dict, Any
import json
import re
from loguru import logger

class RAGServiceSimple:
    """Simple RAG service without external ML dependencies"""
    
    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        logger.info(f"Loaded {len(self.security_patterns)} security patterns")
    
    def _load_security_patterns(self) -> List[Dict[str, Any]]:
        """Load hardcoded security patterns"""
        return [
            {
                "id": "pattern_001",
                "title": "Web Application SQL Injection",
                "description": "Attackers inject malicious SQL code through web application input fields to gain unauthorized access to databases. Common in applications with poor input validation.",
                "attack_vector": "Web Application",
                "severity": "High",
                "mitre_techniques": ["T1190", "T1505.003"],
                "detection_methods": ["WAF logs analysis", "Database query monitoring", "Anomalous SQL pattern detection"],
                "affected_systems": ["Web applications", "Databases", "API endpoints"],
                "keywords": ["sql", "injection", "web", "database", "input", "validation"]
            },
            {
                "id": "pattern_002",
                "title": "API Rate Limiting Bypass",
                "description": "Attackers attempt to bypass API rate limiting controls through various techniques like distributed requests, header manipulation, or endpoint enumeration.",
                "attack_vector": "API",
                "severity": "Medium",
                "mitre_techniques": ["T1190", "T1078"],
                "detection_methods": ["API gateway logs", "Request pattern analysis", "Rate limiting violation monitoring"],
                "affected_systems": ["API gateways", "Microservices", "Load balancers"],
                "keywords": ["api", "rate", "limiting", "bypass", "microservices", "gateway"]
            },
            {
                "id": "pattern_003",
                "title": "Credential Stuffing Attacks",
                "description": "Automated attacks using stolen username/password pairs from data breaches to gain unauthorized access to user accounts across multiple services.",
                "attack_vector": "Authentication",
                "severity": "High",
                "mitre_techniques": ["T1110", "T1078"],
                "detection_methods": ["Login anomaly detection", "Geographic impossibility analysis", "Failed authentication clustering"],
                "affected_systems": ["Authentication systems", "User databases", "Session management"],
                "keywords": ["credential", "stuffing", "authentication", "login", "password", "brute"]
            },
            {
                "id": "pattern_004",
                "title": "Privilege Escalation via Service Accounts",
                "description": "Attackers compromise service accounts to escalate privileges and move laterally within the infrastructure, often targeting over-privileged service accounts.",
                "attack_vector": "Identity",
                "severity": "High",
                "mitre_techniques": ["T1078.004", "T1484"],
                "detection_methods": ["Service account activity monitoring", "Privilege usage analysis", "Unusual access pattern detection"],
                "affected_systems": ["Identity management", "Service accounts", "Privileged access systems"],
                "keywords": ["privilege", "escalation", "service", "account", "identity", "access"]
            },
            {
                "id": "pattern_005",
                "title": "Data Exfiltration via DNS Tunneling",
                "description": "Attackers use DNS queries to exfiltrate sensitive data, bypassing traditional network security controls by encoding data in DNS requests.",
                "attack_vector": "Network",
                "severity": "High",
                "mitre_techniques": ["T1041", "T1071.004"],
                "detection_methods": ["DNS query analysis", "Data size anomaly detection", "Unusual DNS pattern monitoring"],
                "affected_systems": ["DNS servers", "Network infrastructure", "Data repositories"],
                "keywords": ["data", "exfiltration", "dns", "tunneling", "network", "bypass"]
            },
            {
                "id": "pattern_006",
                "title": "Microservices Inter-Service Attack",
                "description": "Attacks targeting communication between microservices, exploiting weak authentication, unencrypted traffic, or service mesh vulnerabilities.",
                "attack_vector": "Microservices",
                "severity": "Medium",
                "mitre_techniques": ["T1210", "T1557"],
                "detection_methods": ["Service mesh monitoring", "Inter-service traffic analysis", "Authentication failure tracking"],
                "affected_systems": ["Kubernetes clusters", "Service mesh", "Container orchestration"],
                "keywords": ["microservices", "kubernetes", "container", "service", "mesh", "orchestration"]
            },
            {
                "id": "pattern_007",
                "title": "Cloud Storage Misconfiguration Exploitation",
                "description": "Attackers exploit misconfigured cloud storage buckets, databases, or services to access sensitive data or establish persistence.",
                "attack_vector": "Cloud",
                "severity": "High",
                "mitre_techniques": ["T1530", "T1083"],
                "detection_methods": ["Cloud configuration monitoring", "Unauthorized access detection", "Data access pattern analysis"],
                "affected_systems": ["Cloud storage", "Cloud databases", "Cloud services"],
                "keywords": ["cloud", "storage", "misconfiguration", "aws", "azure", "gcp", "bucket"]
            },
            {
                "id": "pattern_008",
                "title": "Supply Chain Software Compromise",
                "description": "Attackers compromise software supply chain components, including third-party libraries, CI/CD pipelines, or development tools to inject malicious code.",
                "attack_vector": "Supply Chain",
                "severity": "Critical",
                "mitre_techniques": ["T1195", "T1543"],
                "detection_methods": ["Software integrity monitoring", "CI/CD pipeline analysis", "Dependency vulnerability scanning"],
                "affected_systems": ["Development environment", "CI/CD systems", "Software repositories"],
                "keywords": ["supply", "chain", "cicd", "pipeline", "development", "dependency"]
            },
            {
                "id": "pattern_009",
                "title": "Business Email Compromise (BEC)",
                "description": "Sophisticated phishing attacks targeting business email systems to compromise executive accounts and initiate fraudulent transactions.",
                "attack_vector": "Email",
                "severity": "High",
                "mitre_techniques": ["T1566.002", "T1078"],
                "detection_methods": ["Email behavior analysis", "Executive impersonation detection", "Financial transaction monitoring"],
                "affected_systems": ["Email systems", "Financial systems", "Executive accounts"],
                "keywords": ["email", "phishing", "business", "compromise", "executive", "financial"]
            },
            {
                "id": "pattern_010",
                "title": "IoT Device Network Infiltration",
                "description": "Attackers compromise IoT devices to gain network access, establish persistence, or launch attacks on internal infrastructure.",
                "attack_vector": "IoT",
                "severity": "Medium",
                "mitre_techniques": ["T1078", "T1021"],
                "detection_methods": ["IoT device behavior monitoring", "Network traffic analysis", "Device authentication tracking"],
                "affected_systems": ["IoT devices", "Network infrastructure", "Device management systems"],
                "keywords": ["iot", "device", "network", "infiltration", "embedded", "sensor"]
            }
        ]
    
    async def query_attack_patterns(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Query for relevant attack patterns using simple keyword matching"""
        
        query_lower = query.lower()
        pattern_scores = []
        
        for pattern in self.security_patterns:
            score = self._calculate_relevance_score(query_lower, pattern)
            if score > 0:
                pattern_with_score = pattern.copy()
                pattern_with_score["relevance_score"] = score
                pattern_scores.append(pattern_with_score)
        
        # Sort by relevance score (highest first)
        pattern_scores.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        # Return top_k results
        results = pattern_scores[:top_k]
        
        logger.info(f"Found {len(results)} relevant patterns for query")
        return results
    
    def _calculate_relevance_score(self, query: str, pattern: Dict[str, Any]) -> float:
        """Calculate relevance score using keyword matching"""
        score = 0.0
        
        # Check keywords (highest weight)
        for keyword in pattern.get("keywords", []):
            if keyword in query:
                score += 3.0
        
        # Check title (medium weight)
        title_words = pattern.get("title", "").lower().split()
        for word in title_words:
            if word in query:
                score += 2.0
        
        # Check description (lower weight)
        desc_words = pattern.get("description", "").lower().split()
        for word in desc_words:
            if len(word) > 4 and word in query:  # Only longer words
                score += 1.0
        
        # Check attack vector
        if pattern.get("attack_vector", "").lower() in query:
            score += 2.5
        
        # Check affected systems
        for system in pattern.get("affected_systems", []):
            if system.lower() in query:
                score += 1.5
        
        return score
    
    async def query_detection_methods(self, attack_vector: str, technologies: List[str]) -> List[Dict[str, Any]]:
        """Query for detection methods based on attack vector and technologies"""
        
        relevant_patterns = []
        
        for pattern in self.security_patterns:
            # Match by attack vector
            if attack_vector and pattern.get("attack_vector", "").lower() == attack_vector.lower():
                relevant_patterns.append(pattern)
                continue
            
            # Match by technologies
            for tech in technologies:
                if any(tech.lower() in keyword for keyword in pattern.get("keywords", [])):
                    relevant_patterns.append(pattern)
                    break
        
        # Extract detection methods
        detection_methods = []
        for pattern in relevant_patterns:
            methods = {
                "attack_vector": pattern.get("attack_vector", ""),
                "detection_methods": pattern.get("detection_methods", []),
                "affected_systems": pattern.get("affected_systems", []),
                "severity": pattern.get("severity", "")
            }
            detection_methods.append(methods)
        
        return detection_methods[:5]  # Return top 5
    
    async def add_custom_pattern(self, pattern: Dict[str, Any]) -> bool:
        """Add a custom security pattern"""
        try:
            # Add keywords if not provided
            if "keywords" not in pattern:
                pattern["keywords"] = self._extract_keywords(pattern)
            
            # Add ID if not provided
            if "id" not in pattern:
                pattern["id"] = f"custom_{len(self.security_patterns) + 1:03d}"
            
            self.security_patterns.append(pattern)
            logger.info(f"Added custom pattern: {pattern.get('title', 'Unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom pattern: {e}")
            return False
    
    def _extract_keywords(self, pattern: Dict[str, Any]) -> List[str]:
        """Extract keywords from pattern title and description"""
        text = f"{pattern.get('title', '')} {pattern.get('description', '')}"
        
        # Simple keyword extraction (remove common words)
        common_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "is", "are", "was", "were", "be", "been", "have", "has", "had", "do", "does", "did", "will", "would", "could", "should", "may", "might", "can", "this", "that", "these", "those"}
        
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        keywords = [word for word in words if word not in common_words]
        
        # Remove duplicates and return first 10
        return list(set(keywords))[:10]
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the pattern collection"""
        
        attack_vectors = {}
        severities = {}
        
        for pattern in self.security_patterns:
            vector = pattern.get("attack_vector", "Unknown")
            severity = pattern.get("severity", "Unknown")
            
            attack_vectors[vector] = attack_vectors.get(vector, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
        
        return {
            "total_patterns": len(self.security_patterns),
            "attack_vectors": attack_vectors,
            "severities": severities,
            "collection_type": "simple_keyword_matching"
        }