import PyPDF2
import re
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from loguru import logger

class DBIRPDFProcessor:
    """Processor for extracting real data from DBIR 2025 PDF report"""
    
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        self.raw_text = ""
        self.pages_text = []
        
    def extract_all_text(self) -> str:
        """Extract all text from PDF"""
        try:
            with open(self.pdf_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                
                for page_num, page in enumerate(reader.pages):
                    try:
                        text = page.extract_text()
                        self.pages_text.append({
                            "page_number": page_num + 1,
                            "text": text
                        })
                        self.raw_text += f"\n--- PAGE {page_num + 1} ---\n{text}"
                    except Exception as e:
                        logger.warning(f"Error extracting page {page_num + 1}: {e}")
                        continue
                        
                logger.info(f"Extracted text from {len(self.pages_text)} pages")
                return self.raw_text
                
        except Exception as e:
            logger.error(f"Error reading PDF: {e}")
            return ""
    
    def extract_attack_patterns(self) -> List[Dict[str, Any]]:
        """Extract attack patterns with frequencies and details"""
        if not self.raw_text:
            self.extract_all_text()
            
        patterns = []
        
        # Pattern 1: Web Application attacks
        web_app_data = self._extract_web_application_data()
        if web_app_data:
            patterns.append(web_app_data)
            
        # Pattern 2: System Intrusion
        system_intrusion_data = self._extract_system_intrusion_data()
        if system_intrusion_data:
            patterns.append(system_intrusion_data)
            
        # Pattern 3: Social Engineering
        social_eng_data = self._extract_social_engineering_data()
        if social_eng_data:
            patterns.append(social_eng_data)
            
        # Pattern 4: Denial of Service
        dos_data = self._extract_dos_data()
        if dos_data:
            patterns.append(dos_data)
            
        # Extract additional patterns from general text analysis
        additional_patterns = self._extract_additional_patterns()
        patterns.extend(additional_patterns)
        
        logger.info(f"Extracted {len(patterns)} attack patterns from DBIR PDF")
        return patterns
    
    def _extract_web_application_data(self) -> Optional[Dict[str, Any]]:
        """Extract Web Application attack data"""
        # Look for web application mentions and percentages
        web_patterns = [
            r'web\s+application[s]?\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?web\s+application',
            r'application\s+layer.*?(\d+\.?\d*)%'
        ]
        
        frequency = self._find_frequency_in_text(web_patterns, "web application")
        
        if frequency:
            return {
                "id": "dbir_web_app",
                "name": "Web Application Attacks",
                "description": "Attacks targeting web applications including injection attacks, authentication bypass, and application-layer vulnerabilities",
                "frequency": frequency / 100.0,
                "attack_vector": "Web Application",
                "severity": "High",
                "source": "DBIR 2025 PDF",
                "extraction_method": "automated_pdf_parsing",
                "mitre_techniques": ["T1190", "T1505.003", "T1078"],
                "detection_methods": [
                    "Web application firewall monitoring",
                    "Application security scanning",
                    "Input validation monitoring",
                    "Authentication log analysis"
                ],
                "affected_systems": ["Web applications", "API endpoints", "Application servers"]
            }
        return None
    
    def _extract_system_intrusion_data(self) -> Optional[Dict[str, Any]]:
        """Extract System Intrusion attack data"""
        intrusion_patterns = [
            r'system\s+intrusion[s]?\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?system\s+intrusion',
            r'intrusion[s]?\s+.*?(\d+\.?\d*)%'
        ]
        
        frequency = self._find_frequency_in_text(intrusion_patterns, "system intrusion")
        
        if frequency:
            return {
                "id": "dbir_system_intrusion",
                "name": "System Intrusion",
                "description": "Unauthorized access to systems through various attack vectors including malware, credential theft, and privilege escalation",
                "frequency": frequency / 100.0,
                "attack_vector": "Network/System",
                "severity": "Critical",
                "source": "DBIR 2025 PDF",
                "extraction_method": "automated_pdf_parsing",
                "mitre_techniques": ["T1078", "T1021", "T1055", "T1484"],
                "detection_methods": [
                    "Network traffic monitoring",
                    "Endpoint detection and response",
                    "Privilege escalation detection",
                    "Lateral movement monitoring"
                ],
                "affected_systems": ["Servers", "Workstations", "Network infrastructure"]
            }
        return None
    
    def _extract_social_engineering_data(self) -> Optional[Dict[str, Any]]:
        """Extract Social Engineering attack data"""
        social_patterns = [
            r'social\s+engineering\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?social\s+engineering',
            r'phishing\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?phishing'
        ]
        
        frequency = self._find_frequency_in_text(social_patterns, "social engineering")
        
        if frequency:
            return {
                "id": "dbir_social_engineering",
                "name": "Social Engineering",
                "description": "Human-targeted attacks including phishing, pretexting, and other manipulation techniques to gain unauthorized access",
                "frequency": frequency / 100.0,
                "attack_vector": "Human",
                "severity": "High", 
                "source": "DBIR 2025 PDF",
                "extraction_method": "automated_pdf_parsing",
                "mitre_techniques": ["T1566", "T1078", "T1204"],
                "detection_methods": [
                    "Email security monitoring",
                    "User behavior analytics",
                    "Security awareness metrics",
                    "Suspicious link detection"
                ],
                "affected_systems": ["Email systems", "User accounts", "Authentication systems"]
            }
        return None
    
    def _extract_dos_data(self) -> Optional[Dict[str, Any]]:
        """Extract Denial of Service attack data"""
        dos_patterns = [
            r'denial\s+of\s+service\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?denial\s+of\s+service',
            r'ddos\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?ddos'
        ]
        
        frequency = self._find_frequency_in_text(dos_patterns, "denial of service")
        
        if frequency:
            return {
                "id": "dbir_dos",
                "name": "Denial of Service",
                "description": "Attacks aimed at disrupting service availability through resource exhaustion or service interruption",
                "frequency": frequency / 100.0,
                "attack_vector": "Network",
                "severity": "Medium",
                "source": "DBIR 2025 PDF", 
                "extraction_method": "automated_pdf_parsing",
                "mitre_techniques": ["T1498", "T1499"],
                "detection_methods": [
                    "Network traffic analysis",
                    "Resource utilization monitoring", 
                    "Rate limiting enforcement",
                    "Anomaly detection"
                ],
                "affected_systems": ["Web servers", "Network infrastructure", "CDN services"]
            }
        return None
    
    def _extract_additional_patterns(self) -> List[Dict[str, Any]]:
        """Extract additional attack patterns from text analysis"""
        additional_patterns = []
        
        # Look for other common attack types mentioned in the text
        attack_keywords = [
            ("malware", "Malware"),
            ("ransomware", "Ransomware"),
            ("credential", "Credential Attacks"),
            ("insider", "Insider Threats"),
            ("supply chain", "Supply Chain Attacks"),
            ("cloud", "Cloud Security Incidents"),
            ("iot", "IoT Security Incidents"),
            ("mobile", "Mobile Security Incidents")
        ]
        
        for keyword, attack_name in attack_keywords:
            patterns = [
                rf'{keyword}\s+.*?(\d+\.?\d*)%',
                rf'(\d+\.?\d*)%.*?{keyword}'
            ]
            
            frequency = self._find_frequency_in_text(patterns, keyword)
            
            if frequency and frequency > 5.0:  # Only include if frequency > 5%
                additional_patterns.append({
                    "id": f"dbir_{keyword.replace(' ', '_')}",
                    "name": attack_name,
                    "description": f"Security incidents related to {attack_name.lower()}",
                    "frequency": frequency / 100.0,
                    "attack_vector": "Various",
                    "severity": "Medium",
                    "source": "DBIR 2025 PDF",
                    "extraction_method": "keyword_based_extraction",
                    "mitre_techniques": [],
                    "detection_methods": ["General security monitoring", "Log analysis"],
                    "affected_systems": ["Various systems"]
                })
        
        return additional_patterns
    
    def _find_frequency_in_text(self, patterns: List[str], context: str) -> Optional[float]:
        """Find frequency percentage for given patterns"""
        text_lower = self.raw_text.lower()
        
        for pattern in patterns:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                try:
                    # Extract the numeric value
                    if match.groups():
                        frequency = float(match.group(1))
                        # Validate frequency range (should be reasonable percentage)
                        if 0.1 <= frequency <= 100.0:
                            logger.debug(f"Found frequency {frequency}% for {context}")
                            return frequency
                except (ValueError, IndexError):
                    continue
        
        return None
    
    def extract_industry_data(self) -> Dict[str, Any]:
        """Extract industry-specific breach data"""
        industries = {}
        
        # Common industry terms to look for
        industry_keywords = [
            "financial", "finance", "banking", "fintech",
            "healthcare", "medical", "hospital",
            "retail", "e-commerce", "shopping",
            "manufacturing", "industrial",
            "government", "public sector",
            "education", "academic", "university",
            "technology", "software", "saas"
        ]
        
        for industry in industry_keywords:
            patterns = [
                rf'{industry}\s+.*?(\d+\.?\d*)%',
                rf'(\d+\.?\d*)%.*?{industry}'
            ]
            
            frequency = self._find_frequency_in_text(patterns, industry)
            if frequency:
                industries[industry] = frequency / 100.0
        
        return industries
    
    def extract_threat_actor_data(self) -> List[Dict[str, Any]]:
        """Extract threat actor information"""
        threat_actors = []
        
        # Look for external vs internal threat data
        external_freq = self._find_frequency_in_text([
            r'external\s+.*?(\d+\.?\d*)%',
            r'(\d+\.?\d*)%.*?external'
        ], "external threats")
        
        if external_freq:
            threat_actors.append({
                "type": "External",
                "frequency": external_freq / 100.0,
                "source": "DBIR 2025 PDF"
            })
        
        internal_freq = self._find_frequency_in_text([
            r'internal\s+.*?(\d+\.?\d*)%', 
            r'(\d+\.?\d*)%.*?internal',
            r'insider\s+.*?(\d+\.?\d*)%'
        ], "internal threats")
        
        if internal_freq:
            threat_actors.append({
                "type": "Internal", 
                "frequency": internal_freq / 100.0,
                "source": "DBIR 2025 PDF"
            })
        
        return threat_actors
    
    def save_extracted_data(self, output_path: str) -> bool:
        """Save extracted data to JSON file"""
        try:
            extracted_data = {
                "source": "DBIR 2025 PDF Report",
                "extraction_date": "2025-01-19",
                "pdf_path": str(self.pdf_path),
                "attack_patterns": self.extract_attack_patterns(),
                "industry_data": self.extract_industry_data(),
                "threat_actors": self.extract_threat_actor_data(),
                "metadata": {
                    "total_pages": len(self.pages_text),
                    "extraction_method": "PyPDF2 + regex patterns"
                }
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(extracted_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved extracted DBIR data to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving extracted data: {e}")
            return False