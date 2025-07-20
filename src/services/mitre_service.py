import json
import requests
import subprocess
import asyncio
from typing import List, Dict, Any
import os
from loguru import logger
from src.models.base import MitreAttackTechnique
from src.services.community_mcp_client import CommunityMCPClient

class MitreService:
    """Service for interacting with MITRE ATT&CK framework"""
    
    def __init__(self):
        self.mitre_url = os.getenv("MITRE_ATTACK_URL", 
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        self.techniques_cache = None
        
        # Initialize Community MCP
        self.mcp_server_path = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-community", "mitre-attack-mcp-server.py")
        self.mcp_data_path = os.path.join(os.path.dirname(__file__), "..", "..", "mcp-community", "data")
        self.community_mcp = CommunityMCPClient(self.mcp_server_path, self.mcp_data_path)
        
        if self.community_mcp.is_available():
            logger.info("Community MCP initialized successfully")
            logger.info(f"MCP Server info: {self.community_mcp.get_server_info()}")
            # Note: MCP data will be initialized lazily on first use
        else:
            logger.warning("Community MCP not available, using fallback methods")
        
        self._load_mitre_data()
    
    def _initialize_community_mcp(self):
        """Force initialization of Community MCP data"""
        try:
            # Import the MCP server module to trigger initialization
            import sys
            import importlib.util
            
            mcp_dir = os.path.dirname(self.mcp_server_path)
            if mcp_dir not in sys.path:
                sys.path.insert(0, mcp_dir)
            
            # Load the module dynamically
            spec = importlib.util.spec_from_file_location("mitre_attack_mcp_server", self.mcp_server_path)
            if spec is None or spec.loader is None:
                logger.warning("Could not load MCP server module for initialization")
                return
                
            module = importlib.util.module_from_spec(spec)
            
            # Temporarily set sys.argv to prevent argparse issues
            original_argv = sys.argv
            sys.argv = ['mitre-attack-mcp-server.py', self.mcp_data_path]
            
            try:
                # Execute the module to initialize it
                spec.loader.exec_module(module)
                
                # Initialize attack data with the correct data path
                if hasattr(module, 'initialize_attack_data'):
                    module.initialize_attack_data(self.mcp_data_path)
                    logger.info("Community MCP data initialized during service startup")
            finally:
                sys.argv = original_argv
                
        except Exception as e:
            logger.warning(f"Failed to initialize Community MCP data: {e}")
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data"""
        try:
            response = requests.get(self.mitre_url, timeout=30)
            response.raise_for_status()
            
            mitre_data = response.json()
            self.techniques_cache = self._parse_mitre_data(mitre_data)
            
            logger.info(f"Loaded {len(self.techniques_cache)} MITRE ATT&CK techniques")
            
        except Exception as e:
            logger.warning(f"Failed to load MITRE data: {e}. Using fallback data.")
            self.techniques_cache = self._get_fallback_techniques()
    
    def _parse_mitre_data(self, mitre_data: Dict) -> List[Dict[str, Any]]:
        """Parse MITRE ATT&CK JSON data"""
        techniques = []
        
        for obj in mitre_data.get("objects", []):
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                # Extract technique ID
                external_refs = obj.get("external_references", [])
                technique_id = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id")
                        break
                
                if technique_id:
                    # Extract tactics
                    tactics = []
                    kill_chain_phases = obj.get("kill_chain_phases", [])
                    for phase in kill_chain_phases:
                        if phase.get("kill_chain_name") == "mitre-attack":
                            tactics.append(phase.get("phase_name"))
                    
                    # Extract platforms
                    platforms = obj.get("x_mitre_platforms", [])
                    
                    technique = {
                        "technique_id": technique_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", "")[:500],  # Truncate long descriptions
                        "tactics": tactics,
                        "platforms": [p.lower() for p in platforms]
                    }
                    
                    techniques.append(technique)
        
        return techniques
    
    def _get_fallback_techniques(self) -> List[Dict[str, Any]]:
        """Fallback MITRE techniques if API is unavailable"""
        return [
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "tactics": ["initial-access", "persistence", "privilege-escalation", "defense-evasion"],
                "platforms": ["linux", "macos", "windows", "azure-ad", "office-365", "saas", "iaas", "google-workspace"]
            },
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "tactics": ["initial-access"],
                "platforms": ["linux", "macos", "windows", "network"]
            },
            {
                "technique_id": "T1562",
                "name": "Impair Defenses",
                "description": "Adversaries may maliciously modify components of a victim's environment in order to hinder or disable defensive mechanisms.",
                "tactics": ["defense-evasion"],
                "platforms": ["linux", "macos", "windows", "office-365", "iaas", "saas"]
            },
            {
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "tactics": ["execution"],
                "platforms": ["linux", "macos", "windows", "network"]
            },
            {
                "technique_id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "tactics": ["exfiltration"],
                "platforms": ["linux", "macos", "windows"]
            },
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
                "tactics": ["defense-evasion", "privilege-escalation"],
                "platforms": ["linux", "macos", "windows"]
            },
            {
                "technique_id": "T1566",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "tactics": ["initial-access"],
                "platforms": ["linux", "macos", "windows", "office-365", "saas", "google-workspace"]
            },
            {
                "technique_id": "T1210",
                "name": "Exploitation of Remote Services",
                "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
                "tactics": ["lateral-movement"],
                "platforms": ["linux", "macos", "windows"]
            },
            {
                "technique_id": "T1083",
                "name": "File and Directory Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                "tactics": ["discovery"],
                "platforms": ["linux", "macos", "windows"]
            },
            {
                "technique_id": "T1087",
                "name": "Account Discovery",
                "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a victim's environment.",
                "tactics": ["discovery"],
                "platforms": ["linux", "macos", "windows", "azure-ad", "office-365", "saas", "iaas", "google-workspace"]
            },
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "tactics": ["credential-access"],
                "platforms": ["linux", "macos", "windows", "azure-ad", "office-365", "saas", "iaas", "google-workspace"]
            },
            {
                "technique_id": "T1505",
                "name": "Server Software Component",
                "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.",
                "tactics": ["persistence"],
                "platforms": ["linux", "windows", "network"]
            }
        ]
    
    async def search_techniques(self, detector_name: str, detector_description: str) -> List[MitreAttackTechnique]:
        """Search for relevant MITRE techniques using Community MCP"""
        
        # First try Community MCP
        query = f"{detector_name} {detector_description}"
        try:
            if self.community_mcp.is_available():
                mcp_results = await self.community_mcp.search_techniques_by_content(query)
                if mcp_results:
                    logger.info(f"Community MCP found {len(mcp_results)} techniques for query: {query}")
                    # Try to convert with better error handling
                    valid_techniques = []
                    for i, tech in enumerate(mcp_results):
                        try:
                            # Log first few for debugging
                            if i < 3:
                                logger.info(f"Processing technique {i}: {tech}")
                            
                            # Ensure all required fields exist
                            if 'technique_id' not in tech and 'attack_id' in tech:
                                tech['technique_id'] = tech['attack_id']
                            if 'tactics' not in tech or not tech['tactics']:
                                tech['tactics'] = ['unknown']
                            if 'platforms' not in tech or not tech['platforms']:
                                tech['platforms'] = ['unknown']
                            if 'name' not in tech:
                                tech['name'] = 'Unknown Technique'
                            if 'description' not in tech:
                                tech['description'] = ''
                            
                            # Clean up extra fields that might cause issues
                            clean_tech = {
                                'technique_id': tech.get('technique_id', tech.get('attack_id', 'T0000')),
                                'name': tech.get('name', 'Unknown'),
                                'description': tech.get('description', ''),
                                'tactics': tech.get('tactics', ['unknown']),
                                'platforms': tech.get('platforms', ['unknown'])
                            }
                            
                            valid_techniques.append(MitreAttackTechnique(**clean_tech))
                            
                        except Exception as validation_error:
                            logger.error(f"Technique validation failed for item {i}: {validation_error}")
                            logger.error(f"Problematic data: {tech}")
                            continue
                    
                    logger.info(f"Successfully converted {len(valid_techniques)} out of {len(mcp_results)} techniques")
                    if valid_techniques:
                        return valid_techniques
        except Exception as e:
            logger.warning(f"Community MCP query failed, using fallback: {e}")
        
        # Fallback to keyword-based search
        return await self._search_techniques_fallback(detector_name, detector_description)
    
    async def _search_techniques_fallback(self, detector_name: str, detector_description: str) -> List[MitreAttackTechnique]:
        """Fallback search when MCP is not available"""
        if not self.techniques_cache:
            return []
        
        relevant_techniques = []
        search_terms = (detector_name + " " + detector_description).lower()
        
        # Keywords mapping to technique types
        keyword_mappings = {
            "authentication": ["T1078", "T1110", "T1556"],
            "login": ["T1078", "T1110"],
            "api": ["T1190", "T1078"],
            "web": ["T1190", "T1566"],
            "network": ["T1210", "T1046"],
            "database": ["T1078", "T1083"],
            "file": ["T1083", "T1005"],
            "process": ["T1055", "T1057"],
            "service": ["T1505", "T1543"],
            "script": ["T1059"],
            "phishing": ["T1566"],
            "brute": ["T1110"],
            "credential": ["T1078", "T1110", "T1555"],
            "privilege": ["T1068", "T1055"],
            "lateral": ["T1210", "T1021"],
            "persistence": ["T1505", "T1543", "T1078"],
            "exfiltration": ["T1041", "T1048"],
            "discovery": ["T1083", "T1087", "T1018"]
        }
        
        # Find matching techniques
        matched_technique_ids = set()
        for keyword, technique_ids in keyword_mappings.items():
            if keyword in search_terms:
                matched_technique_ids.update(technique_ids)
        
        # Get technique details
        for technique_data in self.techniques_cache:
            if technique_data["technique_id"] in matched_technique_ids:
                technique = MitreAttackTechnique(**technique_data)
                relevant_techniques.append(technique)
        
        # If no specific matches, return some general techniques
        if not relevant_techniques:
            general_techniques = ["T1078", "T1190", "T1562"]
            for technique_data in self.techniques_cache:
                if technique_data["technique_id"] in general_techniques:
                    technique = MitreAttackTechnique(**technique_data)
                    relevant_techniques.append(technique)
        
        return relevant_techniques[:5]  # Return top 5 most relevant
    
    async def _query_community_mcp(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Query the community MCP server for MITRE techniques"""
        
        # This would integrate with the community MCP server
        # For now, we'll simulate the integration by parsing the query
        # and mapping it to the fallback techniques
        
        if not self.techniques_cache:
            return []
        
        query_lower = query.lower()
        matching_techniques = []
        
        # Search through cached techniques
        for technique in self.techniques_cache:
            if (query_lower in technique["name"].lower() or 
                query_lower in technique["description"].lower() or
                any(query_lower in tactic for tactic in technique["tactics"])):
                matching_techniques.append(technique)
        
        return matching_techniques[:limit]
    
    async def get_technique_by_id(self, technique_id: str) -> MitreAttackTechnique:
        """Get specific technique by ID"""
        for technique_data in self.techniques_cache or []:
            if technique_data["technique_id"] == technique_id:
                return MitreAttackTechnique(**technique_data)
        
        return None
    
    async def get_techniques_by_tactic(self, tactic: str) -> List[MitreAttackTechnique]:
        """Get techniques by tactic (e.g., 'initial-access', 'persistence')"""
        techniques = []
        
        for technique_data in self.techniques_cache or []:
            if tactic in technique_data.get("tactics", []):
                technique = MitreAttackTechnique(**technique_data)
                techniques.append(technique)
        
        return techniques
    
    def get_all_tactics(self) -> List[str]:
        """Get all available tactics"""
        tactics = set()
        
        for technique_data in self.techniques_cache or []:
            tactics.update(technique_data.get("tactics", []))
        
        return sorted(list(tactics))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get MITRE framework statistics"""
        if not self.techniques_cache:
            return {"error": "MITRE data not loaded"}
        
        tactic_counts = {}
        platform_counts = {}
        
        for technique in self.techniques_cache:
            # Count tactics
            for tactic in technique.get("tactics", []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            
            # Count platforms
            for platform in technique.get("platforms", []):
                platform_counts[platform] = platform_counts.get(platform, 0) + 1
        
        return {
            "total_techniques": len(self.techniques_cache),
            "total_tactics": len(tactic_counts),
            "total_platforms": len(platform_counts),
            "most_common_tactic": max(tactic_counts.items(), key=lambda x: x[1]) if tactic_counts else None,
            "most_common_platform": max(platform_counts.items(), key=lambda x: x[1]) if platform_counts else None
        }