"""
Client to interact with the Community MITRE ATT&CK MCP Server
"""

import json
import subprocess
import asyncio
import os
from typing import List, Dict, Any, Optional
from loguru import logger

# Global cache for modules (shared across all instances)
_global_module_cache = {}
_global_initialized_modules = set()

class CommunityMCPClient:
    """Client for the Community MITRE ATT&CK MCP Server"""
    
    def __init__(self, mcp_server_path: str, data_path: str):
        self.mcp_server_path = mcp_server_path
        self.data_path = data_path
        self.server_available = os.path.exists(mcp_server_path)
        
        if self.server_available:
            # Ensure data directory exists
            os.makedirs(data_path, exist_ok=True)
    
    async def _call_mcp_function(self, function_name: str, params: dict) -> List[Dict[str, Any]]:
        """Call MCP function by importing and executing it directly"""
        try:
            # Check if module is already cached globally
            module_key = self.mcp_server_path
            if module_key not in _global_module_cache:
                # Import the MCP server module using importlib
                import sys
                import importlib.util
                
                mcp_dir = os.path.dirname(self.mcp_server_path)
                if mcp_dir not in sys.path:
                    sys.path.insert(0, mcp_dir)
                
                # Load the module dynamically
                spec = importlib.util.spec_from_file_location("mitre_attack_mcp_server", self.mcp_server_path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load module from {self.mcp_server_path}")
                    
                module = importlib.util.module_from_spec(spec)
                
                # Temporarily set sys.argv to prevent argparse issues
                original_argv = sys.argv
                sys.argv = ['mitre-attack-mcp-server.py', self.data_path]
                
                try:
                    # Execute the module to initialize it
                    spec.loader.exec_module(module)
                    
                    # Initialize attack data with the correct data path (only once globally)
                    if hasattr(module, 'initialize_attack_data') and module_key not in _global_initialized_modules:
                        module.initialize_attack_data(self.data_path)
                        _global_initialized_modules.add(module_key)
                        logger.info(f"MCP Client: Initialized MITRE ATT&CK data for {module_key}")
                    else:
                        logger.debug(f"MCP Client: Skipping initialization, already done for {module_key}")
                finally:
                    sys.argv = original_argv
                
                # Cache the module globally
                _global_module_cache[module_key] = module
            else:
                # Use cached module
                module = _global_module_cache[module_key]
            
            # Get the function
            func = getattr(module, function_name)
            
            # Call the function
            result = await func(**params)
            
            # Parse the result
            return self._parse_mcp_response(result)
            
        except Exception as e:
            logger.error(f"Failed to call MCP function {function_name}: {e}")
            return []
    
    def _parse_mcp_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse MCP response string into structured data"""
        if not response or "No matching objects found" in response:
            return []
            
        techniques = []
        lines = response.split('\n')
        current_technique = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_technique:
                    # Ensure required fields are present
                    if self._validate_technique_data(current_technique):
                        techniques.append(current_technique)
                    current_technique = {}
                continue
                
            if line.startswith('ATT&CK ID:') or line.startswith('ID:'):
                attack_id = line.split(':', 1)[1].strip()
                current_technique['technique_id'] = attack_id
                current_technique['attack_id'] = attack_id  # Keep both for compatibility
            elif line.startswith('Name:'):
                current_technique['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('Description:'):
                current_technique['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('Tactics:'):
                tactics_str = line.split(':', 1)[1].strip()
                current_technique['tactics'] = [t.strip() for t in tactics_str.split(',') if t.strip()]
            elif line.startswith('Platforms:'):
                platforms_str = line.split(':', 1)[1].strip()
                current_technique['platforms'] = [p.strip().lower() for p in platforms_str.split(',') if p.strip()]
        
        if current_technique:
            if self._validate_technique_data(current_technique):
                techniques.append(current_technique)
            
        return techniques
    
    def _validate_technique_data(self, technique: Dict[str, Any]) -> bool:
        """Validate and fix technique data to match MitreAttackTechnique model"""
        # Ensure required fields exist with proper defaults
        
        # Handle technique_id
        if 'technique_id' not in technique or not technique['technique_id']:
            if 'attack_id' in technique and technique['attack_id']:
                technique['technique_id'] = technique['attack_id']
            else:
                # Generate a fallback ID
                name_hash = hash(technique.get('name', 'unknown'))
                technique['technique_id'] = f"T{abs(name_hash) % 9999:04d}"
        
        # Handle name
        if 'name' not in technique or not technique['name']:
            technique['name'] = "Unknown Technique"
        
        # Handle description
        if 'description' not in technique:
            technique['description'] = technique.get('name', 'No description available')
        
        # Handle tactics - ensure it's always a list
        if 'tactics' not in technique or not isinstance(technique['tactics'], list):
            technique['tactics'] = ['unknown']  # Default tactic instead of empty
        
        # Handle platforms - ensure it's always a list  
        if 'platforms' not in technique or not isinstance(technique['platforms'], list):
            technique['platforms'] = ['unknown']  # Default platform instead of empty
        
        # Ensure tactics and platforms are not empty
        if not technique['tactics']:
            technique['tactics'] = ['unknown']
        if not technique['platforms']:
            technique['platforms'] = ['unknown']
        
        # Truncate description if too long
        if len(technique['description']) > 500:
            technique['description'] = technique['description'][:500] + "..."
        
        return True
    
    async def get_all_techniques(self, domain: str = "enterprise", include_description: bool = False) -> List[Dict[str, Any]]:
        """Get all techniques from the community MCP"""
        if not self.server_available:
            return []
        
        try:
            # Call MCP server directly
            result = await self._call_mcp_function("get_all_techniques", {
                "domain": domain,
                "include_description": include_description
            })
            logger.info(f"Retrieved {len(result)} techniques from community MCP")
            return result
        except Exception as e:
            logger.error(f"Failed to query community MCP: {e}")
            return []
    
    async def search_techniques_by_content(self, content: str, domain: str = "enterprise") -> List[Dict[str, Any]]:
        """Search techniques by content using community MCP"""
        if not self.server_available:
            return []
        
        try:
            # Try multiple search strategies
            results = []
            
            # Strategy 1: Direct content search
            result1 = await self._call_mcp_function("get_objects_by_content", {
                "content": content,
                "object_type": "attack-pattern",
                "domain": domain,
                "include_description": True
            })
            results.extend(result1)
            
            # Strategy 2: Extract keywords and search
            keywords = self._extract_keywords(content)
            for keyword in keywords[:3]:  # Limit to top 3 keywords
                try:
                    result2 = await self._call_mcp_function("get_objects_by_content", {
                        "content": keyword,
                        "object_type": "attack-pattern", 
                        "domain": domain,
                        "include_description": True
                    })
                    results.extend(result2)
                except:
                    continue
            
            # Remove duplicates
            unique_results = []
            seen_ids = set()
            for result in results:
                result_id = result.get('attack_id') or result.get('name')
                if result_id and result_id not in seen_ids:
                    unique_results.append(result)
                    seen_ids.add(result_id)
            
            logger.info(f"Found {len(unique_results)} techniques matching content: {content}")
            return unique_results
            
        except Exception as e:
            logger.error(f"Failed to search community MCP: {e}")
            return []
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extract relevant keywords from content for search"""
        # Common security keywords mapping
        security_keywords = {
            'authentication': ['authentication', 'credential', 'login', 'access'],
            'database': ['database', 'sql', 'query', 'data'],
            'api': ['api', 'web', 'http', 'endpoint'],
            'network': ['network', 'traffic', 'communication'],
            'container': ['container', 'docker', 'kubernetes'],
            'privilege': ['privilege', 'escalation', 'elevation'],
            'monitoring': ['monitoring', 'detection', 'analysis'],
            'fraud': ['fraud', 'transaction', 'financial'],
            'code': ['code', 'application', 'vulnerability'],
            'configuration': ['configuration', 'setting', 'policy']
        }
        
        content_lower = content.lower()
        keywords = []
        
        # Find matching security domains
        for domain, terms in security_keywords.items():
            if any(term in content_lower for term in terms):
                keywords.extend(terms)
        
        # Add direct words if they seem relevant
        words = content_lower.split()
        for word in words:
            if len(word) > 4 and word not in keywords:
                keywords.append(word)
        
        return list(set(keywords))  # Remove duplicates
    
    async def get_technique_by_attack_id(self, attack_id: str, domain: str = "enterprise") -> Optional[Dict[str, Any]]:
        """Get technique by ATT&CK ID using community MCP"""
        if not self.server_available:
            return None
        
        try:
            # Call MCP server for specific technique
            result = await self._call_mcp_function("get_object_by_attack_id", {
                "attack_id": attack_id,
                "stix_type": "attack-pattern",
                "domain": domain,
                "include_description": True
            })
            if result:
                logger.info(f"Retrieved technique {attack_id} from community MCP")
                return result[0]
            return None
        except Exception as e:
            logger.error(f"Failed to get technique from community MCP: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if community MCP is available"""
        return self.server_available
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get information about the MCP server"""
        return {
            "server_path": self.mcp_server_path,
            "data_path": self.data_path,
            "available": self.server_available,
            "type": "Community MITRE ATT&CK MCP"
        }