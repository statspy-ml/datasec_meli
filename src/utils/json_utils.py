"""
JSON serialization utilities
"""

import json
from typing import Any, Dict, List
from pydantic import BaseModel

def make_json_serializable(obj: Any, _seen: set = None) -> Any:
    """Convert objects to JSON serializable format with recursion protection"""
    
    if _seen is None:
        _seen = set()
    
    # Prevent infinite recursion
    obj_id = id(obj)
    if obj_id in _seen:
        return f"<circular reference to {type(obj).__name__}>"
    
    # Basic JSON-serializable types
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    
    _seen.add(obj_id)
    
    try:
        if isinstance(obj, BaseModel):
            # Convert Pydantic models to dict
            result = obj.dict()
        elif isinstance(obj, (list, tuple)):
            # Convert lists/tuples recursively
            result = [make_json_serializable(item, _seen) for item in obj]
        elif isinstance(obj, set):
            # Convert sets to lists
            result = [make_json_serializable(item, _seen) for item in obj]
        elif isinstance(obj, dict):
            # Convert dict values recursively
            result = {str(key): make_json_serializable(value, _seen) for key, value in obj.items()}
        elif hasattr(obj, 'keys') and hasattr(obj, 'values'):
            # Handle dict-like objects including mappingproxy
            result = {str(key): make_json_serializable(value, _seen) for key, value in obj.items()}
        elif hasattr(obj, '__dict__'):
            # Convert objects with __dict__ to dict
            result = make_json_serializable(obj.__dict__, _seen)
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            # Handle other iterables (like dict_keys, dict_values)
            try:
                result = [make_json_serializable(item, _seen) for item in obj]
            except:
                result = str(obj)
        else:
            # Return string representation for unknown types
            result = str(obj)
    finally:
        _seen.discard(obj_id)
    
    return result

def safe_json_dumps(obj: Any, **kwargs) -> str:
    """Safely convert object to JSON string"""
    try:
        return json.dumps(make_json_serializable(obj), **kwargs)
    except Exception as e:
        # Fallback to string representation
        return json.dumps({"error": f"JSON serialization failed: {str(e)}", "type": str(type(obj))})

def convert_detector_for_json(detector: Any) -> Dict[str, Any]:
    """Convert SecurityDetector to JSON-safe dict"""
    if hasattr(detector, 'dict'):
        detector_dict = detector.dict()
    else:
        detector_dict = dict(detector) if isinstance(detector, dict) else {"raw": str(detector)}
    
    # Handle MITRE techniques specifically
    if "mitre_techniques" in detector_dict:
        mitre_techniques = detector_dict["mitre_techniques"]
        if mitre_techniques:
            detector_dict["mitre_techniques"] = [
                technique.dict() if hasattr(technique, 'dict') else 
                dict(technique) if isinstance(technique, dict) else
                {"technique_info": str(technique)}
                for technique in mitre_techniques
            ]
    
    return detector_dict