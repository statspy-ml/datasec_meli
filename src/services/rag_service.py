import json
import os
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

from src.services.chroma_config import configure_chroma_silent

configure_chroma_silent()

import chromadb
from sentence_transformers import SentenceTransformer

from src.services.pdf_processor import DBIRPDFProcessor


class RAGService:
    """RAG service for querying attack patterns and security knowledge"""

    def __init__(self):
        self.client = chromadb.Client()
        self.collection_name = "security_knowledge"
        self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        self.collection = None
        self.dbir_pdf_path = "data/mitre-attack/2025-dbir-data-breach-investigations-report.pdf"
        self.cache_path = "data/mitre-attack/dbir_extracted_data.json"
        self._initialize_collection()

    def _initialize_collection(self):
        """Initialize ChromaDB collection with security knowledge"""
        try:
            # Try to get existing collection
            self.collection = self.client.get_collection(self.collection_name)
            logger.info("Loaded existing security knowledge collection")
        except:
            # Create new collection
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "Security attack patterns and knowledge base"},
            )
            self._populate_collection()
            logger.info("Created new security knowledge collection")

    def _populate_collection(self):
        """Populate collection with security knowledge base from DBIR PDF and fallback patterns"""
        # Try to load real DBIR data first
        real_patterns = self._load_dbir_patterns()

        if real_patterns:
            logger.info(f"Loading {len(real_patterns)} real patterns from DBIR PDF")
            self._add_patterns_to_collection(real_patterns)
        else:
            logger.info("Loading fallback security patterns")
            fallback_patterns = self._get_fallback_patterns()
            self._add_patterns_to_collection(fallback_patterns)

    def _load_dbir_patterns(self) -> List[Dict[str, Any]]:
        """Load real patterns from DBIR PDF or cache"""
        # Try to load from cache first
        if Path(self.cache_path).exists():
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    cached_data = json.load(f)
                    patterns = cached_data.get("attack_patterns", [])
                    if patterns:
                        logger.info(f"Loaded {len(patterns)} patterns from cache")
                        return patterns
            except Exception as e:
                logger.warning(f"Error loading cached data: {e}")

        # Try to extract from PDF
        if Path(self.dbir_pdf_path).exists():
            try:
                logger.info("Extracting patterns from DBIR PDF...")
                processor = DBIRPDFProcessor(self.dbir_pdf_path)
                patterns = processor.extract_attack_patterns()

                if patterns:
                    # Save to cache for future use
                    processor.save_extracted_data(self.cache_path)
                    logger.info(f"Extracted and cached {len(patterns)} patterns from PDF")
                    return patterns

            except Exception as e:
                logger.error(f"Error extracting from PDF: {e}")

        return []

    def _add_patterns_to_collection(self, patterns: List[Dict[str, Any]]):
        """Add patterns to ChromaDB collection"""
        documents = []
        metadatas = []
        ids = []

        for pattern in patterns:
            # Create searchable document from pattern
            description = pattern.get("description", "")
            detection_methods = " ".join(pattern.get("detection_methods", []))
            affected_systems = " ".join(pattern.get("affected_systems", []))

            document = f"{pattern.get('name', '')} {description} {detection_methods} {affected_systems}"
            documents.append(document)

            # Metadata for filtering and retrieval
            metadata = {
                "title": pattern.get("name", "Unknown"),
                "attack_vector": pattern.get("attack_vector", "Unknown"),
                "severity": pattern.get("severity", "Medium"),
                "mitre_techniques": ",".join(pattern.get("mitre_techniques", [])),
                "detection_methods": ",".join(pattern.get("detection_methods", [])),
                "affected_systems": ",".join(pattern.get("affected_systems", [])),
                "source": pattern.get("source", "Unknown"),
                "frequency": str(pattern.get("frequency", 0.0)),
            }
            metadatas.append(metadata)
            ids.append(pattern.get("id", f"pattern_{len(ids) + 1}"))

        # Add to collection
        if documents:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
            logger.info(f"Added {len(documents)} patterns to ChromaDB collection")

    # In case of fialure to extract from PDF, use fallback patterns TODO: is this allowed?
    def _get_fallback_patterns(self) -> List[Dict[str, Any]]:
        """Get fallback security patterns if PDF extraction fails"""
        return [
            {
                "id": "pattern_001",
                "name": "Web Application SQL Injection",
                "description": "Attackers inject malicious SQL code through web application input fields to gain unauthorized access to databases. Common in applications with poor input validation.",
                "attack_vector": "Web Application",
                "severity": "High",
                "mitre_techniques": ["T1190", "T1505.003"],
                "detection_methods": ["WAF logs analysis", "Database query monitoring", "Anomalous SQL pattern detection"],
                "affected_systems": ["Web applications", "Databases", "API endpoints"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_002",
                "name": "API Rate Limiting Bypass",
                "description": "Attackers attempt to bypass API rate limiting controls through various techniques like distributed requests, header manipulation, or endpoint enumeration.",
                "attack_vector": "API",
                "severity": "Medium",
                "mitre_techniques": ["T1190", "T1078"],
                "detection_methods": ["API gateway logs", "Request pattern analysis", "Rate limiting violation monitoring"],
                "affected_systems": ["API gateways", "Microservices", "Load balancers"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_003",
                "name": "Credential Stuffing Attacks",
                "description": "Automated attacks using stolen username/password pairs from data breaches to gain unauthorized access to user accounts across multiple services.",
                "attack_vector": "Authentication",
                "severity": "High",
                "mitre_techniques": ["T1110", "T1078"],
                "detection_methods": ["Login anomaly detection", "Geographic impossibility analysis", "Failed authentication clustering"],
                "affected_systems": ["Authentication systems", "User databases", "Session management"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_004",
                "name": "Privilege Escalation via Service Accounts",
                "description": "Attackers compromise service accounts to escalate privileges and move laterally within the infrastructure, often targeting over-privileged service accounts.",
                "attack_vector": "Identity",
                "severity": "High",
                "mitre_techniques": ["T1078.004", "T1484"],
                "detection_methods": ["Service account activity monitoring", "Privilege usage analysis", "Unusual access pattern detection"],
                "affected_systems": ["Identity management", "Service accounts", "Privileged access systems"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_005",
                "name": "Data Exfiltration via DNS Tunneling",
                "description": "Attackers use DNS queries to exfiltrate sensitive data, bypassing traditional network security controls by encoding data in DNS requests.",
                "attack_vector": "Network",
                "severity": "High",
                "mitre_techniques": ["T1041", "T1071.004"],
                "detection_methods": ["DNS query analysis", "Data size anomaly detection", "Unusual DNS pattern monitoring"],
                "affected_systems": ["DNS servers", "Network infrastructure", "Data repositories"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_006",
                "name": "Microservices Inter-Service Attack",
                "description": "Attacks targeting communication between microservices, exploiting weak authentication, unencrypted traffic, or service mesh vulnerabilities.",
                "attack_vector": "Microservices",
                "severity": "Medium",
                "mitre_techniques": ["T1210", "T1557"],
                "detection_methods": ["Service mesh monitoring", "Inter-service traffic analysis", "Authentication failure tracking"],
                "affected_systems": ["Kubernetes clusters", "Service mesh", "Container orchestration"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_007",
                "name": "Cloud Storage Misconfiguration Exploitation",
                "description": "Attackers exploit misconfigured cloud storage buckets, databases, or services to access sensitive data or establish persistence.",
                "attack_vector": "Cloud",
                "severity": "High",
                "mitre_techniques": ["T1530", "T1083"],
                "detection_methods": ["Cloud configuration monitoring", "Unauthorized access detection", "Data access pattern analysis"],
                "affected_systems": ["Cloud storage", "Cloud databases", "Cloud services"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_008",
                "name": "Supply Chain Software Compromise",
                "description": "Attackers compromise software supply chain components, including third-party libraries, CI/CD pipelines, or development tools to inject malicious code.",
                "attack_vector": "Supply Chain",
                "severity": "Critical",
                "mitre_techniques": ["T1195", "T1543"],
                "detection_methods": ["Software integrity monitoring", "CI/CD pipeline analysis", "Dependency vulnerability scanning"],
                "affected_systems": ["Development environment", "CI/CD systems", "Software repositories"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_009",
                "name": "Business Email Compromise (BEC)",
                "description": "Sophisticated phishing attacks targeting business email systems to compromise executive accounts and initiate fraudulent transactions.",
                "attack_vector": "Email",
                "severity": "High",
                "mitre_techniques": ["T1566.002", "T1078"],
                "detection_methods": ["Email behavior analysis", "Executive impersonation detection", "Financial transaction monitoring"],
                "affected_systems": ["Email systems", "Financial systems", "Executive accounts"],
                "source": "Fallback patterns",
            },
            {
                "id": "pattern_010",
                "name": "IoT Device Network Infiltration",
                "description": "Attackers compromise IoT devices to gain network access, establish persistence, or launch attacks on internal infrastructure.",
                "attack_vector": "IoT",
                "severity": "Medium",
                "mitre_techniques": ["T1078", "T1021"],
                "detection_methods": ["IoT device behavior monitoring", "Network traffic analysis", "Device authentication tracking"],
                "affected_systems": ["IoT devices", "Network infrastructure", "Device management systems"],
                "source": "Fallback patterns",
            },
        ]

    async def query_attack_patterns(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Query for relevant attack patterns based on ecosystem description"""
        try:
            # Query the collection
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k,
            )

            # Format results
            patterns = []
            if results["documents"] and results["documents"][0]:
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results["metadatas"][0][i]
                    distance = results["distances"][0][i] if "distances" in results else 0

                    pattern = {
                        "id": results["ids"][0][i],
                        "title": metadata.get("title", ""),
                        "attack_vector": metadata.get("attack_vector", ""),
                        "severity": metadata.get("severity", ""),
                        "mitre_techniques": metadata.get("mitre_techniques", "").split(","),
                        "detection_methods": metadata.get("detection_methods", "").split(","),
                        "affected_systems": metadata.get("affected_systems", "").split(","),
                        "relevance_score": 1.0 - distance,  # Convert distance to relevance
                    }
                    patterns.append(pattern)

            logger.info(f"Found {len(patterns)} relevant attack patterns for query")
            return patterns

        except Exception as e:
            logger.error(f"Error querying attack patterns: {e}")
            return []

    async def query_detection_methods(self, attack_vector: str, technologies: List[str]) -> List[Dict[str, Any]]:
        """Query for detection methods based on attack vector and technologies"""
        # Build query based on attack vector and technologies
        query = f"{attack_vector} {' '.join(technologies)} detection monitoring"

        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=5,
                where={"attack_vector": attack_vector} if attack_vector else None,
            )

            detection_methods = []
            if results["documents"] and results["documents"][0]:
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results["metadatas"][0][i]

                    methods = {
                        "attack_vector": metadata.get("attack_vector", ""),
                        "detection_methods": metadata.get("detection_methods", "").split(","),
                        "affected_systems": metadata.get("affected_systems", "").split(","),
                        "severity": metadata.get("severity", ""),
                    }
                    detection_methods.append(methods)

            return detection_methods

        except Exception as e:
            logger.error(f"Error querying detection methods: {e}")
            return []

    async def add_custom_pattern(self, pattern: Dict[str, Any]) -> bool:
        """Add a custom security pattern to the knowledge base"""
        try:
            # Create searchable document
            document = f"{pattern['title']} {pattern['description']} {' '.join(pattern.get('detection_methods', []))}"

            # Metadata
            metadata = {
                "title": pattern["title"],
                "attack_vector": pattern.get("attack_vector", "Unknown"),
                "severity": pattern.get("severity", "Medium"),
                "mitre_techniques": ",".join(pattern.get("mitre_techniques", [])),
                "detection_methods": ",".join(pattern.get("detection_methods", [])),
                "affected_systems": ",".join(pattern.get("affected_systems", [])),
            }

            # Add to collection
            self.collection.add(
                documents=[document],
                metadatas=[metadata],
                ids=[pattern.get("id", f"custom_{len(self.collection.get()['ids']) + 1}")],
            )

            logger.info(f"Added custom pattern: {pattern['title']}")
            return True

        except Exception as e:
            logger.error(f"Error adding custom pattern: {e}")
            return False

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        try:
            data = self.collection.get()

            # Count by attack vector
            attack_vectors = {}
            severities = {}

            for metadata in data.get("metadatas", []):
                vector = metadata.get("attack_vector", "Unknown")
                severity = metadata.get("severity", "Unknown")

                attack_vectors[vector] = attack_vectors.get(vector, 0) + 1
                severities[severity] = severities.get(severity, 0) + 1

            return {
                "total_patterns": len(data.get("ids", [])),
                "attack_vectors": attack_vectors,
                "severities": severities,
                "collection_name": self.collection_name,
            }

        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {"error": str(e)}

