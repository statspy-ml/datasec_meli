"""
Adaptive detector generation based on system context
"""
from typing import List
from src.models.base import EcosystemContext, SecurityDetector

def get_adaptive_detectors(context: EcosystemContext) -> List[SecurityDetector]:
    """Return adaptive default detectors based on context"""
    defaults = []
    
    # Universal detectors (always included)
    defaults.extend([
        SecurityDetector(
            name="Unusual Login Patterns",
            description="Detect suspicious authentication attempts and credential stuffing",
            priority="high",
            risk_score=8.5,
            impact_level="high",
            implementation_effort="medium",
            rationale="Authentication attacks are common according to DBIR 2025",
            mitre_techniques=[],
        ),
        SecurityDetector(
            name="Data Exfiltration Detection", 
            description="Monitor for unusual data access patterns and data transfer anomalies",
            priority="high",
            risk_score=9.2 if context.data_sensitivity == "high" else 7.5,
            impact_level="critical" if context.data_sensitivity == "high" else "high",
            implementation_effort="high",
            rationale="Data breaches have high impact on business and compliance",
            mitre_techniques=[],
        ),
    ])
    
    # API-specific detectors
    if "api" in context.technologies:
        defaults.append(SecurityDetector(
            name="API Security Monitoring",
            description="Detect API abuse, rate limiting violations, and injection attacks",
            priority="high",
            risk_score=8.8,
            impact_level="high", 
            implementation_effort="medium",
            rationale="API attacks are prevalent in web applications",
            mitre_techniques=[],
        ))
    
    # Container/Kubernetes detectors (only if actually using containers)
    if context.architecture_type == "containerized" or "kubernetes" in context.technologies:
        defaults.append(SecurityDetector(
            name="Container Runtime Monitoring",
            description="Monitor for malicious container activity and escape attempts",
            priority="high",
            risk_score=8.0,
            impact_level="high",
            implementation_effort="medium",
            rationale="Container security is critical in containerized environments",
            mitre_techniques=[],
        ))
    
    # Microservices-specific detectors (only for microservices)
    if context.architecture_type == "microservices":
        defaults.append(SecurityDetector(
            name="Service Mesh Security Monitoring",
            description="Monitor inter-service communication for suspicious patterns",
            priority="medium",
            risk_score=7.5,
            impact_level="high",
            implementation_effort="medium",
            rationale="Service-to-service attacks can bypass perimeter security",
            mitre_techniques=[],
        ))
    
    # Database detectors
    if "database" in context.technologies:
        defaults.append(SecurityDetector(
            name="Database Anomaly Detection",
            description="Detect SQL injection, data harvesting, and unauthorized queries",
            priority="high",
            risk_score=8.7,
            impact_level="critical",
            implementation_effort="medium",
            rationale="Database attacks threaten core business data",
            mitre_techniques=[],
        ))
    
    # Payment/Financial detectors
    if "payment" in context.technologies or "PCI-DSS" in context.compliance_requirements:
        defaults.append(SecurityDetector(
            name="Payment Fraud Detection",
            description="Monitor for fraudulent transactions and payment anomalies",
            priority="high",
            risk_score=9.5,
            impact_level="critical",
            implementation_effort="high",
            rationale="Payment fraud directly impacts business and PCI-DSS compliance",
            mitre_techniques=[],
        ))
    
    # ML/AI specific detectors
    if "ml" in context.technologies:
        defaults.append(SecurityDetector(
            name="ML Model Integrity Monitoring",
            description="Detect model poisoning, adversarial attacks, and data drift",
            priority="high",
            risk_score=8.3,
            impact_level="high",
            implementation_effort="high",
            rationale="ML models are critical business assets requiring protection",
            mitre_techniques=[],
        ))
    
    # Biometric specific detectors
    if "biometric" in context.technologies:
        defaults.append(SecurityDetector(
            name="Biometric Authentication Bypass Detection",
            description="Monitor for spoofing attempts and biometric system compromises",
            priority="high",
            risk_score=8.9,
            impact_level="high",
            implementation_effort="medium",
            rationale="Biometric bypasses can compromise identity verification",
            mitre_techniques=[],
        ))
    
    # Celery/Task Queue specific detectors
    if "celery" in context.technologies:
        defaults.append(SecurityDetector(
            name="Task Queue Security Monitoring", 
            description="Detect malicious tasks, queue poisoning, and unauthorized job execution",
            priority="medium",
            risk_score=7.2,
            impact_level="medium",
            implementation_effort="medium",
            rationale="Task queues can be exploited for privilege escalation",
            mitre_techniques=[],
        ))
    
    # Compliance-specific detectors
    if "LGPD" in context.compliance_requirements:
        defaults.append(SecurityDetector(
            name="LGPD Compliance Monitoring",
            description="Monitor data processing activities for LGPD compliance violations",
            priority="medium",
            risk_score=7.8,
            impact_level="high",
            implementation_effort="medium",
            rationale="LGPD violations can result in significant fines",
            mitre_techniques=[],
        ))
    
    # Deployment-specific detectors
    if hasattr(context, 'deployment_type'):
        if context.deployment_type == "cloud":
            defaults.append(SecurityDetector(
                name="Cloud Configuration Drift Detection",
                description="Monitor for unauthorized changes to cloud infrastructure",
                priority="medium",
                risk_score=7.3,
                impact_level="medium",
                implementation_effort="low",
                rationale="Cloud misconfigurations are common attack vectors",
                mitre_techniques=[],
            ))
        elif context.deployment_type == "on-premise":
            defaults.append(SecurityDetector(
                name="Network Perimeter Monitoring",
                description="Monitor network boundaries for intrusion attempts",
                priority="medium",
                risk_score=7.6,
                impact_level="high",
                implementation_effort="medium",
                rationale="On-premise environments rely on network perimeter security",
                mitre_techniques=[],
            ))
    
    return defaults