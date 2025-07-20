import json
from datetime import datetime
from typing import Any, Dict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(
    page_title="DataSec Challenge - Security Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Configurações
API_BASE_URL = "http://datasec-api:8000"

# CSS customizado
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .detector-card {
        background-color: #ffffff;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .risk-high { border-left: 5px solid #ff4444; }
    .risk-medium { border-left: 5px solid #ffaa00; }
    .risk-low { border-left: 5px solid #00aa44; }
</style>
""", unsafe_allow_html=True)

def main():
    st.markdown('<h1 class="main-header"> DataSec Challenge</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; font-size: 1.2rem; color: #666;">Sistema Multi-Agente para Análise de Segurança</p>', unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.header("Configurações")

        # Entregar alguns exemoplos pre-prefinidos para facilitar avaliação
        example_type = st.selectbox(
            "Escolha um exemplo:",
            ["Customizado", "E-commerce", "Healthcare", "SaaS"],
        )

        st.subheader("Contexto Adicional")
        industry = st.selectbox(
            "Setor:",
            ["", "retail", "financial_services", "healthcare", "technology", "manufacturing"],
        )

        compliance = st.multiselect(
            "Conformidade:",
            ["PCI-DSS", "GDPR", "LGPD", "HIPAA", "ISO-27001"],
        )


    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Descrição do Ecosistema")

        example_text = get_example_text(example_type)

        ecosystem_description = st.text_area(
            "Descreva seu sistema de TI:",
            value=example_text,
            height=200,
            help="Inclua arquitetura, tecnologias, dados sensíveis, usuários, etc.",
        )

        if st.button("Analisar Sistema", type="primary", use_container_width=True):
            if ecosystem_description.strip():
                analyze_system(ecosystem_description, industry, compliance)
            else:
                st.error("Por favor, forneça uma descrição do sistema.")

def get_example_text(example_type: str) -> str:
    """Retorna texto de exemplo baseado no tipo selecionado"""
    examples = {
        "E-commerce": """Plataforma de e-commerce B2C com arquitetura de microserviços:
- 15 microserviços containerizados em Kubernetes
- API Gateway Kong para roteamento
- Bases de dados: PostgreSQL (transações), MongoDB (catálogo), Redis (cache)
- Sistema de pagamentos: Stripe + PayPal
- Frontend React.js com CDN Cloudflare  
- Autenticação via JWT + OAuth2
- Processamento de dados PII e cartões de crédito
- 500.000 usuários ativos mensais
- 50.000 transações por dia
- Compliance PCI-DSS obrigatório""",

        "Healthcare": """Sistema de gestão hospitalar integrado:
- Aplicação web monolítica em Java/Spring Boot
- Base de dados Oracle com registros médicos (EHR)
- Integração com equipamentos médicos via protocolo HL7
- Sistema de PACS para imagens médicas (DICOM)  
- Portal do paciente para acesso a exames e resultados
- Telemedicina com videoconferência segura
- Backup em nuvem híbrida (local + AWS)
- 5.000 funcionários, 50.000 pacientes cadastrados
- Conformidade HIPAA e LGPD obrigatória""",

        "SaaS": """Plataforma SaaS B2B multi-tenant:
- Arquitetura serverless na AWS (Lambda + API Gateway)
- Banco de dados PostgreSQL com isolamento por tenant
- Frontend Angular com autenticação SSO
- APIs RESTful e GraphQL para integrações
- Sistema de billing automatizado
- Logs centralizados no ElasticSearch
- CI/CD automatizado com GitLab
- 1.000 clientes enterprise, 100.000 usuários finais
- Processamento de dados corporativos sensíveis""",
    }

    return examples.get(example_type, "")

def check_api_health():
    """Verifica o status da API"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            st.success("API Online")
            health_data = response.json()
            st.json(health_data)
        else:
            st.error("API com problemas")
    except requests.exceptions.RequestException:
        st.error("API não disponível")
        st.info("Certifique-se de que a API está rodando em http://localhost:8000")

def analyze_system(description: str, industry: str, compliance: list):
    """Executa a análise do sistema"""
    # Preparar dados da requisição
    additional_context = {}
    if industry:
        additional_context["industry"] = industry
    if compliance:
        additional_context["compliance_requirements"] = compliance

    request_data = {
        "ecosystem_description": description,
        "additional_context": additional_context if additional_context else None,
    }

    with st.spinner("Analisando sistema... Isso pode levar alguns minutos."):
        try:
            response = requests.post(
                f"{API_BASE_URL}/analyze",
                json=request_data,
                timeout=300,  # 5 minutos
            )

            if response.status_code == 200:
                result = response.json()
                display_analysis_results(result)
            else:
                st.error(f"Erro na análise: {response.status_code}")
                st.json(response.json())

        except requests.exceptions.Timeout:
            st.error("Timeout na análise. Tente novamente com uma descrição mais concisa.")
        except requests.exceptions.RequestException as e:
            st.error(f"Erro de conexão: {e!s}")

def display_analysis_results(result: Dict[str, Any]):
    """Exibe os resultados da análise"""
    st.success("Análise concluída com sucesso!")

    # Session ID
    session_id = result.get("session_id", "N/A")
    st.info(f"**Session ID:** `{session_id}`")

    report = result.get("report", {})

    if not report or not isinstance(report, dict):
        st.error("Erro: Relatório não foi gerado corretamente")
        st.json(result)
        return

    st.subheader("Métricas Principais")

    if report and "priority_detectors" in report:
        detectors = report["priority_detectors"]
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Detectores Identificados", len(detectors))

        with col2:
            high_priority = 0
            for d in detectors:
                priority = d.get("priority", "")
                if isinstance(priority, str):
                    if priority == "high":
                        high_priority += 1
                elif isinstance(priority, dict):
                    if priority.get("_value_") == "high" or priority.get("value") == "high":
                        high_priority += 1
            st.metric("Alta Prioridade", high_priority)

        with col3:
            risk_scores = []
            for d in detectors:
                risk_score = d.get("risk_score", 0)
                try:
                    risk_scores.append(float(risk_score))
                except (ValueError, TypeError):
                    risk_scores.append(0.0)

            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            st.metric("Risk Score Médio", f"{avg_risk:.1f}")

        with col4:
            critical_impact = len([d for d in detectors if d.get("impact_level") == "critical"])
            st.metric("Impacto Crítico", critical_impact)

    # Executive Summary
    if report and "executive_summary" in report:
        st.subheader("Resumo Executivo")
        st.markdown(f"**{report['executive_summary']}**")

    # Detectores Prioritários
    if report and "priority_detectors" in report and report["priority_detectors"]:
        st.subheader("Detectores Prioritários")

        for i, detector in enumerate(report["priority_detectors"]):
            display_detector_card(detector, i + 1)
    else:
        st.warning("Nenhum detector foi identificado")

    # Roadmap de Implementação
    if report and "implementation_roadmap" in report and report["implementation_roadmap"]:
        st.subheader("Roadmap de Implementação")
        display_implementation_roadmap(report["implementation_roadmap"])

    # Contexto do Ecosistema
    if report and "ecosystem_context" in report:
        st.subheader("Contexto Analisado")
        context = report["ecosystem_context"]

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Tecnologias Identificadas:**")
            if "technologies" in context:
                for tech in context["technologies"]:
                    st.markdown(f"- {tech}")

        with col2:
            st.markdown("**Características:**")
            st.markdown(f"- **Arquitetura:** {context.get('architecture_type', 'N/A')}")
            st.markdown(f"- **Sensibilidade:** {context.get('data_sensitivity', 'N/A')}")
            if "compliance_requirements" in context:
                st.markdown(f"- **Compliance:** {', '.join(context['compliance_requirements'])}")

def display_detector_card(detector: Dict[str, Any], index: int):
    """Exibe um card de detector"""
    priority_raw = detector.get("priority", "medium")
    if isinstance(priority_raw, str):
        priority = priority_raw
    elif isinstance(priority_raw, dict):
        priority = priority_raw.get("_value_", priority_raw.get("value", "medium"))
    else:
        priority = "medium"

    risk_class = f"risk-{priority}"

    st.markdown(f"""
    <div class="detector-card {risk_class}">
        <h4>#{index} {detector.get('name', 'Detector Desconhecido')}</h4>
        <p><strong>Descrição:</strong> {detector.get('description', 'N/A')}</p>
        <p><strong>Justificativa:</strong> {detector.get('rationale', 'N/A')}</p>
    </div>
    """, unsafe_allow_html=True)

    # Métricas do detector
    col1, col2, col3 = st.columns(3)

    with col1:
        priority_color = {"high": "red", "medium": "orange", "low": "green"}.get(priority, "gray")
        st.markdown(f"**Prioridade:** :{priority_color}[{priority.upper()}]")

    with col2:
        risk_score = detector.get("risk_score", 0)
        try:
            risk_score_float = float(risk_score)
            st.markdown(f"**Risk Score:** {risk_score_float:.1f}/10")
        except (ValueError, TypeError):
            st.markdown(f"**Risk Score:** {risk_score}/10")

    with col3:
        impact = detector.get("impact_level", "N/A")
        st.markdown(f"**Impacto:** {impact}")

    # MITRE ATT&CK Techniques
    if detector.get("mitre_techniques"):
        st.markdown("MITRE ATT&CK Techniques:")
        for technique in detector["mitre_techniques"]:
            st.markdown(f"- **{technique.get('technique_id')}**: {technique.get('name')}")

    st.markdown("---")

def display_implementation_roadmap(roadmap: list):
    """Exibe o roadmap de implementação"""
    if not roadmap:
        st.info("Nenhum roadmap disponível")
        return

    for phase in roadmap:
        st.markdown(f"### Fase {phase.get('phase', 'N/A')}")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown(f"**Timeline:** {phase.get('timeline', 'N/A')}")

        with col2:
            st.markdown(f"**Prioridade:** {phase.get('priority', 'N/A')}")

        with col3:
            st.markdown(f"**Esforço:** {phase.get('estimated_effort', 'N/A')}")

        if "success_metrics" in phase:
            st.markdown("**Métricas de Sucesso:**")
            for metric in phase["success_metrics"]:
                st.markdown(f"- {metric}")

def display_session_logs(session_id: str):
    """Exibe os logs de uma sessão"""
    try:
        response = requests.get(f"{API_BASE_URL}/session/{session_id}/logs")

        if response.status_code == 200:
            logs_data = response.json()

            st.subheader("Logs da Sessão")

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Interações", logs_data.get("total_interactions", 0))
            with col2:
                st.metric("Decisões", logs_data.get("total_decisions", 0))

            tab1, tab2 = st.tabs(["Interações", "Decisões"])

            with tab1:
                if "logs" in logs_data and "interactions" in logs_data["logs"]:
                    interactions_df = pd.DataFrame(logs_data["logs"]["interactions"])
                    if not interactions_df.empty:
                        st.dataframe(interactions_df, use_container_width=True)
                    else:
                        st.info("Nenhuma interação registrada")

            with tab2:
                if "logs" in logs_data and "decisions" in logs_data["logs"]:
                    decisions_df = pd.DataFrame(logs_data["logs"]["decisions"])
                    if not decisions_df.empty:
                        st.dataframe(decisions_df, use_container_width=True)
                    else:
                        st.info("Nenhuma decisão registrada")

        else:
            st.error(f"Erro ao carregar logs: {response.status_code}")

    except requests.exceptions.RequestException as e:
        st.error(f"Erro de conexão: {e!s}")

if __name__ == "__main__":
    main()

