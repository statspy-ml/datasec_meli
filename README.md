# DataSec Challenge - Sistema Multi-Agente para Análise de Segurança

Sistema multi-agente desenvolvido para o desafio técnico da equipe de Data Security do Mercado Livre. Analisa ecossistemas de TI e gera recomendações de detectores de segurança baseados no DBIR 2025 e framework MITRE ATT&CK.

## Arquitetura

### Sistema Multi-Agente

O sistema utiliza **4 agentes especializados** que comunicam de forma dinâmica e assíncrona:

> **Nota**: A pasta `src/agents/` contém 6 arquivos, sendo 4 agentes funcionais + 2 arquivos de suporte:
>
> - `base_agent.py` → Classe abstrata base (herança)
> - `analyzer_agent_adaptive.py` → Módulo de detectores adaptativos

#### **1. OrchestratorAgent** (`src/agents/orchestrator_agent.py`)

- **Função**: Coordenador central do fluxo de análise
- **Responsabilidades**:
  - Gerencia o workflow completo de análise (4 etapas)
  - Coordena comunicação entre agentes especializados
  - Controla timeouts e recuperação de falhas
  - Integra resultados finais
- **Fluxo**: Recebe input → delega para AnalyzerAgent → RiskAssessorAgent → ReportGeneratorAgent

#### **2. AnalyzerAgent** (`src/agents/analyzer_agent.py`)

- **Função**: Motor de análise e detecção de padrões
- **Responsabilidades**:
  - Analisa descrições de ecossistemas usando LLM (Claude)
  - Identifica detectores prioritários baseado em DBIR 2025
  - Consulta RAG service para padrões similares de ataque
  - Aplica detectores adaptativos vs hardcoded (fallback)
- **Integração**: DBIR Service + RAG Service + LLM contextual

#### **3. RiskAssessorAgent** (`src/agents/risk_assessor_agent.py`)

- **Função**: Especialista em mapeamento de riscos e MITRE ATT&CK
- **Responsabilidades**:
  - Mapeia detectores para técnicas MITRE ATT&CK via MCP
  - Calcula risk scores baseado em contexto do sistema
  - Avalia severidade e impacto de cada detector
  - Prioriza recomendações por criticidade
- **Integração**: MITRE ATT&CK MCP + Context awareness

#### **4. ReportGeneratorAgent** (`src/agents/report_generator_agent.py`)

- **Função**: Gerador de relatórios executivos e técnicos
- **Responsabilidades**:
  - Sintetiza análises em relatório estruturado
  - Gera executive summary e roadmap de implementação
  - Cria recomendações acionáveis por detector
  - Formata output JSON para consumo via API
- **Output**: Relatório completo + métricas + próximos passos

### Comunicação Entre Agentes

```mermaid
graph TD
    A[OrchestratorAgent] --> B[AnalyzerAgent]
    B --> C[RiskAssessorAgent]
    C --> D[ReportGeneratorAgent]
    D --> A

    B -.-> E[DBIR Service]
    B -.-> F[RAG Service]
    C -.-> G[MITRE MCP]

    A --> H[LoggingService]
    B --> H
    C --> H
    D --> H
```

### **MCP (Model Context Protocol) Integration**

O sistema integra **3 MCPs especializados** para extensibilidade:

#### **MITRE ATT&CK Community MCP**

- **Propósito**: Acesso programático ao framework MITRE ATT&CK
- **Origem**: **Desenvolvido pela comunidade** (não proprietário, conforme permitido pelas regras do challenge)
- **Biblioteca Base**: `mitreattack-python` (oficial MITRE) + `FastMCP`
- **Funcionalidade**:
  - Query de técnicas por ID (T1078, T1190, etc.)
  - Mapeamento de táticas para detectores
  - Enriquecimento contextual de riscos
- **Integração**: Custom client em `src/services/community_mcp_client.py`
- **Endpoint**: `/mitre/status` - Status da integração
- **Localização**: `mcp-community/mitre-attack-mcp-server.py` (community) + `src/services/mitre_service.py` (integration)

#### **DBIR RAG MCP**

- **Propósito**: Processamento inteligente do DBIR 2025 Report
- **Funcionalidade**:
  - Extração de padrões reais de ataques do PDF
  - Embeddings semânticos com SentenceTransformers
  - Vector search com ChromaDB
  - Cache inteligente de dados extraídos
- **Localização**: `src/services/rag_service.py` + `src/services/pdf_processor.py`

#### **Custom Logging MCP**

- **Propósito**: Rastreabilidade completa de decisões
- **Funcionalidade**:
  - Log de todas interações entre agentes
  - Tracking de decisões e rationale
  - Persistência em PostgreSQL
  - API de consulta de logs por sessão
- **Endpoint**: `/session/{session_id}/logs`
- **Localização**: `src/services/logging_service.py`

### **Arquitetura RAG (Retrieval Augmented Generation)**

#### **Pipeline de Dados Real**

```
DBIR 2025 PDF → PyPDF2 → Text Extraction → Pattern Analysis → ChromaDB Embeddings
                                                                      ↓
User Query → SentenceTransformers → Vector Search → Top-K Patterns → LLM Context
```

#### **Componentes Técnicos**

- **PDF Processor** (`src/services/pdf_processor.py`): Extrai dados reais do DBIR 2025
- **ChromaDB**: Vector database para similarity search
- **SentenceTransformers**: Modelo `all-MiniLM-L6-v2` para embeddings
- **Cache System**: JSON cache em `data/mitre-attack/dbir_extracted_data.json`
- **Fallback Patterns**: 10 padrões hardcoded se PDF falhar

#### **Real vs Fallback Data**

- **Real Data**: 7 padrões extraídos do DBIR 2025 (66% web apps, 80% system intrusion)
- **Fallback**: Padrões genéricos se extração PDF falhar
- **Status**: Sistema funciona com dados reais comprovadamente

### Características Principais

- **Comunicação assíncrona** entre agentes via message passing
- **RAG real** com dados extraídos do DBIR 2025 PDF
- **MITRE ATT&CK** integration via Community MCP
- **PostgreSQL** para persistência (migrado de SQLite)
- **Rastreabilidade completa** de decisões e interações
- **API REST** com FastAPI + endpoints de monitoramento
- **Docker containerization** com compose

## Instalação e Execução

### Opção 1: Início Inteligente Docker com guias  (Recomendado)

```bash
# 1. Clone o repositório
git clone <repository-url>
cd datasec-challenge

# 2. Configure sua API key
Adicione a API key .env

# Edite .env: ANTHROPIC_API_KEY=sk-ant-...

# 3. Execute o script inteligente
chmod +x start_docker.sh
./start_docker.sh
```

### Opção 2: Docker (Recomendado)

```bash
# 1. Configure .env com suas credenciais
Edite o arquivo .env, adicionando chave API Anth

# 2. Execute com Docker Compose
docker-compose up --build

# Acessos:
# - API: http://localhost:8000
# - Frontend: http://localhost:8501
# - Docs: http://localhost:8000/docs
```

## Exemplos de Uso


### Via API

#### **Endpoint de Análise**

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "ecosystem_description": "Sistema de e-commerce com microserviços na AWS usando Django, PostgreSQL, Redis para cache, API Gateway, EKS para containers e S3 para storage.",
    "scenario_name": "ecommerce_aws",
    "additional_context": {
      "compliance": ["PCI-DSS", "LGPD"],
      "data_sensitivity": "high"
    }
  }'
```

**Response:**

```json
{
  "session_id": "11eb1e2d-c05f-4757-8cd4-235d5e73b6b6",
  "status": "completed",
  "report": {
    "ecosystem_context": {
      "technologies": ["web", "api", "database", "cloud", "container"],
      "architecture_type": "microservices",
      "data_sensitivity": "high"
    },
    "priority_detectors": [
      {
        "name": "API Gateway Anomaly Detection",
        "priority": "high",
        "risk_score": 8.8,
        "mitre_techniques": ["T1190", "T1078"]
      }
    ]
  }
}
```

#### **Consulta de Logs**

```bash
# Verificar progresso e decisões
curl "http://localhost:8000/session/11eb1e2d-c05f-4757-8cd4-235d5e73b6b6/logs"
```

#### **Status MITRE ATT&CK**

```bash
# Verificar integração MCP
curl "http://localhost:8000/mitre/status"
```

**Response:**

```json
{
  "community_mcp_available": true,
  "mitre_statistics": {
    "total_techniques": 191,
    "total_tactics": 14,
    "last_updated": "2025-01-01"
  }
}
```


### Via Frontend Web

Acesse `http://localhost:8501` para interface gráfica.

## Estrutura dos Resultados

### Relatório Gerado

```json
{
  "session_id": "uuid-da-sessao",
  "ecosystem_context": {
    "technologies": ["web", "api", "database"],
    "architecture_type": "microservices",
    "risk_level": "high"
  },
  "priority_detectors": [
    {
      "name": "Suspicious API Access Pattern",
      "description": "Detecta padrões anômalos de acesso à API",
      "priority": "high",
      "mitre_techniques": ["T1078", "T1190"],
      "risk_score": 8.5,
      "implementation_steps": [...]
    }
  ],
  "executive_summary": "...",
  "implementation_roadmap": [...]
}
```

### Logs de Rastreabilidade

```json
{
  "interactions": [
    {
      "from_agent": "orchestrator",
      "to_agent": "analyzer",
      "message_type": "analyze_ecosystem",
      "timestamp": "2025-01-01T10:00:00"
    }
  ],
  "decisions": [
    {
      "agent": "analyzer",
      "decision": "priority_detectors_identified",
      "rationale": "Baseado no DBIR 2025...",
      "data": {...}
    }
  ]
}
```

## Configuração Avançada

### MCPs Disponíveis

- **MITRE ATT&CK MCP**: Integração com framework MITRE
- **DBIR RAG MCP**: Processamento do relatório DBIR 2025
- **Custom Logging MCP**: Sistema de logs estruturados

### Variáveis de Ambiente

```bash
# APIs
ANTHROPIC_API_KEY=sk-...

# Database (PostgreSQL recomendado para produção)
DATABASE_URL=postgresql://user:password@localhost:5432/datasec_db
# Alternativa SQLite para desenvolvimento:
# DATABASE_URL=sqlite:///./datasec_challenge.db
# Importante: 
A porta do postgres foi alterada para 5433 no docker-compose.yaml pois já tenho uma instancia postgresql defafult rodando na porta 5432
# MITRE ATT&CK
MITRE_ATTACK_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# DBIR 2025
DBIR_2025_PATH=data/dbir_2025_report.pdf
```
## Estrutura do Projeto

```
datasec-challenge/
├── src/
│   ├── agents/                     # Sistema Multi-Agente
│   │   ├── orchestrator_agent.py  # Coordenador central
│   │   ├── analyzer_agent.py      # Motor de análise + LLM
│   │   ├── risk_assessor_agent.py # Especialista MITRE ATT&CK
│   │   ├── report_generator_agent.py # Gerador de relatórios
│   │   ├── base_agent.py          # Classe abstrata base
│   │   └── analyzer_agent_adaptive.py # Detectores adaptativos
│   ├── models/          # Modelos Pydantic (EcosystemContext, etc.)
│   ├── services/        # Serviços especializados
│   │   ├── rag_service.py          # RAG + ChromaDB + DBIR 2025
│   │   ├── pdf_processor.py       # Extração real de dados PDF
│   │   ├── mitre_service.py       # MITRE ATT&CK MCP
│   │   ├── dbir_service.py        # Threat intelligence
│   │   └── logging_service.py     # Rastreabilidade PostgreSQL
│   └── utils/           # Clients LLM (Claude, OpenAI)
├── data/               # Dados fonte
│   └── mitre-attack/   # DBIR 2025 PDF + cache JSON
├── logs/               # Logs do sistema
├── results/            # Análises geradas (JSON)
├── main.py             # API FastAPI
└── requirements.txt    # Dependências Python
```

## Pontos Implementados

### Requisitos Principais

- Sistema multi-agente com roles específicos
- Comunicação dinâmica (não-sequencial) entre agentes
- Integração com DBIR 2025 via RAG
- Mapeamento para MITRE ATT&CK
- Geração de relatórios com acionáveis
- Sistema completo de logs e trazabilidade
- MCPs para extensibilidade

### Pontos Bonus

- API REST com FastAPI
- Frontend web com Streamlit
- Containerização com Docker
- Múltiplos cenários de teste
- Documentação completa

## Exemplo de Análise

Para um sistema de e-commerce, o sistema identifica:

1. **Detectores Prioritários**:

   - Ataques a aplicações web (OWASP Top 10)
   - Padrões anômalos de API access
   - Tentativas de exfiltração de dados

2. **Mapeamento MITRE**:

   - T1190: Exploit Public-Facing Application
   - T1078: Valid Accounts
   - T1041: Exfiltration Over C2 Channel

3. **Acionáveis**:
   - Implementar WAF com regras específicas
   - Configurar monitoramento de APIs
   - Estabelecer baselines de comportamento

## Suporte

Para dúvidas sobre implementação ou execução:

1. Verifique os logs em `logs/`
2. Consulte a documentação da API em `/docs`
3. Execute os cenários de exemplo com `python run.py`

## Troubleshooting

### Erro de Dependências ML

```bash
# Se houver erro com sentence-transformers ou chromadb:
python start.py  # Usa fallback automático
# OU
pip install --no-deps sentence-transformers==2.7.0
pip install huggingface-hub==0.23.5
```

### Erro de Conexão API

```bash
# Verifique se ANTHROPIC_API_KEY está configurada:
cat .env | grep ANTHROPIC

# Teste a API key:
curl -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "Content-Type: application/json" \
     https://api.anthropic.com/v1/messages
```

### Docker Issues

```bash
# Se houver problemas com Docker:
docker-compose down -v    # Limpar volumes
docker system prune -a    # Limpar cache
docker-compose up --build --force-recreate
```



## Próximos Passos e Roadmap

### **Limitações Atuais**

#### **Performance e Escalabilidade**

- **Análise Síncrona**: Processo completo demora 60-120s bloqueando API
- **Single-threaded**: Apenas 1 análise por vez
- **LLM Latency**: Cada agente faz chamadas LLM sequenciais (Claude)
- **Memory Usage**: ChromaDB carrega embeddings completos na memória

#### **Dependências Externas**

- **Claude API**: Sistema 100% dependente da Anthropic (rate limits)
- **Network Bound**: Todas chamadas LLM requerem conectividade
- **Cost per Analysis**: ~$0.10-0.50 por análise dependendo do contexto

### **Melhorias Planejadas**

#### **Fase 1: Sistema Assíncrono (Prioridade ALTA - 4-6 semanas)**

**Implementação Celery + RabbitMQ**

```python
# Transformar análise síncrona:
POST /analyze → [60-120s wait] → Response

# Em assíncrona:
POST /analyze → {"task_id": "abc123", "status": "queued"} [~100ms]
GET /analyze/abc123/status → {"status": "in_progress", "progress": 45%}
GET /session/{id}/logs → Logs em tempo real
```

**Benefícios Esperados:**

- API responde em ~100ms vs 60-120s
- Múltiplas análises paralelas (5-10 simultâneas)
- Progress tracking em tempo real
- Retry automático em falhas de LLM
- Escalabilidade horizontal (múltiplos workers)

**Implementação:**

- Docker: RabbitMQ + Celery Workers + Flower monitoring
- Background Tasks: Cada agente vira Celery task
- Progress API: WebSocket ou polling para status
- Error Handling: Dead letter queues + retry logic

#### **Fase 2: Otimização LLM (Prioridade ALTA - 3-4 semanas)**

**Prompt Engineering Avançado**

- **Context-aware Prompts**: Detectores específicos por domínio (fintech vs e-commerce)
- **Few-shot Learning**: Exemplos de análises bem-sucedidas no prompt
- **Chain-of-Thought**: LLM explica raciocínio step-by-step
- **Response Caching**: Cache de respostas similares (hash do contexto)

**Multi-LLM Strategy**

```python
# Configuração flexível por agente:
AnalyzerAgent → Claude Sonnet (precisão)
RiskAssessorAgent → Claude Haiku (velocidade)
ReportGeneratorAgent → GPT-4 (criatividade)
```

**Streaming Responses**

- Server-Sent Events para progress updates
- Partial results conforme agentes completam
- User experience não-bloqueante

#### **Fase 3: Modelos Locais (Prioridade MÉDIA - 6-8 semanas)**

**Hybrid Local + Cloud Architecture**

```yaml
# Deployment options:
production: Claude API (máxima qualidade)
development: Llama 3.1 70B local (custo zero)
edge: Llama 3.1 8B local (latência mínima)
```

**Modelos Planejados:**

- **Llama 3.1 70B** via Ollama (primary local model)
- **Mistral 7B** para análises rápidas
- **CodeLlama** para detectores code-aware
- **Embedding local** com `sentence-transformers` (já implementado)

**Infrastructure:**

- GPU support via Docker + NVIDIA runtime
- Model switching por environment variable
- Fallback automático: Local → Claude se modelo local falhar
- Cost tracking: Local vs API usage

#### **Fase 4: Inteligência Avançada (Prioridade MÉDIA - 4-6 semanas)**

**RAG Enhancement**

- **Multi-source RAG**: DBIR 2025 + NIST + CIS Controls + OWASP
- **Temporal RAG**: Detectores baseados em threat trends recentes
- **Domain-specific**: RAG especializado por vertical (fintech, healthcare, etc.)

**Agent Collaboration**

- **Multi-agent Reasoning**: Agentes debatem e chegam a consenso
- **Self-reflection**: Agentes validam próprias recomendações
- **Adaptive Learning**: Sistema aprende com feedback de implementações

**Advanced Analytics**

- **Threat Modeling**: Automated threat model generation
- **Attack Simulation**: Monte Carlo de cenários de ataque
- **ROI Analysis**: Cost-benefit de cada detector recomendado

### **Melhorias de Infrastructure**

#### **Database & Monitoring**

- **Database Sharding**: PostgreSQL clustering para high-volume
- **Metrics & Alerting**: Prometheus + Grafana para sistema health
- **Audit Trail**: Compliance logging para decisões críticas
- **Backup Strategy**: Automated backups + disaster recovery

#### **Security & Compliance**

- **API Authentication**: JWT + API keys para access control
- **Rate Limiting**: Prevent abuse and ensure fair usage
- **Data Privacy**: LGPD/GDPR compliance para análises sensíveis
- **Secrets Management**: HashiCorp Vault para API keys

### **Métricas de Sucesso**

**Performance:**

- Response time: 60-120s → 100ms (API response)
- Throughput: 1 análise → 10+ análises paralelas
- Uptime: 95% → 99.9% (com retry logic)

**Quality:**

- False positive rate: <5% (detectores irrelevantes)
- User satisfaction: 90%+ (feedback system)
- Implementation success: 70%+ (detectores efetivamente implementados)

---

**Desenvolvido para o DataSec Challenge do Mercado Livre**
