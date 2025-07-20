# Setup Docker com Community MCP

## Como usar após a integração do Community MCP

### 1. Pré-requisitos

- Docker e Docker Compose instalados
- Variável de ambiente `ANTHROPIC_API_KEY` configurada

### 2. Configurar variável de ambiente

Crie um arquivo `.env` na raiz do projeto:

```bash
# .env
ANTHROPIC_API_KEY=your_anthropic_api_key_here
DATABASE_URL=sqlite:///./datasec_challenge.db
LOG_LEVEL=INFO
```

### 3. Executar com Docker

```bash
# Construir e iniciar todos os serviços
docker-compose up --build

# Ou em modo background
docker-compose up -d --build
```

### 4. Acessar as aplicações

Após o Docker iniciar:

- **Frontend Streamlit**: <http://localhost:8501>
- **API FastAPI**: <http://localhost:8000>
- **API Docs**: <http://localhost:8000/docs>
- **PostgreSQL**: localhost:5433 # Veja que alterei a porta padrao (5432) por uma especificidade do meu sistema

### 5. Testar a integração

#### Teste rápido da API

```bash
python test_api.py
```

#### Teste completo no frontend

1. Abra o frontend em <http://localhost:8501>
2. Escolha um exemplo (E-commerce, Fintech, etc.)
3. Clique em "Analisar Sistema"
4. Aguarde a análise (pode levar alguns minutos)

### 6. Verificar Community MCP

Acesse <http://localhost:8000/mitre/status> para verificar se o Community MCP está funcionando.

### 7. Logs e Debug

```bash
# Ver logs de todos os serviços
docker-compose logs -f

# Ver logs apenas da API
docker-compose logs -f datasec-api

# Ver logs apenas do frontend
docker-compose logs -f streamlit-frontend
```

### 8. Parar os serviços

```bash
# Parar serviços
docker-compose down

# Parar e remover volumes (limpar dados)
docker-compose down -v
```

## Estrutura dos Serviços

- **datasec-api**: API FastAPI com integração Community MCP
- **streamlit-frontend**: Interface web Streamlit
- **postgres**: Banco de dados PostgreSQL

## Troubleshooting

