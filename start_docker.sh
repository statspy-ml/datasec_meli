#!/bin/bash

echo "Reiniciando Docker Compose..."

echo "Parando containers..."
docker-compose down

echo "Rebuilding containers..."
docker-compose build --no-cache --pull

echo "Iniciando containers..."
docker-compose up -d

echo "Aguardando 15 segundos para containers inicializarem..."
sleep 15

echo "Verificando status dos serviços..."

if curl -f -s http://localhost:8000/health >/dev/null; then
  echo "API rodando em http://localhost:8000"
else
  echo "API não está respondendo"
  echo "Logs da API:"
  docker-compose logs --tail=10 datasec-api
fi

if curl -f -s http://localhost:8501 >/dev/null; then
  echo "Frontend rodando em http://localhost:8501"
else
  echo "Frontend não está respondendo"
  echo "Logs do Frontend:"
  docker-compose logs --tail=10 streamlit-frontend
fi

echo ""
echo "Para ver logs em tempo real:"
echo "docker-compose logs -f"
echo ""
echo "Acessos:"
echo "Frontend: http://localhost:8501"
echo "API Docs: http://localhost:8000/docs"

