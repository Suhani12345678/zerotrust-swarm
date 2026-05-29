#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# ZeroTrust-Swarm — Azure One-Click Deployment Script
# Usage: bash deploy_azure.sh [resource-group-name] [location]
# Requirements: Azure CLI (az) logged in
# ─────────────────────────────────────────────────────────────────
set -e

RG="${1:-zerotrust-swarm-rg}"
LOCATION="${2:-eastus}"
APP_NAME="zerotrust-swarm-api-$(head -c4 /dev/urandom | xxd -p)"
STATIC_NAME="zerotrust-swarm-ui-$(head -c4 /dev/urandom | xxd -p)"
SKU="F1"          # Free tier for demo; use B1 for production

echo "─────────────────────────────────────────────────────────"
echo "  ZeroTrust-Swarm — Azure Deployment"
echo "  Resource Group : $RG"
echo "  Location       : $LOCATION"
echo "  API App Name   : $APP_NAME"
echo "─────────────────────────────────────────────────────────"

# 1. Create resource group
echo ""
echo "▸ Creating resource group..."
az group create --name "$RG" --location "$LOCATION" --output none

# 2. Create App Service plan
echo "▸ Creating App Service plan (Linux, Python 3.11)..."
az appservice plan create \
  --name "${APP_NAME}-plan" \
  --resource-group "$RG" \
  --sku "$SKU" \
  --is-linux \
  --output none

# 3. Create Web App for the FastAPI backend
echo "▸ Creating Web App for FastAPI backend..."
az webapp create \
  --name "$APP_NAME" \
  --resource-group "$RG" \
  --plan "${APP_NAME}-plan" \
  --runtime "PYTHON:3.11" \
  --output none

# 4. Generate secure secrets
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
CALLER_KEY=$(python3 -c "import secrets; print(secrets.token_hex(24))")

echo "▸ Configuring environment variables..."
az webapp config appsettings set \
  --name "$APP_NAME" \
  --resource-group "$RG" \
  --settings \
    JWT_SECRET="$JWT_SECRET" \
    CALLER_API_KEY="$CALLER_KEY" \
    ALLOWED_ORIGIN="https://${STATIC_NAME}.azurestaticapps.net" \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true \
  --output none

# 5. Configure startup command for FastAPI
az webapp config set \
  --name "$APP_NAME" \
  --resource-group "$RG" \
  --startup-file "cd backend && pip install -r requirements.txt && uvicorn main:app --host 0.0.0.0 --port 8000" \
  --output none

# 6. Deploy backend code
echo "▸ Deploying backend to Azure App Service..."
pushd backend > /dev/null
zip -r /tmp/backend-deploy.zip . -x "*.pyc" -x "__pycache__/*" -x "zerotrust.db" > /dev/null
az webapp deploy \
  --name "$APP_NAME" \
  --resource-group "$RG" \
  --src-path /tmp/backend-deploy.zip \
  --type zip \
  --output none
popd > /dev/null

BACKEND_URL="https://${APP_NAME}.azurewebsites.net"

# 7. Build frontend with production API URL
echo "▸ Building frontend for production..."
pushd frontend > /dev/null
echo "VITE_API_URL=$BACKEND_URL" > .env.production
npm ci --silent && npm run build --silent
popd > /dev/null

# 8. Deploy to Azure Static Web Apps
echo "▸ Deploying frontend to Azure Static Web Apps..."
az staticwebapp create \
  --name "$STATIC_NAME" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --source "./frontend/dist" \
  --output none 2>/dev/null || \
  echo "  (Static Web App manual upload: upload ./frontend/dist to $STATIC_NAME)"

FRONTEND_URL="https://${STATIC_NAME}.azurestaticapps.net"

# 9. (Optional) Azure Monitor / Log Analytics
echo "▸ Creating Log Analytics workspace for audit trail..."
az monitor log-analytics workspace create \
  --workspace-name "zerotrust-sentinel" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --output none 2>/dev/null || echo "  (Log Analytics creation skipped — enable manually in Azure Portal)"

# 10. Summary
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "      ZeroTrust-Swarm deployed to Azure!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  API (FastAPI)   : $BACKEND_URL"
echo "  Frontend (SOC)  : $FRONTEND_URL"
echo "  Swagger Docs    : $BACKEND_URL/docs"
echo ""
echo "  CALLER_API_KEY  : $CALLER_KEY"
echo "  (Store this — pass as X-API-Key header to /inspect)"
echo ""
echo "  Next: Run benchmark against live URL:"
echo "  BASE_URL=$BACKEND_URL python backend/benchmark.py"
echo ""
echo "  Cosmos DB migration (optional):"
echo "  export COSMOS_ENDPOINT=... && python backend/migrate_to_cosmos.py"
echo "═══════════════════════════════════════════════════════════"
