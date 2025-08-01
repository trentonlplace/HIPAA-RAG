# HIPAA-RAG Manual Deployment Guide

This guide documents the manual deployment process required when the automated deployment script encounters issues. It includes all workarounds and specific configurations needed for successful deployment.

## ⚠️ Important Notes

- The automated `deploy.sh` script may fail due to Azure quota limits, Key Vault restrictions, or naming conflicts
- This manual process ensures successful deployment by addressing common issues
- All temporary security relaxations are reversed after deployment

## Prerequisites

1. **Azure CLI** logged in: `az login`
2. **Terraform** >= 1.0.0 installed
3. **Location**: Must use `East US 2` (not East US) due to quota availability
4. **App Service Tier**: Must use `S1` Standard (not free tier) for HIPAA compliance

## Step-by-Step Manual Deployment

### 1. Pre-Deployment Validation

```bash
# Check your subscription and quotas
az account show
az vm list-skus --location eastus2 --query "[?name=='Standard_S1'].restrictions" -o table

# Get your Azure AD Object ID (save this for later)
export ADMIN_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
echo "Your Object ID: $ADMIN_OBJECT_ID"
```

### 2. Prepare Terraform Configuration

First, ensure the Terraform configuration has the correct settings:

```bash
cd /Users/trentonlplace/Desktop/HIPAA-RAG/deployment

# Create terraform.tfvars with correct settings
cat > terraform.tfvars <<EOF
environment = "prod"
location = "East US 2"  # CRITICAL: Must be East US 2, not East US
resource_prefix = "hipaa-rag"
admin_object_id = "$ADMIN_OBJECT_ID"
EOF
```

### 3. Fix Configuration Issues

Before running Terraform, make these critical changes to `azure-infrastructure.tf`:

#### Fix 1: Key Vault Public Access (Temporary)
```hcl
# In the azurerm_key_vault resource, temporarily enable public access:
public_network_access_enabled = true  # Will be disabled after deployment

network_acls {
  default_action = "Allow"  # Temporarily allow during deployment
  bypass         = "AzureServices"
}
```

#### Fix 2: App Service Plan SKU
```hcl
# In the azurerm_service_plan resource:
sku_name = "S1"  # Standard S1 pay-per-use tier (NOT free tier)
```

#### Fix 3: Storage Account Access (Temporary)
```hcl
# In the azurerm_storage_account resource:
public_network_access_enabled = true   # Temporarily enable for deployment
shared_access_key_enabled = true      # Temporarily enable for deployment
```

### 4. Handle Existing Resources

If you have a failed partial deployment:

```bash
# Check for existing resource group
RESOURCE_GROUP="hipaa-rag-prod-rg"
if az group show --name "$RESOURCE_GROUP" &> /dev/null; then
    echo "Resource group exists. Cleaning up..."
    
    # Option 1: Quick cleanup (recommended)
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
    
    # Wait for deletion (or proceed if you're impatient)
    sleep 30
    
    # Option 2: If you need to preserve some resources, use Terraform
    # terraform destroy -auto-approve
fi

# Clean up local state
rm -f terraform.tfstate terraform.tfstate.backup
```

### 5. Initialize and Deploy Infrastructure

```bash
# Initialize Terraform
terraform init -upgrade

# Plan the deployment (review carefully)
terraform plan -var-file=terraform.tfvars -out=tfplan

# Apply the deployment
terraform apply tfplan
```

### 6. Create Encryption Keys Manually

After the infrastructure is deployed but before private endpoints are configured:

```bash
# Get the Key Vault name
KEY_VAULT_NAME="hipaa-rag-prod-kv-0801"  # Note: hardcoded to avoid conflicts

# Create the encryption keys
az keyvault key create \
  --vault-name "$KEY_VAULT_NAME" \
  --name "hipaa-phi-primary" \
  --kty RSA \
  --size 2048 \
  --ops encrypt decrypt wrapKey unwrapKey

az keyvault key create \
  --vault-name "$KEY_VAULT_NAME" \
  --name "hipaa-phi-backup" \
  --kty RSA \
  --size 2048 \
  --ops encrypt decrypt wrapKey unwrapKey

az keyvault key create \
  --vault-name "$KEY_VAULT_NAME" \
  --name "hipaa-audit-logs" \
  --kty RSA \
  --size 2048 \
  --ops encrypt decrypt wrapKey unwrapKey
```

### 7. Lock Down Security (Post-Deployment)

After all resources are created and keys are in place:

```bash
# Disable Key Vault public access
az keyvault update \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access Disabled \
  --default-action Deny

# Disable Storage Account public access and shared key access
STORAGE_ACCOUNT=$(terraform output -raw storage_account_name)

az storage account update \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access Disabled \
  --allow-shared-key-access false \
  --default-action Deny
```

### 8. Verify Deployment

```bash
# Check all resources
az resource list --resource-group "$RESOURCE_GROUP" --output table

# Verify private endpoints
az network private-endpoint list --resource-group "$RESOURCE_GROUP" --output table

# Test Key Vault access (should fail from public internet after lockdown)
az keyvault key list --vault-name "$KEY_VAULT_NAME" 2>&1 | grep -q "Forbidden" && \
  echo "✅ Key Vault properly secured" || \
  echo "❌ Key Vault still publicly accessible"
```

## Common Issues and Solutions

### Issue 1: Key Vault Already Exists (Soft-Deleted)

```bash
# Check for soft-deleted vaults
az keyvault list-deleted --query "[?name=='$KEY_VAULT_NAME']"

# If found, purge it (WARNING: permanent deletion)
az keyvault purge --name "$KEY_VAULT_NAME"
```

### Issue 2: App Service Quota Exceeded

```bash
# Check available SKUs in East US 2
az vm list-skus --location eastus2 --query "[?family=='standardSFamily']" -o table

# If S1 is not available, check other regions
az account list-locations --query "[].name" -o tsv | while read loc; do
  echo "Checking $loc..."
  az vm list-skus --location "$loc" --query "[?name=='Standard_S1'].restrictions" -o table
done
```

### Issue 3: Terraform State Conflicts

```bash
# If Terraform state is corrupted
rm -f terraform.tfstate terraform.tfstate.backup

# Import existing resources manually
terraform import azurerm_resource_group.main \
  "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RESOURCE_GROUP"

# Continue with other imports as needed...
```

### Issue 4: Private Endpoint Connection Issues

```bash
# If private endpoints aren't working, check DNS
az network private-endpoint dns-zone-group list \
  --resource-group "$RESOURCE_GROUP" \
  --endpoint-name "hipaa-rag-prod-kv-pe"

# Manually approve private endpoint connections if needed
az keyvault private-endpoint-connection approve \
  --resource-group "$RESOURCE_GROUP" \
  --vault-name "$KEY_VAULT_NAME" \
  --name "hipaa-rag-prod-kv-pe"
```

## Post-Deployment Configuration

### 1. Configure Application Settings

```bash
WEB_APP_NAME="hipaa-rag-prod-app"

# Set HIPAA compliance mode
az webapp config appsettings set \
  --resource-group "$RESOURCE_GROUP" \
  --name "$WEB_APP_NAME" \
  --settings HIPAA_COMPLIANCE_MODE=true
```

### 2. Enable Diagnostic Settings

```bash
# Get Log Analytics Workspace ID
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RESOURCE_GROUP" \
  --name "hipaa-rag-prod-logs" \
  --query id -o tsv)

# Enable diagnostics for Key Vault
az monitor diagnostic-settings create \
  --resource "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --name "kv-diagnostics" \
  --workspace "$WORKSPACE_ID" \
  --logs '[{"category":"AuditEvent","enabled":true}]' \
  --metrics '[{"category":"AllMetrics","enabled":true}]'
```

### 3. Create Deployment Report

```bash
# Generate deployment info
cat > deployment-info.json <<EOF
{
  "deployment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "prod",
  "resource_group": "$RESOURCE_GROUP",
  "key_vault_uri": "https://$KEY_VAULT_NAME.vault.azure.net/",
  "web_app_name": "$WEB_APP_NAME",
  "storage_account": "$STORAGE_ACCOUNT",
  "location": "eastus2"
}
EOF

# Run validation
./deploy.sh validate
```

## Critical Success Factors

1. **Location MUST be East US 2** - East US lacks required quotas
2. **App Service MUST be S1 Standard** - Free tier violates HIPAA requirements
3. **Temporary public access is required** - But must be disabled after deployment
4. **Key Vault name must be unique** - Include timestamp or unique suffix
5. **Keys must be created before private endpoints** - Otherwise access is blocked

## Rollback Procedure

If deployment fails at any point:

```bash
# Quick rollback
az group delete --name "$RESOURCE_GROUP" --yes --no-wait

# Clean up Terraform state
rm -f terraform.tfstate terraform.tfstate.backup tfplan

# Clean up any soft-deleted Key Vaults
az keyvault list-deleted --query "[?properties.deletionDate < '$(date -u +%Y-%m-%d)'].[name]" -o tsv | \
  xargs -I {} az keyvault purge --name {}
```

## Support

For quota issues, open an Azure support ticket requesting:
- Standard_S1 App Service Plan quota in East US 2
- Premium Key Vault quota increase if needed
- Private endpoint quota increase if needed

---

**Note**: This manual process achieves the same HIPAA-compliant deployment as the automated script but with greater control over error handling and recovery.