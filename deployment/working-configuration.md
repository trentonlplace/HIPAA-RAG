# Working Configuration Reference

This document captures the exact configuration that successfully deployed on August 1, 2025.

## Verified Working Configuration

### Azure Settings
- **Location**: `East US 2` (eastus2)
- **Resource Group**: `hipaa-rag-prod-rg`
- **App Service Plan SKU**: `S1` (Standard tier, NOT free)
- **Key Vault Name**: `hipaa-rag-prod-kv-0801` (hardcoded to avoid conflicts)

### Terraform Variables
```hcl
environment = "prod"
location = "East US 2"
resource_prefix = "hipaa-rag"
admin_object_id = "<your-azure-ad-object-id>"
```

### Critical Configuration Changes

#### 1. Key Vault (azure-infrastructure.tf)
```hcl
resource "azurerm_key_vault" "main" {
  name = "hipaa-rag-prod-kv-0801"  # Hardcoded name
  # ...
  
  # TEMPORARY during deployment
  public_network_access_enabled = true
  
  network_acls {
    default_action = "Allow"  # Change to "Deny" after deployment
    bypass         = "AzureServices"
  }
}
```

#### 2. App Service Plan (azure-infrastructure.tf)
```hcl
resource "azurerm_service_plan" "main" {
  # ...
  sku_name = "S1"  # NOT "P2v3" or "F1"
}
```

#### 3. Storage Account (azure-infrastructure.tf)
```hcl
resource "azurerm_storage_account" "audit_logs" {
  # ...
  # TEMPORARY during deployment
  public_network_access_enabled = true
  shared_access_key_enabled = true
}
```

#### 4. Use Data Sources for Keys
```hcl
# Changed from resource to data source
data "azurerm_key_vault_key" "phi_primary" {
  name         = "hipaa-phi-primary"
  key_vault_id = azurerm_key_vault.main.id
}
```

### Deployment Sequence

1. **Deploy infrastructure** with public access enabled
2. **Create encryption keys** manually via Azure CLI
3. **Lock down security** by disabling public access
4. **Verify private endpoints** are functioning

### Post-Deployment Security Commands

```bash
# Lock down Key Vault
az keyvault update \
  --name "hipaa-rag-prod-kv-0801" \
  --resource-group "hipaa-rag-prod-rg" \
  --public-network-access Disabled \
  --default-action Deny

# Lock down Storage Account
az storage account update \
  --name "hipaaragprodaudit" \
  --resource-group "hipaa-rag-prod-rg" \
  --public-network-access Disabled \
  --allow-shared-key-access false \
  --default-action Deny
```

### Known Working Resource Names

- Key Vault: `hipaa-rag-prod-kv-0801`
- Storage Account: `hipaaragprodaudit`
- App Service: `hipaa-rag-prod-app`
- App Service Plan: `hipaa-rag-prod-asp`
- Virtual Network: `hipaa-rag-prod-vnet`
- Log Analytics: `hipaa-rag-prod-logs`

### Validation Results

All resources successfully deployed with:
- ✅ Private endpoints configured
- ✅ Public access disabled
- ✅ Customer-managed encryption keys
- ✅ HIPAA-compliant configuration
- ✅ 7-year audit retention
- ✅ Network isolation enforced

### Environment Variables for Manual Deployment

```bash
export RESOURCE_GROUP="hipaa-rag-prod-rg"
export KEY_VAULT_NAME="hipaa-rag-prod-kv-0801"
export STORAGE_ACCOUNT="hipaaragprodaudit"
export WEB_APP_NAME="hipaa-rag-prod-app"
export LOCATION="eastus2"
export ADMIN_OBJECT_ID="<your-object-id>"
```

---

**Note**: This configuration was tested and verified working on August 1, 2025, in the Azure subscription e3511464-7add-4014-a507-fed8b5b8b741.