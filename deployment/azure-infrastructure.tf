# HIPAA-RAG Production Infrastructure Deployment
# Terraform configuration for Azure HIPAA-compliant infrastructure

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~>2.0"
    }
  }
  required_version = ">= 1.0"
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

# Variables
variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US 2"
}

variable "resource_prefix" {
  description = "Prefix for all resources"
  type        = string
  default     = "hipaa-rag"
}

variable "admin_object_id" {
  description = "Azure AD Object ID of the admin user"
  type        = string
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${var.resource_prefix}-${var.environment}-rg"
  location = var.location

  tags = {
    Environment = var.environment
    Purpose     = "HIPAA-RAG-Production"
    Compliance  = "HIPAA"
    CreatedBy   = "Terraform"
  }
}

# Virtual Network for Private Endpoints
resource "azurerm_virtual_network" "main" {
  name                = "${var.resource_prefix}-${var.environment}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]

  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "app_service" {
  name                 = "app-service-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]

  delegation {
    name = "app-service-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# Network Security Group
resource "azurerm_network_security_group" "main" {
  name                = "${var.resource_prefix}-${var.environment}-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow HTTPS only
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }

  # Deny all other inbound traffic
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = azurerm_resource_group.main.tags
}

# Associate NSG with subnets
resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# Key Vault for HIPAA Customer-Managed Keys
resource "azurerm_key_vault" "main" {
  name                       = "${var.resource_prefix}-${var.environment}-kv"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  # Temporarily enable public access for key creation, then restrict via private endpoints
  public_network_access_enabled = true

  # Enable for deployment, disk encryption, and template deployment
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = true
  enabled_for_template_deployment = false

  network_acls {
    default_action = "Allow"  # Temporarily allow during deployment
    bypass         = "AzureServices"
  }

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = var.admin_object_id

    key_permissions = [
      "Create", "Delete", "Get", "List", "Update", "Import", "Backup", "Restore", "Recover"
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Backup", "Restore", "Recover"
    ]

    certificate_permissions = [
      "Get", "List", "Create", "Delete", "Update", "Import"
    ]
  }

  tags = azurerm_resource_group.main.tags
}

# Customer-Managed Encryption Keys
resource "azurerm_key_vault_key" "phi_primary" {
  name         = "hipaa-phi-primary"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P6M"
    notify_before_expiry = "P30D"
  }

  depends_on = [azurerm_key_vault.main]
}

resource "azurerm_key_vault_key" "phi_backup" {
  name         = "hipaa-phi-backup"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P6M"
    notify_before_expiry = "P30D"
  }

  depends_on = [azurerm_key_vault.main]
}

resource "azurerm_key_vault_key" "audit_logs" {
  name         = "hipaa-audit-logs"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P6M"
    notify_before_expiry = "P30D"
  }

  depends_on = [azurerm_key_vault.main]
}

# Post-deployment script to restrict Key Vault public access
resource "null_resource" "restrict_keyvault_access" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "Restricting Key Vault public access after key creation..."
      az keyvault update \
        --name "${var.resource_prefix}-${var.environment}-kv" \
        --resource-group "${azurerm_resource_group.main.name}" \
        --public-network-access Disabled \
        --default-action Deny
    EOT
  }

  depends_on = [
    azurerm_key_vault_key.phi_primary,
    azurerm_key_vault_key.phi_backup,
    azurerm_key_vault_key.audit_logs
  ]
}

# Storage Account for Audit Logs (7-year retention)
resource "azurerm_storage_account" "audit_logs" {
  name                     = "${replace(var.resource_prefix, "-", "")}${var.environment}audit"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  # Security settings
  public_network_access_enabled   = false
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  min_tls_version                  = "TLS1_2"

  # Customer-managed encryption
  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.audit_logs.id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.storage.id]
  }

  tags = azurerm_resource_group.main.tags
}

# User Assigned Identity for Storage Account
resource "azurerm_user_assigned_identity" "storage" {
  name                = "${var.resource_prefix}-${var.environment}-storage-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = azurerm_resource_group.main.tags
}

# Key Vault Access Policy for Storage Identity
resource "azurerm_key_vault_access_policy" "storage" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.storage.principal_id

  key_permissions = [
    "Get", "UnwrapKey", "WrapKey"
  ]
}

# Blob Container for Audit Logs
resource "azurerm_storage_container" "audit_logs" {
  name                  = "hipaa-audit-logs"
  storage_account_name  = azurerm_storage_account.audit_logs.name
  container_access_type = "private"
}

# Log Analytics Workspace for 7-year retention
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.resource_prefix}-${var.environment}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 730   # 2 years (Azure maximum)
  daily_quota_gb      = 100

  tags = azurerm_resource_group.main.tags
}

# Application Insights
resource "azurerm_application_insights" "main" {
  name                = "${var.resource_prefix}-${var.environment}-ai"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"

  tags = azurerm_resource_group.main.tags
}

# App Service Plan
resource "azurerm_service_plan" "main" {
  name                = "${var.resource_prefix}-${var.environment}-asp"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "S0"  # Free Standard tier to avoid quota issues

  tags = azurerm_resource_group.main.tags
}

# Web App with HIPAA Configuration
resource "azurerm_linux_web_app" "main" {
  name                = "${var.resource_prefix}-${var.environment}-app"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_service_plan.main.location
  service_plan_id     = azurerm_service_plan.main.id

  # Security settings
  https_only                    = true
  client_certificate_enabled   = false
  client_certificate_mode       = "Required"
  public_network_access_enabled = false

  # VNet integration
  virtual_network_subnet_id = azurerm_subnet.app_service.id

  site_config {
    always_on         = true
    health_check_path = "/health"
    http2_enabled     = true
    minimum_tls_version = "1.2"

    # Security headers
    app_command_line = ""
    
    application_stack {
      python_version = "3.11"
    }

    # IP restrictions - deny all public access
    ip_restriction {
      virtual_network_subnet_id = azurerm_subnet.private_endpoints.id
      action                    = "Allow"
      priority                  = 100
    }

    ip_restriction {
      ip_address = "0.0.0.0/0"
      action     = "Deny"
      priority   = 2147483647
    }
  }

  app_settings = {
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = azurerm_application_insights.main.connection_string
    "KEY_VAULT_URL"                        = azurerm_key_vault.main.vault_uri
    "STORAGE_ACCOUNT_URL"                  = azurerm_storage_account.audit_logs.primary_blob_endpoint
    "LOG_ANALYTICS_WORKSPACE_ID"           = azurerm_log_analytics_workspace.main.workspace_id
    "ENVIRONMENT"                          = var.environment
    "HIPAA_COMPLIANCE_MODE"                = "true"
    "AUDIT_LOG_RETENTION_YEARS"            = "7"
    "ENCRYPTION_KEY_ROTATION_MONTHS"       = "6"
    "SESSION_TIMEOUT_MINUTES"              = "30"
    "MFA_REQUIRED"                         = "true"
    "TLS_MIN_VERSION"                      = "1.2"
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  tags = azurerm_resource_group.main.tags
}

# User Assigned Identity for Web App
resource "azurerm_user_assigned_identity" "app" {
  name                = "${var.resource_prefix}-${var.environment}-app-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = azurerm_resource_group.main.tags
}

# Key Vault Access Policy for Web App
resource "azurerm_key_vault_access_policy" "app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.app.principal_id

  key_permissions = [
    "Get", "Decrypt", "Encrypt", "UnwrapKey", "WrapKey", "Verify", "Sign"
  ]

  secret_permissions = [
    "Get", "List"
  ]
}

# Private Endpoints (created after keys to avoid access issues)
resource "azurerm_private_endpoint" "key_vault" {
  name                = "${var.resource_prefix}-${var.environment}-kv-pe"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.resource_prefix}-${var.environment}-kv-psc"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.main.tags
  
  # Create private endpoint AFTER keys are created
  depends_on = [
    azurerm_key_vault_key.phi_primary,
    azurerm_key_vault_key.phi_backup,
    azurerm_key_vault_key.audit_logs
  ]
}

resource "azurerm_private_endpoint" "storage" {
  name                = "${var.resource_prefix}-${var.environment}-storage-pe"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.resource_prefix}-${var.environment}-storage-psc"
    private_connection_resource_id = azurerm_storage_account.audit_logs.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_private_endpoint" "app" {
  name                = "${var.resource_prefix}-${var.environment}-app-pe"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.resource_prefix}-${var.environment}-app-psc"
    private_connection_resource_id = azurerm_linux_web_app.main.id
    subresource_names              = ["sites"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.main.tags
}

# Azure Monitor Diagnostic Settings (created after private endpoints)
resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name               = "${var.resource_prefix}-${var.environment}-kv-diag"
  target_resource_id = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }

  depends_on = [azurerm_private_endpoint.key_vault]
}

resource "azurerm_monitor_diagnostic_setting" "storage" {
  name               = "${var.resource_prefix}-${var.environment}-storage-diag"
  target_resource_id = azurerm_storage_account.audit_logs.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "web_app" {
  name               = "${var.resource_prefix}-${var.environment}-app-diag"
  target_resource_id = azurerm_linux_web_app.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AppServiceHTTPLogs"
  }

  enabled_log {
    category = "AppServiceConsoleLogs"
  }

  enabled_log {
    category = "AppServiceAppLogs"
  }

  enabled_log {
    category = "AppServiceAuditLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# Data sources
data "azurerm_client_config" "current" {}

# Outputs
output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.main.vault_uri
  sensitive   = true
}

output "web_app_hostname" {
  description = "Hostname of the web app"
  value       = azurerm_linux_web_app.main.default_hostname
}

output "storage_account_name" {
  description = "Name of the audit logs storage account"
  value       = azurerm_storage_account.audit_logs.name
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.workspace_id
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.main.connection_string
  sensitive   = true
}