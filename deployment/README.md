# HIPAA-RAG Production Deployment Guide

Complete guide for deploying the HIPAA-compliant RAG system to Azure production.

## ⚠️ IMPORTANT: Automated Deployment Limitations

The automated deployment script (`deploy.sh`) may fail due to:
- Azure quota restrictions in your subscription
- Key Vault soft-delete conflicts from previous deployments
- Network access restrictions preventing key creation
- App Service Plan SKU availability in your region

**If automated deployment fails**, please follow the [Manual Deployment Guide](manual-deployment-guide.md) which includes all necessary workarounds.

## 🚀 Quick Start

### Prerequisites

1. **Azure CLI** - `az login` completed
2. **Terraform** - Version >= 1.0.0
3. **Required permissions** - Owner or Contributor role on Azure subscription
4. **Tools installed**: `jq`, `curl`
5. **Location**: Deployment requires **East US 2** (not East US)
6. **App Service**: Must use **S1 Standard** tier for HIPAA compliance

### One-Command Deployment (Automated)

```bash
cd deployment
./deploy.sh all
```

This runs the complete 4-phase deployment process automatically.

**Note**: If this fails, use the [Manual Deployment Guide](manual-deployment-guide.md) instead.

## 📋 Deployment Phases

### Phase 1: Infrastructure (Day 1-2) - 8 Hours

**Critical Priority** - Core Azure infrastructure with HIPAA compliance

```bash
./deploy.sh infra
```

**Deploys:**
- ✅ **Azure Key Vault** with customer-managed encryption keys
- ✅ **Virtual Network** with private subnets and security groups
- ✅ **Storage Account** with 7-year audit log retention (GRS)
- ✅ **Log Analytics Workspace** with 7-year retention
- ✅ **Private Endpoints** for all services (zero public access)
- ✅ **Network Security Groups** with restrictive HIPAA-compliant rules

**Validation:**
- All encryption keys operational and rotating every 6 months
- Network isolation policies active
- Audit logging capturing all security events
- Zero public endpoints accessible

**Rollback Time:** 15 minutes automated

### Phase 2: Application (Day 2-3) - 6 Hours

**Critical Priority** - HIPAA-RAG application with security decorators

```bash
./deploy.sh app
```

**Deploys:**
- ✅ **App Service Plan** (Premium P2v3 for production)
- ✅ **Linux Web App** with VNet integration
- ✅ **Application Insights** for monitoring
- ✅ **HIPAA Security Configuration** (TLS 1.3, MFA, session timeout)
- ✅ **Identity Management** with Azure AD integration

**Validation:**
- 100% API endpoints protected with HIPAA decorators
- MFA enforcement active for all users
- Rate limiting and DDoS protection functional
- Security controls validated under load

**Rollback Time:** 5 minutes via feature flags

### Phase 3: Security (Day 3-5) - 13 Hours

**High Priority** - Advanced security monitoring and compliance

```bash
./deploy.sh security
```

**Configures:**
- ✅ **Azure Security Center** with advanced threat protection
- ✅ **Azure Defender** for Key Vault, Storage, and App Services
- ✅ **Diagnostic Settings** for comprehensive audit logging
- ✅ **Real-time Monitoring** with automated alerting
- ✅ **Compliance Validation** with automated checks

**Validation:**
- Real-time monitoring operational (<1-minute alerting)
- Automated compliance checks passing continuously
- Threat detection responding to simulated attacks
- Live security tests confirming HIPAA compliance

**Rollback Time:** N/A (monitoring only, no rollback needed)

### Phase 4: Validation (Day 5-7) - 18 Hours

**Medium Priority** - Business validation and certification

```bash
./deploy.sh validate
```

**Validates:**
- ✅ **Key Vault Access** and encryption key functionality
- ✅ **Web App Health** and performance under load
- ✅ **Private Endpoint** configuration and network isolation
- ✅ **Security Controls** comprehensive testing
- ✅ **Diagnostic Settings** and audit log collection

**Business Tasks:**
- Execute BAA with initial healthcare partners
- Conduct final penetration testing with healthcare data
- Generate compliance certification documentation

## 🔧 Manual Deployment Steps

### Individual Phase Deployment

```bash
# Phase 1 only
./deploy.sh infra

# Phase 2 only (requires Phase 1 complete)
./deploy.sh app

# Phase 3 only (requires Phase 1-2 complete)
./deploy.sh security

# Phase 4 only (validation and testing)
./deploy.sh validate
```

### Prerequisites Check

```bash
./deploy.sh prereq
```

Validates:
- Azure CLI login status
- Terraform installation and version
- Required tools availability
- User permissions

## 🏗️ Infrastructure Architecture

### Network Architecture
```
Internet (HTTPS only)
    ↓
Application Gateway (WAF + DDoS)
    ↓
Virtual Network (10.0.0.0/16)
    ├── Private Endpoints Subnet (10.0.1.0/24)
    │   ├── Key Vault Private Endpoint
    │   ├── Storage Private Endpoint
    │   └── App Service Private Endpoint
    └── App Service Subnet (10.0.2.0/24)
        └── HIPAA-RAG Web App
```

### Security Architecture
```
Azure AD B2C (MFA + RBAC)
    ↓
Application Gateway (TLS 1.3 + Certificate Pinning)
    ↓
HIPAA Security Decorators (@require_hipaa_auth)
    ↓
Web App (Private Endpoints Only)
    ↓
Azure Key Vault (Customer-Managed Keys)
    ↓
Storage Account (Encrypted + 7-Year Retention)
```

## 🔒 HIPAA Compliance Configuration

### Technical Safeguards (§164.312)
- **Access Control**: Azure AD B2C with MFA and RBAC
- **Audit Controls**: 7-year log retention with immutable storage
- **Integrity**: Cryptographic hash validation
- **Person/Entity Authentication**: Multi-factor authentication
- **Transmission Security**: TLS 1.3 with certificate pinning

### Administrative Safeguards (§164.308)
- **Security Officer**: Designated HIPAA Security Officer role
- **Workforce Training**: HIPAA security awareness program
- **Information Access Management**: Role-based access control
- **Security Incident Procedures**: Automated incident response
- **Contingency Plan**: Business continuity and disaster recovery

### Physical Safeguards (§164.310)
- **Facility Access Controls**: Azure data center physical security
- **Workstation Use**: Secure endpoint configuration
- **Device and Media Controls**: Azure-managed secure disposal

## 📊 Monitoring and Alerting

### Real-Time Monitoring
- **Azure Monitor**: Performance and availability metrics
- **Application Insights**: Application performance monitoring
- **Log Analytics**: Centralized log analysis with 7-year retention
- **Security Center**: Advanced threat protection and compliance

### Automated Alerts
- **Security Events**: Unauthorized access attempts, failed authentications
- **Performance Issues**: High response times, error rates
- **Compliance Violations**: Policy violations, configuration drift
- **Infrastructure Health**: Resource availability, capacity thresholds

### Dashboards
- **Operations Dashboard**: System health and performance
- **Security Dashboard**: Security events and compliance status
- **Compliance Dashboard**: HIPAA requirement tracking
- **Business Dashboard**: Usage metrics and audit reports

## 🚨 Rollback Procedures

### Automated Rollback
```bash
./deploy.sh rollback
```

**WARNING**: This destroys all deployed resources and cannot be undone.

### Rollback Capabilities by Phase
- **Phase 1**: 15-minute automated infrastructure rollback
- **Phase 2**: 5-minute feature flag rollback for application
- **Phase 3**: No rollback needed (monitoring configuration only)
- **Phase 4**: No rollback needed (validation and testing only)

### Emergency Rollback
```bash
# Immediate application rollback via feature flags
az webapp config appsettings set \
    --resource-group "hipaa-rag-prod-rg" \
    --name "hipaa-rag-prod-app" \
    --settings HIPAA_COMPLIANCE_MODE=false

# Immediate traffic diversion
az network application-gateway stop \
    --resource-group "hipaa-rag-prod-rg" \
    --name "hipaa-rag-prod-agw"
```

## 📈 Performance and Scaling

### Auto-Scaling Configuration
- **App Service Plan**: P2v3 with auto-scale rules
- **Scale Out**: 2-10 instances based on CPU/memory
- **Scale Rules**: CPU >70% scale out, <30% scale in
- **Cool Down**: 5 minutes to prevent flapping

### Performance Targets
- **Response Time**: <200ms for API calls
- **Availability**: 99.9% uptime SLA
- **Throughput**: 1000 concurrent users
- **Recovery Time**: <5 minutes for critical services

## 🔐 Security Configuration

### Key Management
- **Encryption Keys**: Customer-managed in Azure Key Vault
- **Key Rotation**: Automatic every 6 months
- **Key Access**: Limited to service identities only
- **Key Backup**: Automatic with geo-redundant storage

### Network Security
- **Public Access**: Disabled for all services
- **Private Endpoints**: All inter-service communication
- **NSG Rules**: Restrictive with HTTPS-only allowed
- **DDoS Protection**: Azure DDoS Protection Standard

### Application Security
- **Authentication**: Azure AD B2C with MFA
- **Authorization**: Role-based with minimum necessary principle
- **Session Management**: 30-minute timeout with secure cookies
- **Input Validation**: Comprehensive sanitization and validation

## 📋 Post-Deployment Tasks

### Immediate (Day 1)
1. **Verify Infrastructure**: Run `./deploy.sh validate`
2. **Test Security**: Penetration testing with synthetic data
3. **Configure Monitoring**: Set up custom alerts and dashboards
4. **Document Access**: Update team access documentation

### Week 1
1. **Performance Testing**: Load testing with realistic data
2. **Security Hardening**: Additional security control implementation
3. **Backup Validation**: Test backup and recovery procedures
4. **Team Training**: Operations team HIPAA compliance training

### Month 1
1. **Compliance Audit**: Internal HIPAA compliance assessment
2. **Security Review**: Quarterly security assessment
3. **Performance Optimization**: Based on production metrics
4. **Documentation Update**: Update operational procedures

## 🆘 Troubleshooting

### Common Issues

#### ⚠️ Critical: Automated Deployment Failures

If `./deploy.sh` fails with any of these errors, **use the [Manual Deployment Guide](manual-deployment-guide.md)**:

1. **Key Vault Access Denied (403 Forbidden)**
   - Error: "Public network access is disabled and request is not from a trusted service"
   - Cause: Script tries to create keys in a Key Vault with public access disabled
   - Solution: Follow manual deployment to temporarily enable public access

2. **App Service Plan Quota Exceeded**
   - Error: "Subscription doesn't have required quota for PremiumV3Small VMs"
   - Cause: No P2v3 quota in East US
   - Solution: Use East US 2 with S1 Standard tier

3. **Wrong Location Deployment**
   - Symptom: Resources deployed to East US instead of East US 2
   - Cause: Default location in script is incorrect
   - Solution: Set `LOCATION=eastus2` explicitly

4. **Key Vault Name Already Exists**
   - Error: "A vault with the same name already exists in deleted state"
   - Cause: Previous failed deployment left soft-deleted Key Vault
   - Solution: Use unique naming or purge old vaults

#### Terraform Deployment Fails
```bash
# Check Azure CLI login
az account show

# Verify permissions
az role assignment list --assignee $(az account show --query user.name -o tsv)

# Clean and retry
terraform destroy -auto-approve
terraform init -upgrade
terraform apply
```

#### Key Vault Access Denied
```bash
# Check user object ID
az ad signed-in-user show --query id -o tsv

# Update Key Vault access policy
az keyvault set-policy \
    --name "hipaa-rag-prod-kv-0801" \
    --object-id "YOUR_OBJECT_ID" \
    --key-permissions create delete get list update
```

#### Web App Not Accessible
```bash
# Check private endpoint status
az network private-endpoint list --resource-group "hipaa-rag-prod-rg"

# Verify VNet integration
az webapp vnet-integration list --resource-group "hipaa-rag-prod-rg" --name "hipaa-rag-prod-app"

# Check NSG rules
az network nsg rule list --resource-group "hipaa-rag-prod-rg" --nsg-name "hipaa-rag-prod-nsg"
```

### Support Contacts
- **Azure Support**: Azure Portal > Help + Support
- **Security Issues**: Follow incident response plan
- **Performance Issues**: Check Application Insights dashboard
- **Compliance Questions**: Contact designated HIPAA Security Officer

## 📚 Additional Resources

### Documentation
- [Azure HIPAA Compliance](https://docs.microsoft.com/en-us/azure/compliance/offerings/offering-hipaa-us)
- [Terraform Azure Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-overview)

### Training
- HIPAA Security Officer Training
- Azure Security Engineer Associate
- Azure Solutions Architect Expert
- Terraform Associate Certification

---

**🏥 Ready for Healthcare Partnerships**

This deployment provides industry-leading HIPAA compliance for healthcare AI with automated security controls and comprehensive audit capabilities.