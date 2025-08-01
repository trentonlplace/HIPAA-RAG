# [PHI] HIPAA Policy Deployment Script
# Classification: PHI-CRITICAL
# Author: HIPAA Compliance Team
# Version: 1.0.0
# Last Updated: 2025-08-01

<#
.SYNOPSIS
    Deploy HIPAA/HITRUST compliance policies for RAG system.

.DESCRIPTION
    This script deploys custom HIPAA policies and assigns built-in compliance policies
    for HIPAA, HITRUST, and NIST SP 800-53 R4 compliance.

.PARAMETER SubscriptionId
    Azure subscription ID

.PARAMETER ResourceGroupName
    Resource group name for policy scope

.PARAMETER EnvironmentName
    Environment name (dev, staging, prod)

.PARAMETER LogAnalyticsWorkspaceId
    Resource ID of Log Analytics workspace for audit logging

.PARAMETER SecurityOfficerId
    Object ID of HIPAA Security Officer

.EXAMPLE
    .\deploy-policies.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-hipaa-rag-prod" -EnvironmentName "prod" -LogAnalyticsWorkspaceId "/subscriptions/12345678-1234-1234-1234-123456789012/resourcegroups/rg-hipaa-rag-prod/providers/microsoft.operationalinsights/workspaces/log-hipaa-rag-eastus-1234" -SecurityOfficerId "87654321-4321-4321-4321-210987654321"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$EnvironmentName,
    
    [Parameter(Mandatory=$true)]
    [string]$LogAnalyticsWorkspaceId,
    
    [Parameter(Mandatory=$true)]
    [string]$SecurityOfficerId
)

$ErrorActionPreference = "Stop"

# Function to log deployment events
function Write-DeploymentLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

try {
    Write-DeploymentLog "Starting HIPAA policy deployment..." "SUCCESS"
    Write-DeploymentLog "Subscription: $SubscriptionId"
    Write-DeploymentLog "Resource Group: $ResourceGroupName"
    Write-DeploymentLog "Environment: $EnvironmentName"

    # Set Azure context
    Write-DeploymentLog "Setting Azure subscription context"
    Set-AzContext -SubscriptionId $SubscriptionId

    # Get script directory
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    
    # Deploy custom policy definitions
    Write-DeploymentLog "Deploying custom HIPAA policy definitions"
    $policyDefinitionsTemplate = Join-Path $scriptPath "hipaa-policies.json"
    
    $policyDeploymentParams = @{
        Name                = "hipaa-policy-definitions-$(Get-Random)"
        ResourceGroupName   = $ResourceGroupName
        TemplateFile        = $policyDefinitionsTemplate
        subscriptionId      = $SubscriptionId
        resourceGroupName   = $ResourceGroupName
        environmentName     = $EnvironmentName
    }
    
    $policyDeployment = New-AzResourceGroupDeployment @policyDeploymentParams
    
    if ($policyDeployment.ProvisioningState -eq "Succeeded") {
        Write-DeploymentLog "Custom policy definitions deployed successfully" "SUCCESS"
        $customPolicyIds = $policyDeployment.Outputs.policyDefinitionIds.Value
        Write-DeploymentLog "Created $($customPolicyIds.Count) custom policy definitions"
    } else {
        throw "Policy definitions deployment failed: $($policyDeployment.ProvisioningState)"
    }

    # Wait for policy definitions to propagate
    Write-DeploymentLog "Waiting for policy definitions to propagate..."
    Start-Sleep -Seconds 30

    # Deploy policy assignments
    Write-DeploymentLog "Deploying HIPAA policy assignments"
    $policyAssignmentsTemplate = Join-Path $scriptPath "hipaa-policy-assignments.json"
    
    $assignmentDeploymentParams = @{
        Name                     = "hipaa-policy-assignments-$(Get-Random)"
        ResourceGroupName        = $ResourceGroupName
        TemplateFile            = $policyAssignmentsTemplate
        subscriptionId          = $SubscriptionId
        resourceGroupName       = $ResourceGroupName
        environmentName         = $EnvironmentName
        logAnalyticsWorkspaceId = $LogAnalyticsWorkspaceId
        securityOfficerId       = $SecurityOfficerId
    }
    
    $assignmentDeployment = New-AzResourceGroupDeployment @assignmentDeploymentParams
    
    if ($assignmentDeployment.ProvisioningState -eq "Succeeded") {
        Write-DeploymentLog "Policy assignments deployed successfully" "SUCCESS"
        $totalPolicies = $assignmentDeployment.Outputs.totalPoliciesAssigned.Value
        Write-DeploymentLog "Assigned $totalPolicies compliance policies"
    } else {
        throw "Policy assignments deployment failed: $($assignmentDeployment.ProvisioningState)"
    }

    # Validate policy compliance (initial evaluation)
    Write-DeploymentLog "Initiating policy compliance evaluation"
    
    $resourceGroupScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
    
    # Trigger compliance evaluation for critical policies
    $criticalPolicies = @(
        "hipaa-rag-phi-encryption-$EnvironmentName",
        "hipaa-rag-private-endpoints-$EnvironmentName",
        "hipaa-rag-audit-logging-$EnvironmentName"
    )
    
    foreach ($policyName in $criticalPolicies) {
        try {
            Write-DeploymentLog "Triggering compliance evaluation for: $policyName"
            Start-AzPolicyComplianceScan -ResourceGroupName $ResourceGroupName
        } catch {
            Write-DeploymentLog "Failed to trigger compliance scan for $policyName : $($_.Exception.Message)" "WARNING"
        }
    }

    # Generate compliance report
    Write-DeploymentLog "Generating HIPAA policy compliance report"
    
    $complianceReport = @{
        DeploymentId = "hipaa-policies-$EnvironmentName-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        SubscriptionId = $SubscriptionId
        ResourceGroup = $ResourceGroupName
        Environment = $EnvironmentName
        DeploymentDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        SecurityOfficer = $SecurityOfficerId
        LogAnalyticsWorkspace = $LogAnalyticsWorkspaceId
        
        PolicyDefinitions = @{
            CustomPolicies = $customPolicyIds.Count
            BuiltInPolicySets = 3  # HITRUST, NIST, Azure Security Benchmark
            TotalPolicies = $totalPolicies
        }
        
        DeployedPolicies = @(
            @{
                Name = "HIPAA HITRUST Compliance"
                Type = "Built-in Policy Set"
                Scope = $resourceGroupScope
                EnforcementMode = "Default"
                HIPAAControls = @("Multiple HITRUST controls")
            },
            @{
                Name = "NIST SP 800-53 R4 Compliance"
                Type = "Built-in Policy Set"
                Scope = $resourceGroupScope
                EnforcementMode = "Default"
                HIPAAControls = @("Federal security controls")
            },
            @{
                Name = "Azure Security Benchmark"
                Type = "Built-in Policy Set"
                Scope = $resourceGroupScope
                EnforcementMode = "Default"
                HIPAAControls = @("Cloud security best practices")
            },
            @{
                Name = "PHI Data Encryption"
                Type = "Custom Policy"
                Scope = $resourceGroupScope
                EnforcementMode = if ($EnvironmentName -eq "prod") { "Deny" } else { "Audit" }
                HIPAAControls = @("164.312(a)(2)(iv)")
            },
            @{
                Name = "Private Endpoints Required"
                Type = "Custom Policy"
                Scope = $resourceGroupScope
                EnforcementMode = if ($EnvironmentName -eq "prod") { "Deny" } else { "Audit" }
                HIPAAControls = @("164.312(e)(1)")
            },
            @{
                Name = "Audit Logging Required"
                Type = "Custom Policy"
                Scope = $resourceGroupScope
                EnforcementMode = "AuditIfNotExists"
                HIPAAControls = @("164.312(b)")
            },
            @{
                Name = "Backup Retention"
                Type = "Custom Policy"
                Scope = $resourceGroupScope
                EnforcementMode = if ($EnvironmentName -eq "prod") { "Deny" } else { "Audit" }
                HIPAAControls = @("164.312(c)(2)")
            },
            @{
                Name = "Access Controls"
                Type = "Custom Policy"
                Scope = $resourceGroupScope
                EnforcementMode = "AuditIfNotExists"
                HIPAAControls = @("164.312(a)(1)")
            }
        )
        
        ComplianceLevel = "HIPAA"
        Status = "POLICIES_DEPLOYED"
        NextEvaluation = (Get-Date).AddHours(24).ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        Recommendations = @(
            "Monitor policy compliance dashboard within 24 hours",
            "Review and remediate any non-compliant resources",
            "Schedule monthly policy compliance reviews",
            "Update custom policies as needed for regulatory changes",
            "Conduct quarterly security assessments",
            "Ensure Security Officer reviews policy violations weekly"
        )
    }

    # Save compliance report
    $reportPath = "hipaa-policy-compliance-report-$EnvironmentName.json"
    $complianceReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-DeploymentLog "HIPAA policy deployment completed successfully!" "SUCCESS"
    Write-DeploymentLog "Compliance report saved to: $reportPath" "SUCCESS"
    Write-DeploymentLog "Total policies deployed: $totalPolicies" "SUCCESS"

    # Output summary
    Write-Host ""
    Write-Host "=== HIPAA POLICY DEPLOYMENT COMPLETE ===" -ForegroundColor Green
    Write-Host "Environment: $EnvironmentName" -ForegroundColor Yellow
    Write-Host "Policies Deployed: $totalPolicies" -ForegroundColor Yellow
    Write-Host "Custom Policies: $($customPolicyIds.Count)" -ForegroundColor Yellow
    Write-Host "Built-in Policy Sets: 3" -ForegroundColor Yellow
    Write-Host "Compliance Report: $reportPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT NEXT STEPS:" -ForegroundColor Red
    Write-Host "1. Monitor compliance dashboard for policy evaluation results" -ForegroundColor White
    Write-Host "2. Deploy resources using HIPAA-compliant ARM templates" -ForegroundColor White
    Write-Host "3. Review and remediate any non-compliant resources within 24 hours" -ForegroundColor White
    Write-Host "4. Configure automated compliance monitoring and alerting" -ForegroundColor White
    Write-Host "5. Schedule regular compliance reviews with Security Officer" -ForegroundColor White
    Write-Host ""

} catch {
    Write-DeploymentLog "HIPAA policy deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}

Write-DeploymentLog "HIPAA policy deployment script completed" "SUCCESS"