<#
.SYNOPSIS
    Copies the PIM for Groups "Member" settings from a reference group to other groups,
    so every privileged group follows the same just-in-time rules.

.DESCRIPTION
    PIM for Groups stores its settings as a role management policy per group and per
    access type (member / owner). Each policy is a set of rules, for example:
      - Expiration_EndUser_Assignment            -> activation maximum duration
      - Enablement_EndUser_Assignment            -> justification / MFA on activation
      - AuthenticationContext_EndUser_Assignment -> Conditional Access authentication context
      - Approval_EndUser_Assignment              -> approval
      - Expiration_Admin_Eligibility / _Assignment -> expiry of eligible / active assignments
      - Enablement_Admin_Assignment              -> MFA / justification on active assignment
      - Notification_*                           -> email notifications

    The script reads the rules of the reference group (configured and tested in the portal)
    and writes the same rules to each target group. Run with -WhatIf first to preview.

.PARAMETER SourceGroup
    Reference group whose Member settings are copied.

.PARAMETER TargetGroups
    Groups that receive the settings.

.EXAMPLE
    .\Copy-PimGroupSettings.ps1 -WhatIf
    .\Copy-PimGroupSettings.ps1

.NOTES
    Required Graph scopes: Group.Read.All, RoleManagementPolicy.ReadWrite.AzureADGroup
    The signed-in admin needs an active privileged role (e.g. Global Administrator via PIM).
    Author: Javier Coliqueo — IAM365 lab
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SourceGroup = 'SG-ADM-GLOBAL',
    [string[]]$TargetGroups = @('SG-ADM-HELPDESK','SG-ADM-SECURITY','SG-ADM-GRC','SG-ADM-IDENTITY')
)

Connect-MgGraph -Scopes "Group.Read.All","RoleManagementPolicy.ReadWrite.AzureADGroup" -NoWelcome

function Get-MemberPolicyId([string]$groupName) {
    $g = Get-MgGroup -Filter "displayName eq '$groupName'"
    if (-not $g) { throw "Group '$groupName' not found." }
    $uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$($g.Id)' and scopeType eq 'Group' and roleDefinitionId eq 'member'"
    $a = (Invoke-MgGraphRequest -Method GET -Uri $uri).value
    if (-not $a) { throw "No PIM member policy found for '$groupName'." }
    $a[0].policyId
}

function Get-PolicyRules([string]$policyId) {
    (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules").value
}

# 1) Reference rules
$sourcePolicy = Get-MemberPolicyId $SourceGroup
$sourceRules  = Get-PolicyRules $sourcePolicy
Write-Host "Reference: $SourceGroup ($(@($sourceRules).Count) rules)" -ForegroundColor Cyan

# 2) Copy to each target
foreach ($t in $TargetGroups) {
    $targetPolicy = Get-MemberPolicyId $t
    Write-Host "`n$t" -ForegroundColor Cyan

    foreach ($rule in $sourceRules) {
        $body = @{}
        foreach ($k in $rule.Keys) { if ($k -notin '@odata.context') { $body[$k] = $rule[$k] } }

        if ($PSCmdlet.ShouldProcess("$t / $($rule.id)", 'Update rule')) {
            try {
                Invoke-MgGraphRequest -Method PATCH `
                    -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$targetPolicy/rules/$($rule.id)" `
                    -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
                Write-Host "  OK    $($rule.id)" -ForegroundColor Green
            } catch {
                Write-Warning "  FAIL  $($rule.id): $($_.Exception.Message)"
            }
        }
    }
}

# 3) Verification: key settings side by side
Write-Host "`nVerification (key rules):" -ForegroundColor Cyan
$keys = 'Expiration_EndUser_Assignment','AuthenticationContext_EndUser_Assignment','Enablement_EndUser_Assignment',
        'Approval_EndUser_Assignment','Expiration_Admin_Eligibility','Expiration_Admin_Assignment'
$verification = foreach ($name in @($SourceGroup) + $TargetGroups) {
    $r = Get-PolicyRules (Get-MemberPolicyId $name)
    $get = { param($id) $r | Where-Object { $_.id -eq $id } }
    [pscustomobject]@{
        Group              = $name
        ActivationMax      = (& $get 'Expiration_EndUser_Assignment').maximumDuration
        AuthContext        = $(if ((& $get 'AuthenticationContext_EndUser_Assignment').isEnabled) { (& $get 'AuthenticationContext_EndUser_Assignment').claimValue } else { '-' })
        OnActivation       = ((& $get 'Enablement_EndUser_Assignment').enabledRules -join ',')
        Approval           = (& $get 'Approval_EndUser_Assignment').setting.isApprovalRequired
        EligibleMax        = (& $get 'Expiration_Admin_Eligibility').maximumDuration
        ActiveMax          = (& $get 'Expiration_Admin_Assignment').maximumDuration
    }
}
$verification | Format-Table -AutoSize
