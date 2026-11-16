<#
.SYNOPSIS
    Checks that every Entra role assigned to the admin role groups (SG-ADM-*)
    is included in the scope of a Conditional Access policy.

.DESCRIPTION
    Conditional Access policies that target directory roles only protect the
    roles listed in the policy. If a role assigned to an admin group is missing,
    the members of that group are silently outside the control.

    In the IAM365 lab, the Microsoft template for "Require phishing-resistant
    MFA for admins" did not include Identity Governance Administrator. This
    script found the gap.

    Expected result: an empty "not covered" list.

.PARAMETER PolicyName
    Display name of the Conditional Access policy to check.

.NOTES
    Required Graph scopes: Group.Read.All, RoleManagement.Read.Directory, Policy.Read.All
    Author: Javier Coliqueo — IAM365 lab
#>

param(
    [string]$PolicyName = 'CA-Admins-Require-PhishingResistantMFA'
)

Connect-MgGraph -Scopes "Group.Read.All","RoleManagement.Read.Directory","Policy.Read.All" -NoWelcome

# 1) Roles assigned to each admin group
$groups = Get-MgGroup -Filter "startswith(displayName,'SG-ADM-')" -All

$assignments = foreach ($g in $groups) {
    foreach ($a in Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($g.Id)'" -All) {
        $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
        [pscustomobject]@{
            Group          = $g.DisplayName
            Role           = $rd.DisplayName
            RoleTemplateId = $rd.TemplateId
        }
    }
}

Write-Host "`nRole matrix (group -> role):" -ForegroundColor Cyan
$assignments | Sort-Object Group | Format-Table Group, Role -AutoSize

# 2) Policy scope
$policy = Get-MgIdentityConditionalAccessPolicy -All | Where-Object DisplayName -eq $PolicyName
if (-not $policy) { throw "Policy '$PolicyName' not found." }

Write-Host "Policy: $($policy.DisplayName)  |  State: $($policy.State)" -ForegroundColor Cyan

# 3) Roles assigned to admin groups but NOT covered by the policy
$notCovered = $assignments | Where-Object { $_.RoleTemplateId -notin $policy.Conditions.Users.IncludeRoles }

if ($notCovered) {
    Write-Warning "Roles assigned to admin groups but NOT covered by the policy:"
    $notCovered | Format-Table Group, Role -AutoSize
} else {
    Write-Host "All roles assigned to SG-ADM-* groups are covered by the policy." -ForegroundColor Green
}

# 4) Exclusions (expected: only the break glass exclusion group)
Write-Host "`nExclusions:" -ForegroundColor Cyan
$excludedUsers  = @($policy.Conditions.Users.ExcludeUsers)  | Where-Object { $_ }
$excludedGroups = @($policy.Conditions.Users.ExcludeGroups) | Where-Object { $_ }

foreach ($id in $excludedUsers)  { Write-Host "  User : $((Get-MgUser  -UserId  $id).UserPrincipalName)" }
foreach ($id in $excludedGroups) { Write-Host "  Group: $((Get-MgGroup -GroupId $id).DisplayName)" }
if (-not ($excludedUsers -or $excludedGroups)) { Write-Host "  (none)" }

if ($excludedUsers) {
    Write-Warning "The policy excludes individual users. Policy templates exclude the creating admin by default; review it."
}
