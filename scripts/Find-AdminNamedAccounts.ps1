<#
.SYNOPSIS
    Finds every account that LOOKS like an admin account (by naming convention),
    regardless of group membership, and reports how risky each one is.

.DESCRIPTION
    Group-based checks (e.g. "members of SG-ADM-*") only see accounts that are in those
    groups. In the IAM365 lab, two "ADM" accounts had no role and no admin-group membership,
    so a group-based check missed them, yet they were enabled, never used and protected
    only by a password.

    This script sweeps by UPN prefix instead and reports, per account:
      enabled state, creation date, last sign-in, direct role assignments,
      eligible (PIM) group memberships, group memberships, authentication methods,
      and whether a phishing-resistant method is registered.

    Flags:
      PASSWORD-ONLY   enabled account with no MFA method registered
      NEVER-USED      enabled account with no recorded sign-in
      NO-STRONG-AUTH  enabled account without a phishing-resistant method

    Guest accounts whose address starts with the prefix are also returned (Type = Guest):
    review them as well, since a naming match is not proof of privilege.

.PARAMETER Prefix
    UPN prefix that identifies admin accounts (default 'adm', which covers 'adm-' and 'adm.').

.NOTES
    Required Graph scopes: User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory,
                           UserAuthenticationMethod.Read.All, Group.Read.All,
                           PrivilegedAccess.Read.AzureADGroup
    Author: Javier Coliqueo — IAM365 lab
#>

param(
    [string]$Prefix = 'adm'
)

Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","RoleManagement.Read.Directory",
                        "UserAuthenticationMethod.Read.All","Group.Read.All","PrivilegedAccess.Read.AzureADGroup" -NoWelcome

$phishingResistant = 'fido2AuthenticationMethod','windowsHelloForBusinessAuthenticationMethod','x509CertificateAuthenticationMethod'

$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }

# Sign-in activity requires P1/P2; fall back gracefully if it is not available
$props = 'Id','UserPrincipalName','DisplayName','UserType','AccountEnabled','CreatedDateTime','SignInActivity'
try {
    $users = Get-MgUser -Filter "startswith(userPrincipalName,'$Prefix')" -Property $props -All -ErrorAction Stop
} catch {
    Write-Warning "Sign-in activity not available ($($_.Exception.Message)). Continuing without it."
    $users = Get-MgUser -Filter "startswith(userPrincipalName,'$Prefix')" -Property ($props -ne 'SignInActivity') -All
}

$report = foreach ($u in $users) {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($u.Id)'" -All |
             ForEach-Object { $roleNames[$_.RoleDefinitionId] }

    $eligibleGroups = @()
    try {
        $eligibleGroups = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "principalId eq '$($u.Id)'" -All -ErrorAction Stop |
                          ForEach-Object { (Get-MgGroup -GroupId $_.GroupId).DisplayName }
    } catch { }

    $groups  = (Get-MgUserMemberOf -UserId $u.Id -All).AdditionalProperties.displayName
    $methods = (Get-MgUserAuthenticationMethod -UserId $u.Id).AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
    $mfa     = $methods | Where-Object { $_ -ne 'passwordAuthenticationMethod' }
    $strong  = [bool]($methods | Where-Object { $_ -in $phishingResistant })
    $last    = $u.SignInActivity.LastSignInDateTime

    $flags = @()
    if ($u.AccountEnabled) {
        if (-not $mfa)    { $flags += 'PASSWORD-ONLY' }
        if (-not $last)   { $flags += 'NEVER-USED' }
        if (-not $strong) { $flags += 'NO-STRONG-AUTH' }
    }

    [pscustomobject]@{
        User           = $u.UserPrincipalName
        Type           = $u.UserType
        Enabled        = $u.AccountEnabled
        Created        = ([datetime]$u.CreatedDateTime).ToString('yyyy-MM-dd')
        LastSignIn     = if ($last) { ([datetime]$last).ToString('yyyy-MM-dd') } else { '-' }
        DirectRoles    = ($roles -join ', ')
        EligibleGroups = ($eligibleGroups -join ', ')
        Groups         = ($groups -join ', ')
        StrongAuth     = $strong
        Methods        = ($methods -join ', ')
        Flags          = ($flags -join ' ')
    }
}

$report | Sort-Object Type, User | Format-Table User, Type, Enabled, Created, LastSignIn, DirectRoles, EligibleGroups, StrongAuth, Flags -AutoSize | Out-Host

$risky = $report | Where-Object Flags
if ($risky) {
    Write-Warning "$(@($risky).Count) enabled admin-named account(s) need attention:"
    $risky | Format-Table User, Flags -AutoSize
} else {
    Write-Host "No enabled admin-named account is password-only, unused or without strong authentication." -ForegroundColor Green
}

# Full detail (groups and methods) for evidence:
# $report | Export-Csv "$HOME\Documents\admin-named-accounts.csv" -NoTypeInformation -Encoding utf8
