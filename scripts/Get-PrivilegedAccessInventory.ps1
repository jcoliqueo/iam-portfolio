<#
.SYNOPSIS
    Inventory of privileged access in Entra ID: who holds which directory role,
    whether it is permanent or time-bound, active or only eligible (PIM),
    and how admin group memberships are granted.

.DESCRIPTION
    Run it BEFORE and AFTER moving to Privileged Identity Management (PIM):
      - Before: every admin role shows as "Assigned" (standing access) with no end date.
      - After : admins show as "Eligible" and only become "Activated" for a limited time.

    Sections:
      1. Active directory role assignments (permanent or activated), direct or through a group
      2. Eligible directory role assignments (PIM for Entra roles)
      3. Membership of the admin role groups (SG-ADM-*) and of the CA exclusion group:
         active vs eligible (PIM for Groups)

.NOTES
    Required Graph scopes: RoleManagement.Read.Directory, Group.Read.All, User.Read.All,
                           PrivilegedAccess.Read.AzureADGroup
    Requires Entra ID P2 for PIM data.
    Author: Javier Coliqueo — IAM365 lab
#>

Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Group.Read.All","User.Read.All","PrivilegedAccess.Read.AzureADGroup" -NoWelcome

# --- helpers ---------------------------------------------------------------
$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }

$nameCache = @{}
function Get-PrincipalName([string]$id) {
    if (-not $nameCache.ContainsKey($id)) {
        $o = Get-MgDirectoryObject -DirectoryObjectId $id -ErrorAction SilentlyContinue
        $p = $o.AdditionalProperties
        $nameCache[$id] = if ($p.userPrincipalName) { $p.userPrincipalName } else { $p.displayName }
    }
    $nameCache[$id]
}
function Format-End($dt) { if ($dt) { ([datetime]$dt).ToString('yyyy-MM-dd HH:mm') } else { 'Permanent' } }

# --- 1. Active role assignments -------------------------------------------
Write-Host "`n1. ACTIVE directory role assignments" -ForegroundColor Cyan
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All | ForEach-Object {
    [pscustomobject]@{
        Role       = $roleNames[$_.RoleDefinitionId]
        Principal  = Get-PrincipalName $_.PrincipalId
        Type       = $_.AssignmentType     # Assigned = standing access, Activated = PIM activation
        Via        = $_.MemberType         # Direct or Group
        Ends       = Format-End $_.EndDateTime
    }
} | Sort-Object Role, Principal | Format-Table -AutoSize

# --- 2. Eligible role assignments -----------------------------------------
Write-Host "2. ELIGIBLE directory role assignments (PIM)" -ForegroundColor Cyan
$elig = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All | ForEach-Object {
    [pscustomobject]@{
        Role      = $roleNames[$_.RoleDefinitionId]
        Principal = Get-PrincipalName $_.PrincipalId
        Via       = $_.MemberType
        Ends      = Format-End $_.EndDateTime
    }
}
if ($elig) { $elig | Sort-Object Role, Principal | Format-Table -AutoSize } else { Write-Host "  (none)`n" }

# --- 3. Admin and exclusion group membership: active vs eligible ----------
Write-Host "3. GROUP membership: active vs eligible (PIM for Groups)" -ForegroundColor Cyan
$groups = @(Get-MgGroup -Filter "startswith(displayName,'SG-ADM-')" -All) +
          @(Get-MgGroup -Filter "displayName eq 'SG-CA-EXCLUSIONS'")

$rows = foreach ($g in $groups) {
    $active   = @()
    $eligible = @()
    try {
        $active   = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance  -Filter "groupId eq '$($g.Id)'" -All -ErrorAction Stop |
                    Where-Object AccessId -eq 'member'
        $eligible = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "groupId eq '$($g.Id)'" -All -ErrorAction Stop |
                    Where-Object AccessId -eq 'member'
    } catch { }

    if ($active -or $eligible) {
        foreach ($a in $active)   { [pscustomobject]@{ Group = $g.DisplayName; Member = Get-PrincipalName $a.PrincipalId; Membership = "Active ($($a.AssignmentType))"; Ends = Format-End $a.EndDateTime } }
        foreach ($e in $eligible) { [pscustomobject]@{ Group = $g.DisplayName; Member = Get-PrincipalName $e.PrincipalId; Membership = 'Eligible'; Ends = Format-End $e.EndDateTime } }
    } else {
        # Group not managed by PIM yet: list plain members (standing membership)
        $members = Get-MgGroupMember -GroupId $g.Id -All
        if (-not $members) { [pscustomobject]@{ Group = $g.DisplayName; Member = '(no members)'; Membership = '-'; Ends = '-' } }
        foreach ($m in $members) { [pscustomobject]@{ Group = $g.DisplayName; Member = Get-PrincipalName $m.Id; Membership = 'Active (not in PIM)'; Ends = 'Permanent' } }
    }
}
$rows | Sort-Object Group, Member | Format-Table -AutoSize
