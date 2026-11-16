<#
.SYNOPSIS
    Shows the result of a Conditional Access policy (On or Report-only) for the
    most recent sign-ins, with the authentication method used.

.DESCRIPTION
    Useful to validate a policy without opening each sign-in in the portal:
      - reportOnlySuccess / success          -> the method satisfied the policy
      - reportOnlyInterrupted / failure      -> the policy would block or did block
      - reportOnlyNotApplied / notApplied    -> the user was out of scope (check exclusions)

    Uses the beta endpoint because it returns authenticationDetails.
    In some tenants, filtering sign-ins server-side times out, so this script
    retrieves the latest N sign-ins and filters locally.

    Sign-in logs can take minutes (sometimes much longer) to appear.

.PARAMETER PolicyName
    Display name of the Conditional Access policy.

.PARAMETER User
    Optional UPN filter. Accepts several values.

.PARAMETER Top
    Number of most recent sign-ins to retrieve (default 50). Lower it if the request times out.

.NOTES
    Required Graph scope: AuditLog.Read.All
    Author: Javier Coliqueo — IAM365 lab
#>

param(
    [string]$PolicyName = 'CA-Admins-Require-PhishingResistantMFA',
    [string[]]$User,
    [int]$Top = 50
)

Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome

$r = $null
$r = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$top=$Top"
if (-not $r) { throw "No response from Graph (timeout?). Try a lower -Top value." }

$signIns = $r.value
if ($User) { $signIns = $signIns | Where-Object { $_.userPrincipalName -in $User } }

$signIns | ForEach-Object {
    $p = $_.appliedConditionalAccessPolicies | Where-Object { $_.displayName -eq $PolicyName }
    [pscustomobject]@{
        TimeUTC = $_.createdDateTime
        User    = $_.userPrincipalName
        App     = $_.appDisplayName
        Method  = ($_.authenticationDetails | Where-Object succeeded |
                   ForEach-Object authenticationMethod | Select-Object -Unique) -join ', '
        Result  = $p.result
        Error   = $_.status.errorCode
    }
} | Format-Table -AutoSize
