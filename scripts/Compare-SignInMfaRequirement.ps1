<#
.SYNOPSIS
    Before/after view of a Conditional Access MFA control for one account:
    for every interactive sign-in, the authentication requirement and the
    result of a given Conditional Access policy.

.DESCRIPTION
    Used in the IAM365 lab to prove Finding 1: while the primary admin was in the
    exclusion group, "CA-AllUsers-Require-MFA" was notApplied and sign-ins were
    singleFactorAuthentication; after the exclusion was removed, the policy result
    was success and sign-ins were multiFactorAuthentication.

    Data source (choose one):
      -JsonPath  : sign-ins exported from the portal (Sign-in logs > Download > JSON).
                   Best for older data and for tenants where the API times out.
      (default)  : latest sign-ins from Microsoft Graph (beta endpoint), filtered locally.

    -ChangeTimeUtc labels each sign-in as "before" or "after" a change (e.g. the time
    the exclusion was removed). -Anonymize replaces the UPN with a label, for evidence.

.EXAMPLE
    .\Compare-SignInMfaRequirement.ps1 -UserPrincipalName adm-javier.coliqueo@iam365.cl `
        -JsonPath .\InteractiveSignIns.json -ChangeTimeUtc '2026-11-06T19:30:00Z' `
        -ExportCsv .\signins-before-after.csv -Anonymize 'primary-admin'

.NOTES
    Required Graph scope (Graph mode only): AuditLog.Read.All
    Author: Javier Coliqueo — IAM365 lab
#>

param(
    [Parameter(Mandatory)] [string]$UserPrincipalName,
    [string]$PolicyName = 'CA-AllUsers-Require-MFA',
    [string]$JsonPath,
    [datetime]$ChangeTimeUtc,
    [int]$Top = 200,
    [string]$ExportCsv,
    [string]$Anonymize
)

# 1) Load sign-ins
if ($JsonPath) {
    $raw = Get-Content -Path $JsonPath -Raw -Encoding utf8 | ConvertFrom-Json
    # The portal export is a plain array; a Graph response wraps it in "value".
    # (Do not test $raw.value on an array: PowerShell member enumeration returns
    #  an array of nulls, which is "truthy".)
    $signIns = if ($raw -isnot [array] -and $raw.PSObject.Properties['value']) { $raw.value } else { $raw }
} else {
    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
    $r = $null
    $r = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$top=$Top" -OutputType PSObject
    if (-not $r) { throw "No response from Graph (timeout?). Try a lower -Top or use -JsonPath." }
    $signIns = $r.value
}

$signIns = $signIns | Where-Object { $_.userPrincipalName -eq $UserPrincipalName }
if (-not $signIns) { Write-Warning "No sign-ins found for $UserPrincipalName."; return }

# 2) Build rows
$rows = foreach ($s in ($signIns | Sort-Object createdDateTime)) {
    $p    = $s.appliedConditionalAccessPolicies | Where-Object { $_.displayName -eq $PolicyName }
    $time = ([datetime]$s.createdDateTime).ToUniversalTime()
    [pscustomobject]@{
        TimeUTC     = $time.ToString('yyyy-MM-dd HH:mm:ss')
        Account     = if ($Anonymize) { $Anonymize } else { $s.userPrincipalName }
        App         = $s.appDisplayName
        Requirement = $s.authenticationRequirement
        PolicyResult= if ($p) { $p.result } else { '(not evaluated)' }
        Methods     = (($s.authenticationDetails | Where-Object succeeded | ForEach-Object authenticationMethod | Select-Object -Unique) -join ', ')
        ErrorCode   = $s.status.errorCode
        Period      = if ($ChangeTimeUtc) { if ($time -lt $ChangeTimeUtc.ToUniversalTime()) { 'before' } else { 'after' } } else { '' }
    }
}

# 3) Output
$rows | Format-Table TimeUTC, App, Requirement, PolicyResult, Methods, Period -AutoSize | Out-Host

Write-Host "Summary ($PolicyName):" -ForegroundColor Cyan
$rows | Group-Object Period, PolicyResult, Requirement | Sort-Object Name |
    Select-Object Count, @{n='Period / PolicyResult / Requirement'; e={ $_.Name }} | Format-Table -AutoSize

if ($ExportCsv) {
    $rows | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding utf8
    Write-Host "Exported to $ExportCsv" -ForegroundColor Green
}
