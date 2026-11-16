<#
.SYNOPSIS
    Lists the members of the admin role groups (SG-ADM-*) and whether each one
    has a phishing-resistant authentication method registered.

.DESCRIPTION
    Use it before enforcing a Conditional Access policy that requires the
    "Phishing-resistant MFA" authentication strength: any admin with
    PhishingResistant = False would be blocked, or sent to register a method.

    Phishing-resistant methods counted: FIDO2 / passkeys, Windows Hello for
    Business, and certificate-based authentication (x509).

.NOTES
    Required Graph scopes: Group.Read.All, User.Read.All, UserAuthenticationMethod.Read.All
    Author: Javier Coliqueo — IAM365 lab
#>

Connect-MgGraph -Scopes "Group.Read.All","User.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome

# Method types that satisfy the "Phishing-resistant MFA" authentication strength
$phishingResistant = @(
    'fido2AuthenticationMethod',
    'windowsHelloForBusinessAuthenticationMethod',
    'x509CertificateAuthenticationMethod'
)

$groups = Get-MgGroup -Filter "startswith(displayName,'SG-ADM-')" -All

$result = foreach ($g in $groups) {
    foreach ($m in Get-MgGroupMember -GroupId $g.Id -All) {
        $u = Get-MgUser -UserId $m.Id -Property UserPrincipalName,AccountEnabled

        $methods = (Get-MgUserAuthenticationMethod -UserId $m.Id).AdditionalProperties.'@odata.type' `
                    -replace '#microsoft.graph.',''

        [pscustomobject]@{
            Group             = $g.DisplayName
            User              = $u.UserPrincipalName
            Enabled           = $u.AccountEnabled
            PhishingResistant = [bool]($methods | Where-Object { $_ -in $phishingResistant })
            Methods           = ($methods -join ', ')
        }
    }
}

# Show on screen
$result | Sort-Object Group, User | Format-Table -AutoSize

# Summary: enabled admins that would be blocked by the phishing-resistant policy
$atRisk = $result | Where-Object { $_.Enabled -and -not $_.PhishingResistant }
if ($atRisk) {
    Write-Warning "$(@($atRisk).Count) enabled admin(s) without a phishing-resistant method:"
    $atRisk | Format-Table Group, User -AutoSize
} else {
    Write-Host "All enabled admins have a phishing-resistant method." -ForegroundColor Green
}

# Optional: export as evidence
# $result | Export-Csv "$HOME\Documents\admin-auth-methods.csv" -NoTypeInformation -Encoding utf8
