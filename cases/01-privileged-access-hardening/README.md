# Case 01 — Privileged Access Hardening in Microsoft Entra ID

> **Environment:** IAM365 lab tenant (Microsoft Entra ID P2) · **Period:** June – November 2026
> **My role:** sole administrator and auditor of the tenant
> **Tools:** Entra admin center, Conditional Access, Authentication methods, What If, sign-in logs, Microsoft Graph PowerShell

---

## TL;DR

I built the privileged-access controls of an Entra ID tenant, then audited them as if they were someone else's, to check that they actually did what I thought they did.

The audit showed that **a temporary exception I created during the build phase had outlived its purpose**: an MFA exclusion meant to prevent admin lockout while testing Conditional Access was never removed. It also found a stale admin account that was still enabled and admin accounts protected only by a password. And while admins were required to use MFA, nothing required it to be phishing-resistant.

I logged **14 findings**. **8 are remediated** with before/after evidence, **1 is partially mitigated**, and the rest are documented with a recommendation or an explicit risk decision. I then deployed phishing-resistant MFA for every admin role, tested in Report-only first and then enforced.

| Outcome | Before | After |
|---|---|---|
| MFA enforced on the primary Global Admin | ❌ Excluded (single-factor sign-ins in logs) | ✅ Enforced (multi-factor in every sign-in) |
| Phishing-resistant MFA required for admin roles | ❌ Any MFA accepted (push / OTP) | ✅ Passkeys only (FIDO2 / device-bound) |
| Break glass outside every Conditional Access policy | ❌ Included in 1 policy | ✅ 0 policies apply (What If) |
| Stale admin account | ❌ Enabled, licensed, 135 days unused | ✅ Disabled, sessions revoked, license removed |
| Strong authentication methods on the primary admin | 1 security key | 2 device-bound passkeys + recovery path |

---

## 1. Risk

Privileged accounts are the shortest path to full tenant compromise. If an attacker controls a Global Administrator, they control every identity, application and policy in the tenant.

The controls that matter most are:

- **Strong authentication on every admin account, with no exceptions.** Push notifications and one-time codes can be phished; passkeys (FIDO2) cannot.
- **An emergency-access account that still works when everything else fails,** and that no policy change can lock out.
- **No standing access that nobody uses.** Stale admin accounts are an attack surface with no business value.

The question for this case was: *do my controls actually do what I think they do?*

---

## 2. Environment

| Component | Configuration |
|---|---|
| Licensing | Entra ID P2 |
| Admin model | Role-assignable groups (RBAC), one group per role |
| Emergency access | 1 cloud-only break glass account (BG01), permanent Global Admin, FIDO2 security key |
| Exclusion group | `SG-CA-EXCLUSIONS`, contains only BG01 |
| Admin accounts | 1 primary admin + 3 delegated admins (Helpdesk, Security) |

**Role matrix (verified with Graph):**

| Group | Entra role |
|---|---|
| SG-ADM-GLOBAL | Global Administrator |
| SG-ADM-IDENTITY | User Administrator |
| SG-ADM-HELPDESK | Helpdesk Administrator |
| SG-ADM-SECURITY | Security Administrator |
| SG-ADM-GRC | Identity Governance Administrator |

---

## 3. What I built

**Conditional Access baseline (final state):**

| Policy | Target | Control | State |
|---|---|---|---|
| CA-Block-Legacy-Authentication | All users (excl. BG01) | Block legacy protocols | On |
| CA-AllUsers-Require-MFA | All users (excl. SG-CA-EXCLUSIONS) | Require MFA | On |
| CA-Admin-Session-12h | Admin directory roles (excl. SG-CA-EXCLUSIONS) | Sign-in frequency 12 h | On |
| **CA-Admins-Require-PhishingResistantMFA** | All admin directory roles (excl. SG-CA-EXCLUSIONS) | **Authentication strength: Phishing-resistant MFA** | **On** |

**Passkey (FIDO2) profile:**
- Device-bound passkeys only (synced passkeys rejected)
- Attestation enforced
- AAGUID allow-list: YubiKey 5 Series NFC and Microsoft Authenticator (iOS)

**Validation tooling:** What If simulations, sign-in log analysis (portal JSON export and Graph `beta/auditLogs/signIns`), and Graph PowerShell scripts that cross-check role assignments against policy scope. See [Scripts](#10-scripts).

---

## 4. What I found

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Build-phase MFA exclusion for the primary Global Admin never removed | **High** | ✅ Remediated |
| 2 | Previous admin account still enabled and licensed after 135 days without use | Medium | ✅ Remediated |
| 3 | Break glass and primary admin depended on the same single FIDO2 key | High | 🟡 Partially mitigated |
| 4 | Privileged roles assigned permanently (no PIM / just-in-time) | High | ⬜ Open (planned) |
| 5 | Dynamic groups based on editable attributes include admin accounts, and a "privileged" group is driven by job title rather than actual roles | Medium | ⬜ Open |
| 6 | Guest account with no current business purpose | Low | ⚪ Risk accepted (billing dependency) |
| 7 | No phishing-resistant MFA requirement for admin roles | **High** | ✅ Remediated |
| 8 | Break glass included in a Conditional Access policy | Medium | ✅ Remediated |
| 9 | 5 admin-named accounts with password only and no MFA registered (3 with delegated roles, 2 with no role and no sign-in since creation) | **High** | ✅ Contained: accounts disabled until onboarding with a Temporary Access Pass |
| 10 | Primary admin held Global Admin plus a redundant User Admin role | Low | ✅ Remediated |
| 13 | Registering a new credential is protected only by standard MFA, or by nothing at all on a password-only account | **High** | ⬜ Open (recommendation below) |
| 14 | Primary admin had no password-recovery path (SSPR) | Medium | ✅ Remediated |
| — | Two legacy CA policies: one redundant and misnamed (targeted an Audit group), one test policy | Low | ✅ Retired |

*Findings 11 and 12 are process lessons, covered in [What I'd do differently](#7-what-id-do-differently).*

### Finding 1: A temporary exception that became permanent

While building and testing the Conditional Access baseline, I deliberately added the primary admin account to `SG-CA-EXCLUSIONS`. That way a misconfigured policy could not lock me out during testing. This is common practice during a rollout, **but the exception had no end date and no owner review, so it was never removed**.

When the baseline moved to **On (19 June 2026)**, the exclusion stayed in place. The account with the most privileges ended up as the only user, apart from the break glass, not covered by the Require-MFA policy. The audit caught it in November.

**Why it matters:** in real environments, "temporary" exclusions are one of the most common ways Conditional Access gets silently weakened. The fix was trivial. The lesson is the process: every exception needs a reason, an owner and an expiry date. Exclusion groups also need periodic review, for example with an Access Review on the exclusion group.

The sign-in logs of 6 November show the before and after on the same day:

| Period (UTC) | Sign-ins | Require-MFA result | Authentication requirement |
|---|---|---|---|
| 14:16 – 19:20 (excluded) | 8 | `notApplied` | `singleFactorAuthentication` |
| 19:49 onwards (remediated) | 33 | `success` | `multiFactorAuthentication` |

> **Honest note:** during the exclusion window the account was in practice used with a passkey. The finding is that **the control was missing**, so a password alone would have been enough. It is not that weak authentication was observed.

### Finding 7: "Require MFA" was not enough for admins

"Require multifactor authentication" is satisfied by any MFA method, including push notifications, which can be relayed or approved through fatigue attacks. I created `CA-Admins-Require-PhishingResistantMFA` from Microsoft's template. While validating it I found that the template:

- **excluded the current user (me) by default**, which would have recreated Finding 1, and
- **did not include Identity Governance Administrator**, the role of one of my admin groups.

I corrected both and verified with a Graph script that every role assigned through `SG-ADM-*` is in the policy scope (see [Scripts](#10-scripts)).

### Finding 9: Admins with password only

Three delegated admin accounts (Helpdesk, Security) had only a password and no MFA registered, even though a Require-MFA policy was On. **Whoever knows the password can register their own MFA at the first sign-in.**

A wider sweep found **two more "ADM" accounts in the same state, but with no Entra role at all and no sign-in since they were created**. Because they hold no directory role, the admin-focused policies did not even apply to them. They were still members of operational groups and of a group named `DG-PRIVILEGED`.

My first assumption was that the new phishing-resistant policy would leave these accounts "blocked by design". **Testing showed that this was wrong.** The policy raises the bar to *use* the account, but not to *register* its first credentials. Someone with only the password can register Authenticator, then use that fresh MFA to create a passkey, and end up holding a phishing-resistant credential for an admin account (see Finding 13).

**Containment:** all five accounts are **disabled**. A disabled account cannot sign in or register anything. If they are needed again, they will be re-enabled through a **Temporary Access Pass** issued by an administrator, so the password is never the entry point for credential registration.

### Finding 13: Strong credentials can be bootstrapped from weak ones

While testing the block on a delegated admin, Entra asked for standard MFA (password + Authenticator push) and then **offered to create a passkey**. Anyone holding those weaker credentials could have registered a phishing-resistant credential for that admin. On a password-only account the chain is even shorter: password → register Authenticator → register a passkey. The registration attempt failed, and I confirmed with Graph that no passkey was created.

This is why the severity is High. **A strong authentication policy is only as strong as the process that issues the strong credentials.**

**Recommendation:** a Conditional Access policy on the *Register security information* user action that requires a trusted location and/or a **Temporary Access Pass** issued by an administrator.

### Finding 5: A "privileged" group that doesn't track privilege

`DG-PRIVILEGED` is a dynamic group with the rule `user.jobTitle -contains "Privileged"`. That has two consequences:

- **Membership ≠ privilege.** The group contained accounts with no admin role at all, and nothing guarantees that it includes everyone who actually holds one. Any control or report scoped to this group would target the wrong population.
- **Membership is controlled by an editable text field.** Anyone who can change a user's job title, whether a User Administrator or an HR sync, decides who is "privileged".

**Recommendation:** scope privileged controls by **directory roles** or by **role-assignable groups**, as the phishing-resistant policy does. Microsoft does not allow role-assignable groups to use dynamic membership, precisely so that an attribute change can never grant a privileged role. Keep `DG-*` groups for non-privileged purposes and exclude admin accounts from attribute-based rules.

### Finding 2: Disabled ≠ no access

The previous admin account was disabled, its sessions revoked and its P2 license removed. After disabling it, the account **remained a member of an attribute-based dynamic group** (`usageLocation = CL`). Disabling an account does not remove its group memberships. That matters for any access granted through those groups. (Related to Finding 5.)

---

## 5. Testing

The new policy was deployed in **Report-only**, validated, and then switched to **On** with a second admin session open as a fallback.

| Test | Account | Method | Report-only result | Enforced (On) |
|---|---|---|---|---|
| Positive 1 | Primary admin | YubiKey (FIDO2) | `reportOnlySuccess` | ✅ Access granted |
| Positive 2 | Primary admin | Passkey in Microsoft Authenticator (device-bound) | `reportOnlySuccess` | ✅ Access granted |
| Negative | Delegated admin (Helpdesk) | Password + Authenticator push | `reportOnlyInterrupted` | Azure Portal: `failure` (blocked). ⚠️ But the security-info registration flow was still reachable and offered a passkey (Finding 13) → account disabled |
| Exclusion | Break glass (BG01) | FIDO2 | Not applied (What If: 0 policies) | ✅ Access granted |
| Passkey profile | Primary admin | Synced passkey (iCloud Keychain) | — | ⛔ Rejected: "passkey does not meet the criteria set by your administrator" |

---

## 6. Recommendations

**Done:**
- Removed the primary admin from the exclusion group (F1)
- Disabled the stale admin account, revoked its sessions and removed its license (F2)
- Added a second device-bound passkey for the primary admin, registered in Microsoft Authenticator (F3, partial)
- Enforced phishing-resistant MFA for every admin role (F7)
- Excluded the break glass from all CA policies (F8)
- Disabled the 5 password-only admin-named accounts until TAP-based onboarding (F9)
- Removed the redundant User Admin role (F10)
- Enabled a password-recovery path for the primary admin (F14)
- Retired two legacy CA policies

**Next:**
1. **Second break glass account (BG02)** with its own credential, to remove the single-key dependency (F3)
2. **Alert on any break glass sign-in.** Being excluded from every CA policy only works if its use is monitored.
3. **PIM** for just-in-time activation of privileged roles (F4)
4. **Conditional Access on credential registration** with a Temporary Access Pass (F13)
5. **Redesign `DG-PRIVILEGED`**, or retire it, and exclude admin accounts from attribute-based dynamic groups (F5)

---

## 7. What I'd do differently

- **Give every exception an expiry date from day one.** The build-phase exclusion should have been time-boxed and tied to the go-live of the baseline, with an Access Review on the exclusion group.
- **Always review exclusions after creating a policy from a template.** Microsoft's template excluded the creating admin by default. The sign-in logs show the new policy as `reportOnlyNotApplied` for my account until I fixed it.
- **Never let the break glass and a daily admin share a single authenticator.** Losing that one key would have locked out both accounts.
- **Check the scope of exclusion groups regularly.** An exclusion group is a list of accounts that skip controls; it should be as small and as monitored as possible.
- **Test the assumption, not just the policy.** I expected the new policy to block the password-only admins, but the test showed they could still bootstrap a passkey. Enforcing strong authentication and controlling how strong credentials are issued are two separate controls.
- **Plan for log latency.** Sign-in logs sometimes took much longer than expected to appear, and the Graph API timed out on filtered queries. Validate with *What If* before a change, confirm with the logs after, and send logs to Log Analytics or a SIEM for real-time troubleshooting and alerting.

---

## 8. Control mapping

| Control area | ITGC | ISO/IEC 27001:2022 (Annex A) | NIST SP 800-53 Rev. 5 |
|---|---|---|---|
| Privileged access restricted and reviewed | Logical access: privileged users | 8.2 Privileged access rights | AC-2, AC-6 |
| Strong authentication for admins | Logical access: authentication | 8.5 Secure authentication | IA-2(1), IA-2(2) |
| Credential lifecycle (registration, recovery) | Logical access: password / credential management | 5.17 Authentication information | IA-5 |
| Timely removal of unused access | Logical access: user termination | 5.18 Access rights | AC-2(3) |
| Identity management and least privilege | Logical access: provisioning | 5.15 Access control, 5.16 Identity management | AC-2, AC-6(5) |
| Logging and monitoring of privileged use | Monitoring of privileged activity | 8.15 Logging, 8.16 Monitoring activities | AU-6, AC-2(4) |

---

## 9. Evidence

| Artifact | Shows |
|---|---|
| `evidence/signins-before-after.csv` | Finding 1: single-factor sign-ins before and multi-factor after (sanitized) |
| `evidence/whatif-breakglass-before-after.png` | Finding 8: 1 policy → 0 policies |
| `evidence/ca-policy-phishing-resistant.png` | Final scope and grant control of the new policy |
| `evidence/report-only-results.png` | Positive and negative test results |
| `evidence/passkey-profile.png` | Device-bound, attestation and AAGUID allow-list |
| `evidence/synced-passkey-rejected.png` | Profile rejecting a synced passkey |
| `evidence/register-passkey-offer.png` | Finding 13: passkey registration offered after standard MFA |
| `evidence/stale-admin-offboarding.png` | Finding 2: disabled, sessions revoked, license removed |

*All screenshots are sanitized: no tenant IDs, object IDs, break glass UPN or personal email addresses.*

---

## 10. Scripts

Full, documented versions in [`/scripts`](../../scripts):

| Script | Purpose |
|---|---|
| [`Check-AdminAuthMethods.ps1`](../../scripts/Check-AdminAuthMethods.ps1) | Which admins have a phishing-resistant method (who would be locked out) |
| [`Test-AdminPolicyCoverage.ps1`](../../scripts/Test-AdminPolicyCoverage.ps1) | Role matrix, policy coverage of every admin role, and policy exclusions |
| [`Get-CAPolicyResults.ps1`](../../scripts/Get-CAPolicyResults.ps1) | Result of a CA policy (On or Report-only) per sign-in, with the method used |

Core logic:

**Cross-check: are all roles assigned to admin groups covered by the policy?**

```powershell
Connect-MgGraph -Scopes "Group.Read.All","RoleManagement.Read.Directory","Policy.Read.All" -NoWelcome

$groups = Get-MgGroup -Filter "startswith(displayName,'SG-ADM-')" -All
$assignments = foreach ($g in $groups) {
  foreach ($a in Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($g.Id)'" -All) {
    $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId
    [pscustomobject]@{ Group = $g.DisplayName; Role = $rd.DisplayName; RoleTemplateId = $rd.TemplateId }
  }
}

$policy = Get-MgIdentityConditionalAccessPolicy -All |
  Where-Object DisplayName -eq 'CA-Admins-Require-PhishingResistantMFA'

# Roles assigned to admin groups but NOT covered by the policy (expected: empty)
$assignments | Where-Object { $_.RoleTemplateId -notin $policy.Conditions.Users.IncludeRoles }
```

**Which admins would be locked out? (phishing-resistant method check)**

```powershell
Connect-MgGraph -Scopes "Group.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome

$pr = 'fido2AuthenticationMethod','windowsHelloForBusinessAuthenticationMethod','x509CertificateAuthenticationMethod'
foreach ($g in Get-MgGroup -Filter "startswith(displayName,'SG-ADM-')" -All) {
  foreach ($m in Get-MgGroupMember -GroupId $g.Id -All) {
    $types = (Get-MgUserAuthenticationMethod -UserId $m.Id).AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
    [pscustomobject]@{
      Group             = $g.DisplayName
      User              = (Get-MgUser -UserId $m.Id).UserPrincipalName
      PhishingResistant = [bool]($types | Where-Object { $_ -in $pr })
    }
  }
}
```

**Report-only results per sign-in (no portal needed)**

```powershell
$r = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=50'
$r.value | ForEach-Object {
  $p = $_.appliedConditionalAccessPolicies | Where-Object displayName -eq 'CA-Admins-Require-PhishingResistantMFA'
  [pscustomobject]@{
    TimeUTC = $_.createdDateTime
    User    = $_.userPrincipalName
    Method  = ($_.authenticationDetails | Where-Object succeeded | ForEach-Object authenticationMethod | Select-Object -Unique) -join ', '
    Result  = $p.result
  }
} | Format-Table -AutoSize
```

---

*Lab notes with step-by-step configuration (P-001 to P-008) are available in [`/lab-notes`](../../lab-notes).*
