# IAM Portfolio: Javier Coliqueo Vejar

**IAM / IGA / PAM Engineer** · Santiago, Chile · [LinkedIn](https://www.linkedin.com/in/javier-coliqueo-vejar-b1709355) · [jcoliqueo@gmail.com](mailto:jcoliqueo@gmail.com)

Hands-on **Identity & Access Management** work, documented as case studies. Each case starts from a real risk in my own Microsoft Entra ID lab tenant (**IAM365**), shows what I built and what I found when I audited it, and backs every result with evidence and scripts you can run.

I have 15+ years in identity and infrastructure at a global organization. I managed the Joiner-Mover-Leaver lifecycle for LATAM (~5,000 users) inside a hybrid Active Directory + Entra ID environment of ~50,000 identities, ran access review and certification campaigns, controlled privileged, service and third-party accounts, and prepared ISO/IEC 27001, ITGC and NIST evidence for external auditors. I have also designed the role and access matrix for a regulated financial-sector company. This portfolio shows that kind of work in a form you can check.

**Certifications:** Microsoft SC-300 (Identity and Access Administrator) · AZ-104 · SC-900 · AZ-900 · SailPoint Identity University: Introduction to Identity Security Cloud

---

## Start here

👉 **[Case 01: Privileged Access Hardening in Microsoft Entra ID](cases/01-privileged-access-hardening/README.md)**

I built the IAM365 tenant while preparing for SC-300. Months later I came back to it as if I had **inherited it** and audited how it protected its most powerful accounts. Shortcuts from the study phase had outlived their purpose: an MFA exclusion on the primary Global Admin that was never removed, test admin accounts still enabled with only a password, every admin role assigned permanently, and no requirement for phishing-resistant MFA.

I logged **13 findings (6 high)**. The fix moved every admin to **just-in-time access through PIM**, where activating a role always requires a passkey, and put Conditional Access exceptions under time-bound, alerted, monthly-reviewed control. **9 findings are remediated or contained, 2 are risk-accepted, 2 remain open**, each with before/after evidence.

---

## Cases

| # | Case | Focus | Tools |
|---|---|---|---|
| 01 | [Privileged Access Hardening in Microsoft Entra ID](cases/01-privileged-access-hardening/README.md) | Phishing-resistant MFA, Conditional Access, PIM for Groups, access reviews, break glass, stale admin accounts | Entra ID P2, PIM, Conditional Access, Authentication strengths, YubiKey, Microsoft Graph PowerShell |
| 02 | Joiner-Mover-Leaver lifecycle *(planned)* | Provisioning, role changes, offboarding, orphaned accounts | Entra ID, Lifecycle Workflows, Microsoft Graph PowerShell |
| 03 | Access certification and SoD *(planned)* | Role model, segregation of duties, certification campaigns | Entra ID Governance, access packages, Access Reviews |
| 04 | SSO and provisioning *(planned)* | SAML 2.0, OpenID Connect, SCIM | Entra ID enterprise apps |

Reusable scripts from all cases live in [`scripts/`](scripts/).

---

## How to read these

Every case follows the same structure, so you can jump straight to what you care about:

- **Summary:** the problem, the result and a before/after table
- **Risk:** why it matters to the business
- **What I built:** the design and configuration
- **What I found:** findings ranked by severity, with status
- **Testing:** how each control was proven to work
- **Recommendations** and **What I'd do differently**
- **Control mapping:** ISO/IEC 27001:2022 Annex A, NIST SP 800-53 Rev. 5 and ITGC
- **Evidence** and **Scripts**

**Ground rules:** every claim links to evidence. The work happens in a lab tenant, never in an employer's environment. Screenshots are sanitized (tenant IDs, object IDs, break glass account and personal data removed). Findings are reported honestly, including the ones I accepted or left open.

---

## Repository layout

```
iam-portfolio/
├── cases/
│   └── 01-privileged-access-hardening/
│       ├── README.md        ← the case study
│       └── evidence/        ← sanitized screenshots and exports
├── scripts/                 ← Microsoft Graph PowerShell used in the cases
├── LICENSE
└── README.md                ← you are here
```

---

## Skills

- **IAM:** Microsoft Entra ID, Active Directory, hybrid identity, Conditional Access, MFA and passwordless (FIDO2 / passkeys), SSO (SAML 2.0, OIDC, OAuth 2.0), Zero Trust
- **IGA:** Joiner-Mover-Leaver, role and access matrix design, RBAC / ABAC, least privilege, SoD, access review and certification campaigns, orphaned-account remediation
- **PAM:** Entra PIM (just-in-time, approval, justification, expiration), privileged, service and third-party account control, break glass accounts
- **GRC:** audit evidence for ISO/IEC 27001, ITGC and NIST, control execution and reporting, Chilean Personal Data Protection Law 21.719
- **Automation:** PowerShell, Microsoft Graph API, REST APIs, SQL
- **Also exposed to:** SailPoint Identity Security Cloud, Saviynt, Okta and CyberArk (courses and labs)

**Languages:** Spanish (native) · English (professional)

---

## Contact

- LinkedIn: [javier-coliqueo-vejar](https://www.linkedin.com/in/javier-coliqueo-vejar-b1709355)
- Email: [jcoliqueo@gmail.com](mailto:jcoliqueo@gmail.com)

---

*Content is licensed under the [MIT License](LICENSE). Scripts are provided as-is for lab use; review and test them before running in any production tenant.*
