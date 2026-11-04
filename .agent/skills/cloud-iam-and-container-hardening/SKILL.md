---
name: cloud-iam-and-container-hardening
description: >-
  Use this skill when auditing AWS/GCP/Azure IAM policies, role assumption
  chains, instance metadata service (IMDS) exposure, Kubernetes RBAC, and
  container security postures.
---

# Cloud IAM, Metadata Services & Container Security Tactics

This skill covers auditing cloud infrastructure, privilege escalation paths, service account tokens, and container runtime isolation.

## Core Cloud & Container Audit Methods

### 1. Cloud IAM & Privilege Escalation Paths
* **AWS IAM Misconfigurations:**
  * Policies granting `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:PassRole` combined with `ec2:RunInstances` or `lambda:CreateFunction`.
  * Wildcard action policies (`Action: "*"`, `Resource: "*"`) attached to developer or automation roles.
* **GCP IAM & Service Account Impersonation:**
  * Roles granting `iam.serviceAccounts.actAs`, `iam.serviceAccounts.signBlob`, or `resourcemanager.projects.setIamPolicy`.
* **Azure RBAC:**
  * High-privilege role assignments (`Contributor`, `Owner`, `User Access Administrator`) on root management groups.

### 2. Instance Metadata Service (IMDS) Auditing
* **IMDSv1 vs. IMDSv2:**
  * Check if EC2 instances have `HttpTokens=optional` (IMDSv1 vulnerable to SSRF) vs `HttpTokens=required` (IMDSv2 requiring `X-aws-ec2-metadata-token`).
  * Check hop limit (`HttpPutResponseHopLimit`); if set to `1`, containerized workloads cannot access IMDS from within a container network.

### 3. Container & Kubernetes Posture
* **Linux Capabilities & Namespaces:**
  * Containers running with `privileged: true`, `CAP_SYS_ADMIN`, or shared host PID (`hostPID: true`) / network (`hostNetwork: true`) namespaces.
  * Writable host filesystem mounts (`/var/run/docker.sock`, `/run/containerd/containerd.sock`, host root `/`).
* **Kubernetes Service Account Tokens:**
  * Mounted default service account tokens (`automountServiceAccountToken: true`) with cluster-admin or broad secret read privileges.

---

## Automated Execution Steps

1. **Run Container & IAM Manifest Auditor:**
   Execute [cloud_manifest_auditor.py](./scripts/cloud_manifest_auditor.py) across Dockerfiles, Compose files, or K8s manifests:
   ```bash
   python3 .agent/skills/cloud-iam-and-container-hardening/scripts/cloud_manifest_auditor.py --target .
   ```
2. **Consult IAM & Container Reference:**
   Read [cloud-iam-container-matrix.md](./references/cloud-iam-container-matrix.md) for escalation primitives and hardening configurations.

