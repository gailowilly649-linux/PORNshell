# Cloud IAM & Container Hardening Matrix

## 1. Top AWS IAM Escalation Paths

| Permission Combination | Escalation Vector |
|---|---|
| `iam:PassRole` + `ec2:RunInstances` | Launch an EC2 instance with an attached administrative role; extract credentials from IMDS. |
| `iam:CreatePolicyVersion` | Create a new default policy version with `Action: *` and `Resource: *`. |
| `iam:SetDefaultPolicyVersion` | Revert policy to an older inactive version that possessed elevated privileges. |
| `iam:AttachUserPolicy` / `iam:AttachRolePolicy` | Attach `AdministratorAccess` policy to caller's own identity. |
| `lambda:CreateFunction` + `iam:PassRole` | Create a Lambda function with an admin role to execute arbitrary privilege-granting logic. |

## 2. Container Security Context Red Flags

| Manifest Setting | Threat / Exploit Mechanism |
|---|---|
| `privileged: true` | Grants full root capabilities on host; allows breaking out via cgroups or raw disk access. |
| `volumeMounts: /var/run/docker.sock` | Container can command host Docker daemon to spin up privileged container with root mount. |
| `hostPID: true` | Allows reading host process memory, debugging host binaries, and namespace traversal. |
| `hostNetwork: true` | Sniff host network traffic and bypass localhost-only bind boundaries. |
| `runAsUser: 0` / No `readOnlyRootFilesystem` | Root user inside container with mutable rootfs allows dropping persistence or malware. |

