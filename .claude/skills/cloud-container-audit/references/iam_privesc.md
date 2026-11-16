# IAM Misconfiguration and Privilege Escalation (CC-009)

Bug bounty rule: a leaked cloud key is a finding by itself. Do **not** use it unless the program explicitly allows key validation, and then only with a single read-only identity call.

## When a key is found in scope

1. Record where it was found (URL, file, commit), key type, and a redacted prefix (`AKIA****WXYZ`, `AIza****`, SAS `sig=****`).
2. If the program allows validation, one read-only identity call only:
   - AWS: `aws sts get-caller-identity` (does not need any IAM permission)
   - GCP: `gcloud auth activate-service-account --key-file k.json && gcloud auth list` (no resource calls)
   - Azure: `az login --service-principal ...` then `az account show`
3. Do not enumerate permissions, list resources, or call any other API. Report account ID/principal (redacted) and recommend immediate rotation.

## Configuration review (only when the owner provides read access or config files)

### AWS privilege-escalation permissions to flag

| Permission(s) | Why it escalates |
|---|---|
| `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` | Rewrite own policy to admin |
| `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy`, `iam:AttachGroupPolicy`, `iam:PutGroupPolicy` | Grant self admin |
| `iam:CreateAccessKey` on other users | Act as another user |
| `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` | Console access as another user |
| `iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction` + `lambda:InvokeFunction` / `glue:CreateDevEndpoint` / `cloudformation:CreateStack` / `ecs:RunTask` | Run code as a more privileged role |
| `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Trust self in an admin role |
| `lambda:UpdateFunctionCode` on a privileged function | Run code as its role |
| `ssm:SendCommand`, `ssm:StartSession` on privileged instances | Run code on instances |
| `*` on `*`, `iam:*`, `sts:AssumeRole` on `*` | Effectively admin |
| Trust policy `Principal: {"AWS": "*"}` without conditions | Anyone can assume the role |

### GCP

`iam.serviceAccounts.actAs`, `iam.serviceAccountKeys.create`, `iam.serviceAccounts.getAccessToken`, `resourcemanager.projects.setIamPolicy`, `deploymentmanager.deployments.create`, `cloudfunctions.functions.create` + actAs, `compute.instances.setMetadata` (SSH keys), primitive `roles/owner`/`roles/editor` on broad scopes, `allUsers`/`allAuthenticatedUsers` bindings.

### Azure

`Microsoft.Authorization/roleAssignments/write`, Owner/User Access Administrator at subscription scope, `Microsoft.Compute/virtualMachines/runCommand/action`, Automation account runbooks with privileged identities, managed identities with Contributor on subscriptions, app registrations with `RoleManagement.ReadWrite.Directory` or `Application.ReadWrite.All`.

## Tools (owner-approved configuration reviews only)

- AWS: Prowler, ScoutSuite, PMapper, Cloudsplaining, `aws iam simulate-principal-policy`
- GCP: ScoutSuite, Prowler GCP, `gcloud asset analyze-iam-policy`
- Azure: ScoutSuite, Prowler Azure, AzureHound (with approval)
- Kubernetes: kube-bench, kube-hunter (passive mode), `kubectl auth can-i --list` (own credentials)
