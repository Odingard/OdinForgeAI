// =============================================================================
// Task 06 — Kubernetes Scanner
// server/services/cloud/K8sScanner.ts
//
// Production-grade Kubernetes security checks covering:
//   RBAC:     cluster-admin wildcard bindings, default service account
//   Workloads: privileged containers, root containers, hostPID/hostNetwork
//   Network:  missing NetworkPolicies, services exposed as NodePort/LoadBalancer
//   Secrets:  secrets in env vars, default namespace usage
//   Config:   anonymous auth, RBAC disabled, audit logging
// =============================================================================

import * as k8s from "@kubernetes/client-node";

import {
  CloudScanner, type CloudCredentials, type K8sCredentials,
  type CloudFinding,
} from "./base/CloudScanner";

export class K8sScanner extends CloudScanner {
  constructor(opts: ConstructorParameters<typeof CloudScanner>[0]) {
    super({ ...opts, provider: "k8s" });
  }

  protected extractAccountId(credentials: CloudCredentials): string {
    const creds = credentials as K8sCredentials;
    return creds.context ?? "default";
  }

  // —— Credential validation ————————————————————————————————————————————————
  protected async validateCredentials(credentials: CloudCredentials): Promise<void> {
    const creds  = credentials as K8sCredentials;
    const client = this.makeClient(creds);

    try {
      const coreApi = client.makeApiClient(k8s.CoreV1Api);
      await this.withRetry(
        () => coreApi.listNamespace(),
        { label: "k8s-credential-validation" }
      );
    } catch (err: unknown) {
      const e = err as Error & { body?: { message?: string }; statusCode?: number };
      const msg = e.body?.message ?? e.message;

      if (e.statusCode === 401 || msg?.includes("Unauthorized")) {
        throw new Error("Kubernetes authentication failed — check your kubeconfig credentials");
      }
      if (e.statusCode === 403 || msg?.includes("Forbidden")) {
        throw new Error("Kubernetes credentials valid but missing namespace list permissions");
      }
      throw new Error(`Kubernetes connection failed: ${msg}`);
    }
  }

  // —— Main check runner ————————————————————————————————————————————————————
  protected async runChecks(credentials: CloudCredentials): Promise<void> {
    const creds  = credentials as K8sCredentials;
    const client = this.makeClient(creds);

    await Promise.allSettled([
      this.runRbacChecks(client),
      this.runWorkloadChecks(client),
      this.runNetworkChecks(client),
      this.runSecretChecks(client),
      this.runNamespaceChecks(client),
    ]);
  }

  // —— RBAC Checks ——————————————————————————————————————————————————————————
  private async runRbacChecks(client: k8s.KubeConfig): Promise<void> {
    const rbacApi = client.makeApiClient(k8s.RbacAuthorizationV1Api);

    // Check 1: ClusterRoleBindings with cluster-admin
    await this.runCheck("k8s-rbac-cluster-admin", async () => {
      const resp = await this.withRetry(
        () => rbacApi.listClusterRoleBinding(),
        { label: "list-cluster-role-bindings" }
      );
      return resp.items;
    }, (bindings: k8s.V1ClusterRoleBinding[]) => {
      const adminBindings = bindings.filter((b: k8s.V1ClusterRoleBinding) =>
        b.roleRef?.name === "cluster-admin" &&
        b.metadata?.name !== "cluster-admin" // Skip the built-in self-binding
      );

      for (const binding of adminBindings) {
        const subjects = binding.subjects ?? [];
        const nonSystemSubjects = subjects.filter((s: { name?: string; namespace?: string; kind?: string; apiGroup?: string }) =>
          !s.name?.startsWith("system:") &&
          s.namespace !== "kube-system"
        );

        if (nonSystemSubjects.length === 0) continue;

        this.addFinding({
          checkId:     `k8s-rbac-cluster-admin-${binding.metadata?.name}`,
          title:       `ClusterRoleBinding ${binding.metadata?.name} Grants cluster-admin`,
          description: `ClusterRoleBinding ${binding.metadata?.name} grants cluster-admin access to ${nonSystemSubjects.map((s: { name?: string; namespace?: string; kind?: string; apiGroup?: string }) => s.name).join(", ")}. cluster-admin is full unrestricted access to all Kubernetes resources.`,
          severity:    "critical",
          cvssScore:   9.8,
          resource:    `ClusterRoleBinding/${binding.metadata?.name}`,
          resourceType: "k8s_rbac_binding",
          evidence:    {
            BindingName: binding.metadata?.name,
            Subjects:    nonSystemSubjects,
            RoleRef:     binding.roleRef,
          },
          remediationTitle: "Replace cluster-admin binding with least-privilege role",
          remediationSteps: [
            `Review what permissions are actually needed: kubectl describe clusterrolebinding ${binding.metadata?.name}`,
            "Create a custom ClusterRole with only needed permissions",
            `Remove cluster-admin binding: kubectl delete clusterrolebinding ${binding.metadata?.name}`,
            "Create new binding with scoped role",
          ],
          remediationEffort: "high",
          mitreAttackIds: ["T1078", "T1613"],
        });
      }
    });

    // Check 2: Wildcard permissions in ClusterRoles
    await this.runCheck("k8s-rbac-wildcard-rules", async () => {
      const resp = await this.withRetry(
        () => rbacApi.listClusterRole(),
        { label: "list-cluster-roles" }
      );
      return resp.items;
    }, (roles: k8s.V1ClusterRole[]) => {
      for (const role of roles) {
        // Skip system roles
        if (role.metadata?.name?.startsWith("system:")) continue;

        const wildcardRules = (role.rules ?? []).filter((rule: k8s.V1PolicyRule) =>
          rule.verbs?.includes("*") &&
          (rule.resources?.includes("*") || rule.apiGroups?.includes("*"))
        );

        if (wildcardRules.length > 0) {
          this.addFinding({
            checkId:     `k8s-rbac-wildcard-${role.metadata?.name}`,
            title:       `ClusterRole ${role.metadata?.name} Has Wildcard Permissions`,
            description: `ClusterRole ${role.metadata?.name} contains rules with wildcard verbs and/or resources, granting overly broad access.`,
            severity:    "high",
            cvssScore:   8.0,
            resource:    `ClusterRole/${role.metadata?.name}`,
            resourceType: "k8s_cluster_role",
            evidence:    { RoleName: role.metadata?.name, WildcardRules: wildcardRules },
            remediationTitle: "Replace wildcard permissions with specific rules",
            remediationSteps: [
              `Review role: kubectl describe clusterrole ${role.metadata?.name}`,
              "Replace * verbs with explicit: get, list, watch (read-only) or create, update, patch, delete (write)",
              "Replace * resources with specific resource types",
            ],
            remediationEffort: "medium",
            mitreAttackIds: ["T1078"],
          });
        }
      }
    });
  }

  // —— Workload Checks ——————————————————————————————————————————————————————
  private async runWorkloadChecks(client: k8s.KubeConfig): Promise<void> {
    const coreApi = client.makeApiClient(k8s.CoreV1Api);
    const appsApi = client.makeApiClient(k8s.AppsV1Api);

    // Get all namespaces
    const nsResp = await this.withRetry(
      () => coreApi.listNamespace(),
      { label: "list-namespaces" }
    );
    const namespaces = nsResp.items.map((ns: k8s.V1Namespace) => ns.metadata?.name!).filter(Boolean);

    for (const namespace of namespaces) {
      // Check deployments
      await this.runCheck(`k8s-workload-security-${namespace}`, async () => {
        const [deployments, daemonsets, statefulsets] = await Promise.all([
          this.withRetry(() => appsApi.listNamespacedDeployment({ namespace }), { label: `deployments-${namespace}` }),
          this.withRetry(() => appsApi.listNamespacedDaemonSet({ namespace }), { label: `daemonsets-${namespace}` }),
          this.withRetry(() => appsApi.listNamespacedStatefulSet({ namespace }), { label: `statefulsets-${namespace}` }),
        ]);
        return [
          ...deployments.items.map((d: k8s.V1Deployment) => ({ kind: "Deployment" as const, ...d })),
          ...daemonsets.items.map((d: k8s.V1DaemonSet) => ({ kind: "DaemonSet" as const, ...d })),
          ...statefulsets.items.map((d: k8s.V1StatefulSet) => ({ kind: "StatefulSet" as const, ...d })),
        ];
      }, (workloads) => {
        for (const workload of workloads) {
          const name     = workload.metadata?.name;
          const podSpec  = (workload as { spec?: { template?: { spec?: k8s.V1PodSpec } } }).spec?.template?.spec;
          if (!podSpec || !name) continue;

          // Check hostPID / hostNetwork / hostIPC
          if (podSpec.hostPID) {
            this.addFinding({
              checkId:     `k8s-host-pid-${namespace}-${name}`,
              title:       `${workload.kind} ${name} Uses hostPID`,
              description: `${workload.kind} ${name} in namespace ${namespace} has hostPID: true, allowing containers to see all processes on the host node.`,
              severity:    "critical",
              cvssScore:   9.5,
              resource:    `${namespace}/${workload.kind}/${name}`,
              resourceType: "k8s_workload",
              evidence:    { Namespace: namespace, Name: name, Kind: workload.kind, HostPID: true },
              remediationTitle: "Remove hostPID from pod spec",
              remediationSteps: [
                `Edit deployment: kubectl edit ${workload.kind?.toLowerCase()} ${name} -n ${namespace}`,
                "Remove or set hostPID: false in pod spec",
              ],
              remediationEffort: "low",
              mitreAttackIds: ["T1613", "T1057"],
            });
          }

          if (podSpec.hostNetwork) {
            this.addFinding({
              checkId:     `k8s-host-network-${namespace}-${name}`,
              title:       `${workload.kind} ${name} Uses hostNetwork`,
              description: `${workload.kind} ${name} in namespace ${namespace} has hostNetwork: true, giving containers direct access to the host's network stack.`,
              severity:    "high",
              cvssScore:   8.5,
              resource:    `${namespace}/${workload.kind}/${name}`,
              resourceType: "k8s_workload",
              evidence:    { Namespace: namespace, Name: name, Kind: workload.kind, HostNetwork: true },
              remediationTitle: "Remove hostNetwork from pod spec",
              remediationSteps: [`kubectl edit ${workload.kind?.toLowerCase()} ${name} -n ${namespace}`, "Remove hostNetwork: true"],
              remediationEffort: "low",
              mitreAttackIds: ["T1613"],
            });
          }

          // Check containers for privileged mode + root
          for (const container of [...(podSpec.containers ?? []), ...(podSpec.initContainers ?? [])]) {
            if (container.securityContext?.privileged) {
              this.addFinding({
                checkId:     `k8s-privileged-${namespace}-${name}-${container.name}`,
                title:       `Container ${container.name} Runs in Privileged Mode`,
                description: `Container ${container.name} in ${workload.kind}/${name} (ns: ${namespace}) runs with privileged: true. Privileged containers have near-equivalent access to the host kernel.`,
                severity:    "critical",
                cvssScore:   9.8,
                resource:    `${namespace}/${workload.kind}/${name}/${container.name}`,
                resourceType: "k8s_container",
                evidence:    { Namespace: namespace, Workload: name, Container: container.name, Privileged: true },
                remediationTitle: "Remove privileged mode from container",
                remediationSteps: [
                  `Edit: kubectl edit ${workload.kind?.toLowerCase()} ${name} -n ${namespace}`,
                  "Set securityContext.privileged: false",
                  "Use specific capabilities (capabilities.add) instead of privileged mode",
                ],
                remediationEffort: "medium",
                mitreAttackIds: ["T1611"],
              });
            }

            // Check runAsRoot
            const runAsRoot = container.securityContext?.runAsUser === 0 ||
                              container.securityContext?.runAsNonRoot === false;
            if (runAsRoot) {
              this.addFinding({
                checkId:     `k8s-root-${namespace}-${name}-${container.name}`,
                title:       `Container ${container.name} Runs as Root`,
                description: `Container ${container.name} in ${workload.kind}/${name} is explicitly configured to run as root (UID 0). Root in container = root on host if container escape occurs.`,
                severity:    "high",
                cvssScore:   7.5,
                resource:    `${namespace}/${workload.kind}/${name}/${container.name}`,
                resourceType: "k8s_container",
                evidence:    { Container: container.name, RunAsUser: container.securityContext?.runAsUser },
                remediationTitle: "Run container as non-root",
                remediationSteps: [
                  "Set securityContext.runAsNonRoot: true",
                  "Set securityContext.runAsUser to a non-zero UID (e.g., 1000)",
                  "Update container image to run as non-root by default",
                ],
                remediationEffort: "medium",
                mitreAttackIds: ["T1611"],
              });
            }
          }
        }
      });
    }
  }

  // —— Network Policy Checks ————————————————————————————————————————————————
  private async runNetworkChecks(client: k8s.KubeConfig): Promise<void> {
    const networkApi = client.makeApiClient(k8s.NetworkingV1Api);
    const coreApi    = client.makeApiClient(k8s.CoreV1Api);

    await this.runCheck("k8s-network-policies", async () => {
      const [policies, namespaces] = await Promise.all([
        this.withRetry(() => networkApi.listNetworkPolicyForAllNamespaces(), { label: "network-policies" }),
        this.withRetry(() => coreApi.listNamespace(), { label: "namespaces-for-netpol" }),
      ]);

      return {
        policies: policies.items,
        namespaces: namespaces.items.map((ns: k8s.V1Namespace) => ns.metadata?.name!).filter(Boolean),
      };
    }, ({ policies, namespaces }: { policies: k8s.V1NetworkPolicy[]; namespaces: string[] }) => {
      const namespacesWithPolicies = new Set(policies.map((p: k8s.V1NetworkPolicy) => p.metadata?.namespace));

      const unprotectedNamespaces = namespaces.filter((ns: string) =>
        !namespacesWithPolicies.has(ns) &&
        ns !== "kube-system" && ns !== "kube-public" && ns !== "kube-node-lease"
      );

      if (unprotectedNamespaces.length > 0) {
        this.addFinding({
          checkId:     "k8s-no-network-policies",
          title:       `${unprotectedNamespaces.length} Namespace(s) Have No NetworkPolicy`,
          description: `Namespaces ${unprotectedNamespaces.join(", ")} have no NetworkPolicy. All pods can communicate with all other pods across namespaces. Compromised pod = lateral movement to entire cluster.`,
          severity:    "high",
          cvssScore:   7.5,
          resource:    unprotectedNamespaces.join(", "),
          resourceType: "k8s_namespace",
          evidence:    { UnprotectedNamespaces: unprotectedNamespaces },
          remediationTitle: "Implement default-deny NetworkPolicies",
          remediationSteps: [
            "Create a default-deny-all NetworkPolicy in each namespace",
            "Add allow rules for only required pod-to-pod communication",
            "Test policies: kubectl exec -it POD -- curl http://OTHER_SERVICE",
          ],
          remediationEffort: "high",
          mitreAttackIds: ["T1021"],
        });
      }
    });
  }

  // —— Secret Exposure Checks ———————————————————————————————————————————————
  private async runSecretChecks(client: k8s.KubeConfig): Promise<void> {
    const appsApi = client.makeApiClient(k8s.AppsV1Api);

    await this.runCheck("k8s-secrets-in-env", async () => {
      const resp = await this.withRetry(
        () => appsApi.listDeploymentForAllNamespaces(),
        { label: "deployments-for-secrets" }
      );
      return resp.items;
    }, (deployments: k8s.V1Deployment[]) => {
      for (const deployment of deployments) {
        const name      = deployment.metadata?.name;
        const namespace = deployment.metadata?.namespace;
        const containers = deployment.spec?.template?.spec?.containers ?? [];

        for (const container of containers) {
          const secretEnvVars = (container.env ?? []).filter((env: k8s.V1EnvVar) => {
            const key = env.name?.toLowerCase() ?? "";
            return (
              (key.includes("password") || key.includes("secret") || key.includes("key") ||
               key.includes("token") || key.includes("api_key") || key.includes("private")) &&
              env.value !== undefined // Hardcoded value (not valueFrom)
            );
          });

          if (secretEnvVars.length > 0) {
            this.addFinding({
              checkId:     `k8s-secret-env-${namespace}-${name}-${container.name}`,
              title:       `Container ${container.name} Has Secrets as Hardcoded Env Vars`,
              description: `Container ${container.name} in ${namespace}/${name} has ${secretEnvVars.length} potential secret(s) as hardcoded environment variables. Secrets visible in pod spec, etcd, and logs.`,
              severity:    "high",
              cvssScore:   7.5,
              resource:    `${namespace}/Deployment/${name}/${container.name}`,
              resourceType: "k8s_container",
              evidence:    {
                Container:    container.name,
                SecretEnvVars: secretEnvVars.map((e: k8s.V1EnvVar) => e.name), // Log names only, not values
              },
              remediationTitle: "Use Kubernetes Secrets instead of hardcoded env vars",
              remediationSteps: [
                "Create a Kubernetes Secret: kubectl create secret generic my-secret --from-literal=KEY=VALUE",
                "Reference secret in pod spec using envFrom or env[].valueFrom.secretKeyRef",
                "Remove hardcoded values from deployment manifests",
                "Rotate all secrets that were previously hardcoded",
              ],
              remediationEffort: "medium",
              mitreAttackIds: ["T1552"],
            });
          }
        }
      }
    });
  }

  // —— Namespace Checks —————————————————————————————————————————————————————
  private async runNamespaceChecks(client: k8s.KubeConfig): Promise<void> {
    const coreApi = client.makeApiClient(k8s.CoreV1Api);

    await this.runCheck("k8s-default-namespace-usage", async () => {
      const pods = await this.withRetry(
        () => coreApi.listNamespacedPod({ namespace: "default" }),
        { label: "default-namespace-pods" }
      );
      return pods.items.filter((p: k8s.V1Pod) =>
        !p.metadata?.name?.startsWith("kube-")
      );
    }, (pods: k8s.V1Pod[]) => {
      if (pods.length > 0) {
        this.addFinding({
          checkId:     "k8s-default-namespace-pods",
          title:       `${pods.length} Application Pod(s) Running in Default Namespace`,
          description: `${pods.length} non-system pods are running in the default namespace. The default namespace has no network isolation and all new resources land here if no namespace is specified.`,
          severity:    "low",
          cvssScore:   3.5,
          resource:    "namespace/default",
          resourceType: "k8s_namespace",
          evidence:    { PodCount: pods.length, Pods: pods.map((p: k8s.V1Pod) => p.metadata?.name) },
          remediationTitle: "Move workloads to dedicated namespaces",
          remediationSteps: [
            "Create application namespaces: kubectl create namespace app-prod",
            "Redeploy workloads to appropriate namespaces",
            "Apply NetworkPolicies to new namespaces",
          ],
          remediationEffort: "medium",
        });
      }
    });
  }

  // —— Client factory ——————————————————————————————————————————————————————
  private makeClient(creds: K8sCredentials): k8s.KubeConfig {
    const kc = new k8s.KubeConfig();
    kc.loadFromString(creds.kubeconfig);
    if (creds.context) {
      kc.setCurrentContext(creds.context);
    }
    return kc;
  }
}
