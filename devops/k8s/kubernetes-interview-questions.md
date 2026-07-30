---
title: "Kubernetes Interview Questions & Answers"
description: "A beginner-friendly guide to understanding interview questions and answers of Kubernetes (K8s) and how it manages containerized applications like a professional conductor."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com" ]
created: "2026-07-30"
updated: "2026-07-30"
thumbnail: "/images/k8s-interview-qa.png"
tags: [Kubernetes, Docker, DevOps, Cloud-Computing]
keywords: ["What is Kubernetes", "K8s introduction for beginners", "Container orchestration explained", "Kubernetes Interview Questions & Answers"]
---

# Kubernetes Interview Questions & Answers

![Kubernetes Interview Questions & Answers](/images/k8s-interview-qa.png)

## 1. Fundamentals

**Q1. What is Kubernetes, and why do we need it?**
Kubernetes (K8s) is an open-source **container orchestration platform** that automates deployment, scaling, networking, and self-healing of containerized applications. We need it because running containers manually doesn't scale — if a container crashes, nothing restarts it; if traffic spikes, nothing scales it; if a node dies, nothing reschedules the workload. Kubernetes handles all of this automatically.

**Q2. What is the difference between a monolithic and a microservices architecture, and how does K8s help?**
A monolith is one large application handling every function; a single bug or scaling need affects the whole app. Microservices break the app into small independent services, which can each scale/fail independently but are harder to manage manually (many containers, networking, discovery). Kubernetes provides the orchestration layer needed to run microservices reliably at scale.

**Q3. What does "K8s" mean?**
"K" + 8 letters ("ubernete") + "s" = K8s. It originated at Google as an internal system called **Borg**, released as open source in 2014, and is now a CNCF (Cloud Native Computing Foundation) graduated project.

**Q4. What is a container, and how is it different from a VM?**
A container packages an application with its dependencies and shares the host OS kernel, making it lightweight and fast to start. A VM virtualizes an entire OS (its own kernel), making it heavier and slower to boot. Containers are process-level isolation; VMs are hardware-level isolation.

**Q5. What is `kubectl`?**
The command-line client used to interact with a Kubernetes cluster's API Server — used to create, inspect, update, and delete resources (`kubectl apply`, `kubectl get`, `kubectl describe`, etc.).

---

## 2. Architecture

**Q6. Explain the Kubernetes architecture at a high level.**
A cluster has a **Control Plane (Master Node)** and one or more **Worker Nodes**. The Control Plane makes global decisions (scheduling, scaling, detecting failures); Worker Nodes actually run the application containers inside Pods.

**Q7. What are the main components of the Control Plane?**
- **API Server** — the single entry point; all communication (kubectl, kubelet, controllers) goes through it.
- **etcd** — a distributed key-value store holding the entire cluster's state/configuration.
- **Scheduler** — decides which Worker Node a new Pod should run on, based on resource availability, taints/affinity, etc.
- **Controller Manager** — runs control loops (Node controller, ReplicaSet controller, etc.) that continuously reconcile actual state to desired state.

**Q8. What are the main components on a Worker Node?**
- **Kubelet** — the agent that talks to the API Server and ensures the containers described in a Pod spec are actually running.
- **Kube-proxy** — maintains network rules on the node so traffic gets routed correctly to Pods via Services.
- **Container runtime** (e.g., containerd) — the software that actually pulls images and runs containers.

**Q9. Do application containers ever run on the Master Node?**
No. Application workloads (Pods) always run on Worker Nodes. The Master/Control Plane node is tainted by default specifically to prevent regular Pods from being scheduled there.

**Q10. What is `etcd` and why is it important?**
`etcd` is a distributed, consistent key-value store that holds all cluster state — every object (Pods, Deployments, Secrets, etc.) is persisted there. If etcd is lost/corrupted without a backup, the cluster loses its entire state, so etcd backups are critical for disaster recovery.

**Q11. What is a CNI, and why is it needed?**
Container Network Interface — a plugin standard (e.g., Calico, Weave Net, Flannel) that provides networking so that Pods across different nodes can communicate with each other on a flat network.

---

## 3. Pods & Workload Controllers

**Q12. What is a Pod?**
The smallest deployable unit in Kubernetes. A Pod wraps one or more tightly-coupled containers that share the same network namespace (same IP, can talk via `localhost`) and can share storage volumes.

**Q13. Why would a Pod have more than one container?**
When containers need to be co-located and share resources tightly — e.g., a main app container plus a **sidecar** container (log shipper, proxy) or an **init container** that runs setup logic before the main container starts.

**Q14. What is the difference between a Deployment and a ReplicaSet?**
A ReplicaSet ensures a specified number of Pod replicas are running, but has no built-in rolling update mechanism. A Deployment manages ReplicaSets **on top of** that, adding rolling updates and rollback support. In practice, you almost always create Deployments, and Kubernetes creates/manages the ReplicaSet underneath for you.

**Q15. What is a rolling update, and why does it matter?**
A rolling update replaces old Pods with new ones gradually (a few at a time) instead of all at once, so the application stays available throughout the update — no downtime. Controlled via `kubectl set image` or editing the Deployment's Pod template, and configurable via `strategy.rollingUpdate.maxUnavailable`/`maxSurge`.

**Q16. How do you roll back a Deployment?**
```bash
kubectl rollout undo deployment/<name>
kubectl rollout undo deployment/<name> --to-revision=<n>
kubectl rollout history deployment/<name>
```

**Q17. What is a DaemonSet, and when would you use one?**
A DaemonSet ensures exactly one Pod runs on every (or a selected subset of) node — used for node-level agents like log collectors (Fluentd), monitoring agents (Node Exporter), or CNI/network plugins.

**Q18. What is a StatefulSet, and how is it different from a Deployment?**
StatefulSets are for stateful applications (databases) that need: (1) stable, predictable Pod names (`mysql-0`, `mysql-1`…) instead of random suffixes, (2) each replica bound to its own persistent volume via `volumeClaimTemplates`, and (3) ordered, graceful scaling/termination. A Deployment's Pods are interchangeable and don't have this guarantee.

**Q19. What is a headless Service, and why does a StatefulSet need one?**
A Service with `clusterIP: None`. Instead of load-balancing across Pods, it gives each Pod its own DNS entry (`<pod-name>.<service-name>.<namespace>.svc.cluster.local`), which StatefulSet Pods need for stable peer-to-peer addressing (e.g., database replication).

**Q20. What is a Job vs a CronJob?**
A Job runs a Pod to completion once (for a one-time task like a batch script), then stops. A CronJob runs a Job on a recurring schedule using standard cron syntax (e.g., `*/5 * * * *`).

**Q21. What are the possible Pod lifecycle phases?**
`Pending` → `Running` → `Succeeded`/`Failed`. Common troubleshooting states you'll also see: `ContainerCreating`, `CrashLoopBackOff`, `ImagePullBackOff`, `Terminating`.

**Q22. What causes `CrashLoopBackOff`?**
The container keeps starting and then crashing/exiting repeatedly, so Kubernetes backs off and retries with increasing delay. Common causes: application error on startup, missing required environment variables/config, failed liveness probe, or the container's main process exiting immediately.

**Q23. What causes `ImagePullBackOff`?**
Kubernetes can't pull the specified container image — usually due to a wrong image name/tag, a private registry needing credentials (`imagePullSecrets`), or network/registry issues.

---

## 4. Namespaces

**Q24. What is a Namespace, and why use one?**
A logical partition within a single cluster used to group and isolate resources (e.g., separate `dev`, `staging`, `prod`, or per-team/per-app namespaces). Helps avoid naming collisions and allows scoping RBAC, quotas, and network policies.

**Q25. What namespace do resources go into if you don't specify one?**
`default`.

**Q26. What are the built-in namespaces?**
`default`, `kube-system` (control plane components), `kube-public`, `kube-node-lease`.

**Q27. Does deleting a Namespace delete everything inside it?**
Yes — deleting a Namespace cascades and deletes all resources within it (Pods, Services, ConfigMaps, etc.). This is destructive and often takes a little time to fully complete.

---

## 5. Networking: Services & Ingress

**Q28. Why can't we rely on a Pod's IP address directly?**
Pod IPs are ephemeral — every time a Pod restarts or is rescheduled, it can get a new IP. A Service provides a stable virtual IP/DNS name that automatically load-balances across the current set of matching Pods.

**Q29. What are the Service types, and when do you use each?**
- **ClusterIP** (default): internal-only virtual IP, reachable only inside the cluster.
- **NodePort**: exposes the Service on a static port (30000–32000) on every node's IP — useful for quick external access/testing.
- **LoadBalancer**: provisions a cloud load balancer (AWS ELB, etc.) — standard for production external access on cloud.
- **ExternalName**: maps a Service to an external DNS name (no proxying, just a CNAME-style redirect).
- **Headless (`clusterIP: None`)**: gives direct per-Pod DNS, used with StatefulSets.

**Q30. What's the difference between `port` and `targetPort` in a Service spec?**
`port` is the port the Service itself exposes (what clients connect to); `targetPort` is the port on the container/Pod that actually receives the traffic.

**Q31. What is an Ingress, and how is it different from a Service?**
A Service exposes a single set of Pods, typically at Layer 4 (TCP). An Ingress is a Layer 7 (HTTP/HTTPS) routing rule set that can route traffic to multiple different Services based on hostname and URL path — letting you expose many services through one external endpoint/load balancer, plus support TLS termination.

**Q32. Does Ingress work by itself?**
No — you also need an **Ingress Controller** (e.g., ingress-nginx, Traefik) running in the cluster; the Ingress object is just a set of routing rules that the controller reads and implements.

**Q33. How does internal DNS resolution work between services in the same cluster?**
Every Service gets a DNS entry: `<service-name>.<namespace>.svc.cluster.local`. Pods in the same namespace can often just use `<service-name>`.

**Q34. What is kube-proxy's role?**
It watches the API Server for Service/Endpoint changes and configures networking rules (iptables/IPVS) on each node so traffic to a Service's virtual IP gets routed to one of the backing Pods.

---

## 6. Storage

**Q35. Why do Pods need external storage solutions like PV/PVC?**
Containers/Pods are ephemeral — any data written inside a container's filesystem is lost when the Pod is deleted/recreated. Persistent Volumes decouple storage from the Pod's lifecycle so data survives Pod restarts.

**Q36. What is the difference between a PersistentVolume (PV) and a PersistentVolumeClaim (PVC)?**
A PV is the actual piece of storage provisioned from underlying infrastructure (a disk, cloud volume, NFS share). A PVC is a *request* for storage made by a user/Pod ("I need 5Gi, ReadWriteOnce") — Kubernetes binds a PVC to a matching available PV.

**Q37. What is a StorageClass?**
Defines *how* storage should be dynamically provisioned (which provisioner/backend to use — e.g., AWS EBS `gp2`, local-path) so PVCs don't need a pre-existing PV; the StorageClass provisions one on demand.

**Q38. What are the PV access modes?**
- `ReadWriteOnce` (RWO): mountable read-write by a single node.
- `ReadOnlyMany` (ROX): mountable read-only by many nodes.
- `ReadWriteMany` (RWX): mountable read-write by many nodes.

**Q39. What is `persistentVolumeReclaimPolicy`?**
Determines what happens to the underlying storage when its PVC is deleted: `Retain` (keep the data, PV becomes "released" and needs manual cleanup), `Delete` (storage is automatically deleted), `Recycle` (deprecated).

**Q40. Why does a StatefulSet use `volumeClaimTemplates` instead of a plain PVC reference?**
Because each replica (`mysql-0`, `mysql-1`, …) needs its *own* dedicated PVC/PV, created and bound automatically per Pod — a single shared PVC reference in a normal Deployment wouldn't give each replica isolated storage.

---

## 7. ConfigMaps & Secrets

**Q41. What is the difference between a ConfigMap and a Secret?**
Both decouple configuration from Pod specs, but a ConfigMap is meant for **non-sensitive** plain-text data (feature flags, DB name), while a Secret is meant for **sensitive** data (passwords, tokens, keys) and is stored base64-encoded.

**Q42. Is base64 encoding in Secrets secure?**
No — base64 is just an encoding, not encryption; anyone with read access can trivially decode it (`base64 -d`). For real security, encrypt etcd at rest, restrict RBAC access to Secrets, and consider an external secrets manager (Vault, AWS Secrets Manager, Sealed Secrets, etc.).

**Q43. How do you inject a ConfigMap/Secret value into a container as an environment variable?**
```yaml
env:
  - name: MY_VAR
    valueFrom:
      configMapKeyRef:   # or secretKeyRef
        name: my-config
        key: MY_KEY
```

**Q44. Can you mount a ConfigMap/Secret as a file instead of an env var?**
Yes — via a `volume` of type `configMap`/`secret` mounted into the container, which creates files (one per key) at the mount path. This is useful for config files or certs that an app reads from disk.

---

## 8. Scheduling: Taints, Tolerations, Affinity

**Q45. What is a taint, and what is a toleration?**
A taint is applied to a **Node** to repel Pods from being scheduled there unless they explicitly "tolerate" it. A toleration is applied to a **Pod**, allowing it to be scheduled onto a node with a matching taint. They work together: taints repel, tolerations permit.

**Q46. What is Node Affinity, and how is it different from taints/tolerations?**
Node Affinity is applied on the **Pod** side to express a preference/requirement for which nodes it should run on, based on node labels (similar to, but more expressive than, `nodeSelector`). Taints/tolerations are about *exclusion* (keeping Pods away unless permitted); affinity is about *attraction* (pulling Pods toward specific nodes).

**Q47. Why is the Control Plane node tainted by default?**
To prevent regular application Pods from being scheduled on it, keeping control plane components isolated and stable.

---

## 9. Scaling (HPA/VPA)

**Q48. What is the Horizontal Pod Autoscaler (HPA)?**
A controller that automatically adjusts the **number of Pod replicas** in a Deployment/ReplicaSet/StatefulSet based on observed metrics (commonly CPU/memory utilization, or custom metrics).

**Q49. What is the Vertical Pod Autoscaler (VPA)?**
A controller that automatically adjusts the **CPU/memory requests and limits of a Pod** (making individual Pods "bigger" or "smaller") rather than changing the number of replicas.

**Q50. When would you use VPA instead of HPA?**
For workloads that can't easily be horizontally scaled (e.g., a single-instance stateful database), or when the bottleneck is a Pod not having enough resources rather than needing more replicas.

**Q51. What's required for HPA/VPA to work?**
A **Metrics Server** (or a custom metrics adapter) must be running in the cluster to supply resource usage data; and the target Deployment should define `resources.requests` so utilization percentages are meaningful.

**Q52. What's the difference between `requests` and `limits` in a Pod spec?**
`requests` is the guaranteed minimum amount of CPU/memory the scheduler reserves for the container (used for scheduling decisions). `limits` is the maximum the container is allowed to consume — exceeding a memory limit gets the container OOM-killed; exceeding a CPU limit gets it throttled.

---

## 10. RBAC & Security

**Q53. What is RBAC in Kubernetes?**
Role-Based Access Control — a mechanism to control which users/ServiceAccounts can perform which actions (verbs like `get`, `list`, `create`, `delete`) on which resources, scoped either to a namespace (`Role`/`RoleBinding`) or the whole cluster (`ClusterRole`/`ClusterRoleBinding`).

**Q54. What is the difference between a Role and a ClusterRole?**
A Role's permissions are scoped to a single namespace. A ClusterRole's permissions apply cluster-wide (or can be bound within a specific namespace too) — needed for cluster-scoped resources like Nodes, or for tools like the Dashboard that need broad access.

**Q55. What is a ServiceAccount, and how is it different from a regular User?**
A ServiceAccount is an identity used by processes/Pods running *inside* the cluster (e.g., an application calling the K8s API). Regular Users are typically managed externally (via a cloud IAM system, certificates, or OIDC) and aren't a first-class API object the way ServiceAccounts are.

**Q56. How do you check what a user/ServiceAccount is allowed to do?**
```bash
kubectl auth can-i <verb> <resource> --as=<user> -n <namespace>
kubectl auth can-i get pods --as=system:serviceaccount:<ns>:<sa> -n <ns>
```

**Q57. What is `cluster-admin`?**
A built-in ClusterRole with unrestricted access to every resource in the cluster — used sparingly, typically for cluster administrators or trusted tooling (like binding it to a Dashboard's admin ServiceAccount).

---

## 11. Helm

**Q58. What is Helm, and what problem does it solve?**
Helm is Kubernetes' package manager. It bundles a set of related manifests (Deployment, Service, HPA, ConfigMap, etc.) into a reusable, versioned, configurable package called a **Chart**, so you don't have to write/maintain raw YAML for every environment (dev/staging/prod) separately.

**Q59. What are the key files in a Helm chart?**
`Chart.yaml` (metadata: name/version), `values.yaml` (default configurable values), and `templates/` (the actual K8s manifest templates using Go templating, e.g. `{{ .Values.image.tag }}`).

**Q60. How do you install the same chart into multiple environments with different configuration?**
```bash
helm install dev-app ./chart -n dev --create-namespace
helm install prod-app ./chart -n prod --create-namespace --set replicaCount=3
```
Each release is independent, with its own values/overrides, even though they share the same underlying chart templates.

**Q61. How do you roll back a Helm release?**
```bash
helm rollback <release-name> <revision-number>
helm history <release-name>
```

---

## 12. Monitoring & Troubleshooting

**Q62. What are the three pillars of observability?**
**Metrics** (what is happening — CPU/memory/network, via Prometheus/Grafana), **Logs** (why it happened — via Loki/Promtail or an ELK-style stack), and **Traces** (how a request flowed across services — via Jaeger/OpenTelemetry).

**Q63. What is Prometheus, and how does it collect data in a K8s cluster?**
A time-series database that **scrapes** metrics from configured targets over HTTP. In K8s it typically scrapes: **Node Exporter** (per-node OS metrics), **kube-state-metrics** (state of K8s objects — Deployments, Pods, etc.), and the control plane components (API server, scheduler) directly.

**Q64. What is `kube-state-metrics` vs `metrics-server`?**
`metrics-server` provides real-time resource usage (CPU/memory) for `kubectl top` and HPA. `kube-state-metrics` exposes the **state** of Kubernetes objects (e.g., how many replicas are desired vs available, Pod status) as Prometheus metrics — it's about object state, not raw resource usage.

**Q65. What is Grafana's role relative to Prometheus?**
Grafana is a visualization layer — it queries Prometheus (or other data sources) and renders dashboards/graphs/alerts; it does not store the metrics itself.

**Q66. Walk through how you'd debug a Pod stuck in `Pending`.**
```bash
kubectl describe pod <pod> -n <ns>
```
Check the Events section — common causes: insufficient CPU/memory on any node, no node matches the Pod's node affinity/selector, unbound PVC (no matching PV), or all nodes are tainted without a matching toleration.

**Q67. How do you check logs for a crashing container, especially if it already restarted?**
```bash
kubectl logs <pod> -n <ns>
kubectl logs <pod> -n <ns> --previous   # logs from the last crashed instance
```

**Q68. What's the difference between `kubectl delete` and `kubectl apply` for updating a resource?**
`kubectl apply` does a declarative update — it diffs your YAML against the live state and patches only what changed. `kubectl delete` + recreate is destructive and causes downtime; generally you should prefer `apply` (or `kubectl edit`/`kubectl set`) for live changes.

---

## 13. Advanced / Architecture Design

**Q69. What is an Init Container, and how is it different from a Sidecar container?**
An Init Container runs **before** the main container and must complete successfully before the main container starts — used for setup tasks (waiting for a dependency, preparing files). A Sidecar runs **alongside** the main container for the Pod's whole lifetime, helping it (e.g., a log shipper, a proxy) — both run concurrently and typically share a Volume.

**Q70. What is a Service Mesh, and why would you introduce one (e.g., Istio)?**
A Service Mesh (like Istio) transparently injects a sidecar proxy (Envoy) into every Pod to manage service-to-service traffic — providing mutual TLS encryption, retries/circuit breaking, fine-grained traffic routing (canary/blue-green), and deep observability into which service calls which, without changing application code.

**Q71. What is a Custom Resource Definition (CRD)?**
A way to extend the Kubernetes API with your own resource "kind" (beyond built-ins like Pod/Deployment). Once a CRD is registered, users can create YAML instances of that new kind, and Kubernetes stores/manages them the same way it manages native resources.

**Q72. What is an Operator, and how does it relate to CRDs?**
An Operator is a custom controller that watches Custom Resources and runs automation logic in response — encoding operational knowledge (e.g., how to safely upgrade a database) into software. Examples: the Prometheus Operator, the ArgoCD application controller.

**Q73. What is GitOps, and how does ArgoCD implement it?**
GitOps is a deployment model where a Git repository is the single source of truth for your desired infrastructure/app state. ArgoCD continuously watches that repo and automatically syncs the live cluster to match it — so deployments happen via a Git commit/merge rather than someone running `kubectl apply` manually.

**Q74. What is the difference between a managed Kubernetes service (like EKS) and self-managed (like via kubeadm)?**
In a managed service (EKS/AKS/GKE), the cloud provider runs and maintains the Control Plane (API server, etcd, scheduler, etc.) for you — you only manage worker nodes/workloads. With kubeadm, you're responsible for bootstrapping and maintaining the entire control plane yourself.

**Q75. How would you design zero-downtime deployments in Kubernetes?**
Use Deployments with a rolling update strategy (`maxUnavailable`/`maxSurge` tuned appropriately), define `readinessProbes` so traffic isn't sent to a Pod until it's actually ready, define `livenessProbes` so unhealthy Pods get restarted, and use `PodDisruptionBudgets` to control how many Pods can be voluntarily evicted at once (e.g., during node maintenance).

**Q76. What is a `readinessProbe` vs a `livenessProbe` vs a `startupProbe`?**
- **livenessProbe**: is the container alive? If it fails, Kubernetes restarts the container.
- **readinessProbe**: is the container ready to serve traffic? If it fails, the Pod is removed from Service endpoints (but not restarted).
- **startupProbe**: used for slow-starting containers — disables liveness/readiness checks until the app has successfully started, avoiding premature restarts.

---

## 14. Scenario-Based Questions

**Q77. A Deployment shows 3/3 replicas "Ready" but users are getting connection errors. How do you troubleshoot?**
Check: (1) does the Service's `selector` actually match the Pods' `labels`? (2) is `targetPort` correct and matching the container's listening port? (3) are readinessProbes passing (a Pod can be "Running" but not "Ready" and still be excluded from the Service)? (4) check Ingress rules/annotations if traffic comes through an Ingress Controller. (5) check NetworkPolicies that might be blocking traffic.

**Q78. Your Pod keeps getting OOMKilled. What do you check/do?**
Check `kubectl describe pod` for `OOMKilled` in the last state; either the app has a memory leak, or the `resources.limits.memory` is set too low for actual usage. Fix by profiling the app's real memory needs and adjusting `requests`/`limits`, or fixing the leak.

**Q79. You need to run a one-time database migration before a new app version goes live. How would you do this in Kubernetes?**
Use an Init Container on the Deployment (if it must run before every Pod start), or more commonly a standalone **Job** (possibly triggered as a pre-deploy hook, e.g., a Helm `pre-upgrade` hook) that runs the migration script to completion before the new Deployment rolls out.

**Q80. How do you securely pass a database password to a Pod without hardcoding it in the manifest?**
Store it in a Kubernetes `Secret` (ideally sourced from a proper secrets manager, and with etcd encryption at rest enabled), then reference it via `secretKeyRef` in the container's `env`, restricting who can read that Secret via RBAC.

**Q81. Your cluster's nodes are running low on capacity and new Pods stay `Pending`. What are your options?**
Scale out the node group (manually or via Cluster Autoscaler), review whether existing Pods have over-provisioned `resources.requests` (wasting reservable capacity), check for taints preventing scheduling on otherwise-free nodes, or consider Vertical Pod Autoscaler to right-size existing workloads and free up room.

**Q82. How would you migrate a stateful application (like MySQL) into Kubernetes safely?**
Use a StatefulSet with `volumeClaimTemplates` bound to durable storage (cloud-backed, not local ephemeral disk, unless intentionally using local-path with backups), configure a headless Service for stable network identity, plan for backups (e.g., CronJob for dumps, or a dedicated backup operator), and test failover/restart behavior before going to production.

---

## Bonus: Rapid-Fire One-Liners

| Question | Short Answer |
|---|---|
| Smallest deployable unit? | Pod |
| Which component makes scheduling decisions? | Scheduler |
| Which component stores cluster state? | etcd |
| Which component runs on every worker node and talks to the API server? | Kubelet |
| Default namespace? | `default` |
| Command to see Pod events/errors? | `kubectl describe pod <name>` |
| Object for stable network identity + load balancing? | Service |
| Object for L7 HTTP routing across services? | Ingress |
| Object for persisting data beyond Pod lifecycle? | PersistentVolume + PersistentVolumeClaim |
| Object for non-sensitive config? | ConfigMap |
| Object for sensitive config? | Secret |
| Controller that scales replica count automatically? | HPA |
| Controller that resizes a Pod's resources automatically? | VPA |
| Ensures one Pod per node? | DaemonSet |
| Used for databases needing stable identity + storage? | StatefulSet |
| Runs a container to completion once? | Job |
| Runs a Job on a schedule? | CronJob |
| K8s package manager? | Helm |
| Extends the K8s API with custom object types? | CustomResourceDefinition (CRD) |
| Manages who can do what in the cluster? | RBAC (Role/RoleBinding/ClusterRole/ClusterRoleBinding) |