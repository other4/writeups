---
title: "Introduction to Kubernetes"
description: "A beginner-friendly guide to understanding Kubernetes (K8s) and how it manages containerized applications like a professional conductor."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com" ]
created: "2026-04-10"
updated: "2026-04-10"
thumbnail: "/images/kubernetes.webp"
tags: [Kubernetes, Docker, DevOps, Cloud-Computing]
keywords: ["What is Kubernetes", "K8s introduction for beginners", "Container orchestration explained"]
---

# Introduction to Kubernetes: The Orchestrator of Containers

Kubernetes (often called K8s) is an open-source platform that acts like a conductor for a massive orchestra of containers. In the modern world of software, we package applications into small, independent units called containers. While one or two containers are easy to handle, managing hundreds or thousands across different servers becomes a nightmare.

Think of it this way: if a container (like Docker) is a single musician, Kubernetes is the conductor. The conductor doesn’t play the instruments but ensures every musician plays the right music, at the right time, and at the right volume. If a musician gets sick, the conductor brings in a replacement immediately so the symphony never stops. Kubernetes does the same for your apps—ensuring they stay running, scale up when traffic hits, and deploy smoothly without downtime.

![Introduction to Kubernetes](/images/kubernetes.webp)

### What it actually does for you:
1. Self-Healing: If a container crashes, Kubernetes automatically restarts it. If a whole server (node) dies, it moves your containers to a healthy one.
2. Auto-Scaling: If your website suddenly gets a lot of traffic, it can automatically spin up more copies of your app to handle the load.
3. Service Discovery & Load Balancing: It gives your apps their own IP addresses and a single DNS name, then balances traffic so no single container gets overwhelmed.
4. Zero-Downtime Updates: It can roll out new versions of your code one container at a time, so your app never goes offline during an update.
5. Storage Management: It automatically attaches storage (like hard drives or cloud storage) to your containers as they move around the cluster.

![Kubernetes work](/images/kubernetes-work.webp)

### Why people use it:
Before Kubernetes, if a server went down at 3 AM, a human had to wake up and fix it. With Kubernetes, the system fixes itself based on the "desired state" you defined in your YAML files.

### Orchestration
orchestration is the ***automated coordination and management of complex computer systems and services.***
If a Container (like Docker) is a single musician, Orchestration is the Conductor who:
- Places the players: Decides which server has enough room to run a container (Scheduling).
- Keeps the beat: Restarts a container immediately if it crashes (Self-healing).
- Adjusts the volume: Adds more containers when traffic is high and removes them when it's low (Scaling).
- Manages the sheet music: Handles how different containers talk to each other and the outside world (Networking).

Without orchestration, you would have to manually log into every server to start, stop, or update your apps. With it, you just tell the system your "desired state," and it handles the rest.

## Main Components or  building blocks of your application inside Kubernetes
![Kubernetes arch](/images/kubernetes-arch.webp)
### 1. Pods (The Compute)
- What it is: The smallest deployable unit in K8s.
- Analogy: A wrapper or a "hotel room" for your container (like Docker).
- Role: It runs your application code. If a Pod dies, K8s replaces it with a new one.

### 2. Service (The Networking)
- What it is: A stable, permanent IP address for a group of Pods.
- Analogy: A reception desk.
- Role: Since Pods are constantly created and destroyed (changing their internal IPs), the Service provides a single point of contact so other apps can find them.

### 3. Ingress (The Gateway)
- What it is: A set of rules that allow external traffic (from the internet) into your cluster.
- Analogy: The front door of the building.
- Role: It handles SSL certificates and routes traffic based on URLs (e.g., `://myapp.com` goes to Service A, `://myapp.com` goes to Service B).

### 4. ConfigMap (The Settings)
- What it is: A way to store non-sensitive configuration data.
- Analogy: A dictionary or a `.env` file.
- Role: It separates your code from your environment settings (like database URLs or port numbers) so you don't have to rebuild your image to change a setting.

### 5. Secrets (The Vault)
- What it is: Similar to a ConfigMap, but for sensitive data.
- Analogy: A safe or a locker.
- Role: It stores passwords, API keys, and certificates securely (Base64 encoded) so they aren't visible in plain text in your code or logs.

### example:
Here is a simple example. We create a ConfigMap to store a theme color and a Secret to store a database password, then pull both into a Pod as environment variables.
### 1. The Configuration (Settings & Secrets)
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-settings
data:
  APP_COLOR: "blue"
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  DB_PASSWORD: dG9wLXNlY3JldC1wd2Q= # "top-secret-pwd" in base64
```

### 2. The Pod (Using the data)
The Pod "injects" these values so your code can read them just like local environment variables.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: backend-container
      image: node:18
      env:
        # Pulling from ConfigMap
        - name: THEME_COLOR
          valueFrom:
            configMapKeyRef:
              name: app-settings
              key: APP_COLOR
        # Pulling from Secret
        - name: DATABASE_PW
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: DB_PASSWORD
```

### Key takeaway:
- ConfigMap: Use for `API_URL`, `PORT`, or `LOG_LEVEL`.
- Secret: Use for `DB_PASSWORD`, `STRIPE_KEY`, or `SSL_CERT`.

### 1. Standard Project Folder Structure

```text
my-project/
├── .github/workflows/      # CI/CD pipelines (GitHub Actions)
├── src/                    # Your application code (Node, Python, etc.)
├── Dockerfile              # Instructions to build your image
├── k8s/                    # All Kubernetes manifests
│   ├── base/               # Common settings for all environments
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── ingress.yaml
│   └── overlays/           # Environment-specific overrides
│       ├── dev/
│       │   ├── configmap.yaml
│       │   └── secret.yaml  (or reference to a Vault)
│       └── prod/
│           ├── configmap.yaml
│           └── hpa.yaml     # Horizontal Pod Autoscaler
└── README.md
```

### 2. Inside the `k8s/` Folder (Resource Based)

If you aren't using a tool like Kustomize or Helm yet, you might prefer organizing by object type:

```text
k8s/
├── 01-namespace.yaml      # Always run first
├── 02-configmap.yaml      # Configs before the app starts
├── 03-secrets.yaml        # Secrets before the app starts
├── 04-deployment.yaml     # The actual app
├── 05-service.yaml        # Internal networking
└── 06-ingress.yaml        # External access
```

### 3. Best Practices for This Structure
- Naming Convention: Prefix files with numbers (`01-`, `02-`) so you know the order in which to run `kubectl apply -f`.
- Secret Safety: Never commit real passwords in `secrets.yaml` to GitHub. Use a `.gitignore` for that file or use a tool like Sealed Secrets or HashiCorp Vault.
- One File per Service: Keep your backend and frontend manifests in separate subfolders if they are large.
Pro-Tip: Use Kustomize (built into `kubectl`). It allows you to have a `base` folder and just "patch" the parts that change between Dev and Prod (like DB URLs or CPU limits).

###  Full-Stack project, 
***separate your Frontend and Backend manifests.*** This allows you to scale them independently (e.g., more Frontend pods during a sale, but fewer Backend pods).

Here is the recommended structure:
#### Recommended Project Layout
```text
my-fullstack-app/
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   └── k8s/
│       ├── deployment.yaml  (Runs the React/Next.js container)
│       ├── service.yaml     (Internal cluster IP)
│       └── ingress.yaml     (Routes 'myapp.com' to Frontend)
├── backend/
│   ├── src/
│   ├── Dockerfile
│   └── k8s/
│       ├── deployment.yaml  (Runs Node/Python/Go container)
│       ├── service.yaml     (Internal cluster IP for Backend)
│       ├── configmap.yaml   (DB URLs, Port settings)
│       └── secrets.yaml     (DB Passwords, API Keys)
└── infrastructure/
    └── database.yaml        (Postgres/MongoDB StatefulSet)
```

#### How They Connect in K8s

1. Backend Config (`backend/k8s/configmap.yaml`):  
    Contains the `DB_URL`. The Backend Pod reads this to connect to the Database.
2. Backend Service (`backend/k8s/service.yaml`):  
    Creates a fixed DNS name inside the cluster, e.g., `http://backend-service`.
3. Frontend Config (`frontend/k8s/deployment.yaml`):  
    You pass an environment variable `API_URL` to your Frontend container with the value `http://backend-service`.
4. Ingress (`frontend/k8s/ingress.yaml`):  
    The "Front Door." It routes public traffic:    
    - `://myapp.com` → Frontend Service
    - `://myapp.com` → Backend Service
    
#### Why this structure?
- Decoupling: You can update the Backend code without touching the Frontend's K8s files.
- Security: The Database and Backend stay private. Only the Ingress is exposed to the internet.
- Scaling: If your Frontend is heavy, you can set `replicas: 5` in `frontend/k8s/deployment.yaml` while keeping the Backend at `replicas: 2`.

This Ingress file acts as the "Traffic Controller." It sits at the entry point of your cluster and routes requests based on the URL path.

### The Ingress Manifest (`frontend/k8s/ingress.yaml`)
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: main-ingress
  annotations:
    # Essential if using NGINX Ingress Controller
    kubernetes.io/ingress.class: "nginx"
    # Rewrites paths so '/api/users' reaches backend as '/users'
    nginx.ingress.kubernetes.io/rewrite-target: /$2
spec:
  rules:
  - host: myapp.com  # Your domain
    http:
      paths:
      - path: /api(/|$)(.*)  # Routes any URL starting with /api
        pathType: ImplementationSpecific
        backend:
          service:
            name: backend-service  # Matches the 'name' in backend/service.yaml
            port:
              number: 8080         # The port your Backend Service listens on
      - path: /              # Routes everything else to the frontend
        pathType: Prefix
        backend:
          service:
            name: frontend-service # Matches the 'name' in frontend/service.yaml
            port:
              number: 80           # The port your Frontend Service listens on
```

#### How it works in your project:
1. Frontend Traffic: When a user visits `://myapp.com`, the Ingress sends them to the Frontend Service.
2. Backend Traffic: When the React/Next.js app calls `://myapp.com`, the Ingress strips the `/api` prefix and sends the request to the Backend Service.
3. Security: Your Backend and Database don't need public IPs. They stay safe inside the cluster, and only the Ingress is exposed to the internet.

#### Important Note on Services:
For this to work, your `backend-service.yaml` and `frontend-service.yaml` must have `name: backend-service` and `name: frontend-service` respectively.

## Master Process
In Kubernetes, the `master process` ***refers to the Control Plane, which acts as the cluster's brain***. It is not a single process but a collection of four core components that work together to manage the state of the cluster. 

### 1. kube-apiserver (The Gateway)
- Role: The front end of the cluster.
- Function: All communications—whether from users via `kubectl`, internal components, or external tools—must go through this API. It validates and processes REST requests, acting as the only component that directly interacts with the cluster's database.

### 2. etcd (The Database)
- Role: The "source of truth" for the entire cluster.
- Function: A highly available, distributed key-value store that keeps a record of all cluster data, including configurations, secrets, and the current state of every resource (like Pods and Nodes).

### 3. kube-scheduler (The Decision Maker)
- Role: Assigns workloads to specific machines.
- Function: When a new Pod is created, the scheduler looks at the available resources (CPU, RAM) and constraints (policies, affinity) on all worker nodes and chooses the best one to run that Pod. 

### 4. kube-controller-manager (The Supervisor)
- Role: Maintains the "desired state" of the cluster.
- Function: It runs background control loops (controllers) that watch for changes. For example, if you want 3 replicas of an app but one crashes, the Replication Controller detects the gap and tells the API server to start a new one to get back to 3.

### How they work together
1. Request: You send a command like `kubectl apply` to the API Server.
2. Storage: The API Server saves this "desired state" into etcd.
3. Scheduling: The Scheduler notices a new Pod needs a home and tells the API Server which Node to use.
4. Enforcement: The Controller Manager constantly checks that what is actually running matches what you requested in your configuration. 

Would you like to see how these master components communicate with the Kubelet on your worker nodes to actually start a container?

---
## References
[0] [kubernetes](https://kubernetes.io/docs/)
[1] [https://www.geeksforgeeks.org](https://www.geeksforgeeks.org/devops/what-is-kubernetes-control-plane/)
[2] [https://medium.com](https://medium.com/jorgeacetozi/kubernetes-master-components-etcd-api-server-controller-manager-and-scheduler-3a0179fc8186)
[3] [https://medium.com](https://medium.com/@thisara.weerakoon2001/kubernetes-the-roles-of-master-and-worker-nodes-08fc539812d2)
[4] [https://www.linkedin.com](https://www.linkedin.com/pulse/kubernetes-master-node-deep-dive-bojan-djokic-gkhbf)
[5] [https://medium.com](https://medium.com/jorgeacetozi/kubernetes-master-components-etcd-api-server-controller-manager-and-scheduler-3a0179fc8186)
[6] [https://medium.com](https://medium.com/@akshay.ar.1733/lesson-03-understanding-the-components-of-master-node-in-k8s-c168c7265c76)
[7] [https://dev.to](https://dev.to/monarene/inside-the-kubernetes-control-plane-28ie)
[8] [https://blog.devops.dev](https://blog.devops.dev/kubernetes-architecture-understanding-nodes-and-processes-bcc0e860a012)
[9] [https://medium.com](https://medium.com/@rajeshkanumurudevops/kubernetes-master-components-248b57b36e03)
[10] [https://www.armosec.io](https://www.armosec.io/glossary/kubernetes-control-plane/)

---
