# security-testing-suite
Security script suite that runs on a deployment

# What Trivy catches in Deployment Files
## Container security context

1. Running as root (runAsRoot: true or no runAsNonRoot)
2. Missing readOnlyRootFilesystem
3. allowPrivilegeEscalation not explicitly denied
4. Privileged containers (privileged: true)
5. Missing seccompProfile or appArmorProfile

## Resource limits

1. Missing resources.limits.cpu / resources.limits.memory
2. Missing resources.requests

## Networking

1. hostNetwork: true — container shares the host network stack
2. hostPort usage — binds directly to a node port
3. hostPID: true / hostIPC: true

## Capabilities

1. Dangerous capabilities granted (NET_ADMIN, SYS_ADMIN, etc.)
2. Missing drop: [ALL] in securityContext.capabilities

## Images

1. Using latest tag (no pinned digest)
2. No image pull policy set

## Service accounts

1. automountServiceAccountToken: true when not needed

# How to run
## Generate base scan reports
```bash
trivy config --severity MEDIUM,HIGH,CRITICAL ./secure-app
```

or

```bash
chmod +x trivy-helm-scan.sh

export NEXUS_BASE_URL=https://nexus.internal/repository/tools
export NEXUS_USER=ci-user
export NEXUS_PASS=secret

# Pin version, scan a chart directory
./trivy-helm-scan.sh -v 0.51.2 ./charts/my-app

# JSON report, fail only on CRITICAL
./trivy-helm-scan.sh -v 0.51.2 -o json -f CRITICAL ./deploy/helm
```


## Fancy Report
```bash
python trivy_report.py report.json -o build/reports/scan.html --title "Production Helm Scan"
```

## To see exposed and published ports for a running contain
```bash
docker inspect
```

