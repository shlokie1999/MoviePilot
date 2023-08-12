
## Overview

Clair is open-source tool used for static analysis of vulnerabilities in Docker containers. It was developed by CoreOS (now part of Red Hat). The purpose of Clair is to identify known security issues in container images before they are deployed in production environments. This helps to ensure that containers used in applications are free from known vulnerabilities and potential security risks.

Clair is often integrated into container orchestration platforms and CI/CD pipelines to ensure that only secure container images are deployed in production environments.

## Work Mechanism of Clair
Indexing: Clair maintains a database of known vulnerabilities for various container images. This database is continuously updated with information about newly discovered vulnerabilities.
Scanning: When a new container image is uploaded to Clair for analysis, the tool breaks down the image's layers and compares them against its vulnerability database.
Reporting: Clair generates a report that lists the vulnerabilities found in the container image along with information about their severity, the affected packages, and potential solutions or fixes.

## Docker Build
Browse to the google cloud repositories,and edit cloudbuild.yaml.
Add below commands to build an image that needs to be scanned.

```
steps:
  # Step 0: Build the Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'us-central1-docker.pkg.dev/mcmp-integration-qa/clair-scan-repo/appimage:latest', '.']

```
## Installation and Scanning within the CI pipeline using Clair

```
# Step 1: Install and run clair scanne ron the built image
  - name: 'ubuntu'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        ls
        cat /etc/os-release
        apt-get update
        apt-get install net-tools
        apt-get install -y wget
        apt-get install -y curl
        apt-get install iproute2 -y
        apt-get -y install jq
        apt-get install ca-certificates curl gnupg -y
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
        docker pull arminc/clair-local-scan
        docker pull arminc/clair-db
        docker images
        docker run --network=cloudbuild -d --name clair-db arminc/clair-db:latest 
        docker run --network=cloudbuild -p 6060:6060 --link clair-db:postgres -d --name clair arminc/clair-local-scan:latest
        _CLAIR_CONTAINER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' clair)
        _DOCKER_HOST_IP=$(ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
        curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o /usr/bin/clair-scanner
        chmod 777 /usr/bin/clair-scanner
        clair-scanner -h
        docker images
        ip addr show
        ifconfig
        clair-scanner -c http://$${_CLAIR_CONTAINER_IP}:6060 --ip $${_DOCKER_HOST_IP} --report="report.json" -t "Critical" us-central1-docker.pkg.dev/mcmp-integration-qa/clair-scan-repo/appimage:latest

```




















steps:
  # Step 0: Build the Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'us-central1-docker.pkg.dev/mcmp-integration-qa/clair-scan-repo/appimage:latest', '.']
    
  # Step 1: Install and run clair scanne ron the built image
  - name: 'ubuntu'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        ls
        cat /etc/os-release
        apt-get update
        apt-get install net-tools
        apt-get install -y wget
        apt-get install -y curl
        apt-get install iproute2 -y
        apt-get -y install jq
        apt-get install ca-certificates curl gnupg -y
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
        docker pull arminc/clair-local-scan
        docker pull arminc/clair-db
        docker images
        docker run --network=cloudbuild -d --name clair-db arminc/clair-db:latest 
        docker run --network=cloudbuild -p 6060:6060 --link clair-db:postgres -d --name clair arminc/clair-local-scan:latest
        _CLAIR_CONTAINER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' clair)
        _DOCKER_HOST_IP=$(ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
        curl -L https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -o /usr/bin/clair-scanner
        chmod 777 /usr/bin/clair-scanner
        clair-scanner -h
        docker images
        ip addr show
        ifconfig
        clair-scanner -c http://$${_CLAIR_CONTAINER_IP}:6060 --ip $${_DOCKER_HOST_IP} --report="report.json" -t "Critical" us-central1-docker.pkg.dev/mcmp-integration-qa/clair-scan-repo/appimage:latest

    # Step 3:Check for critical Vulnerabilities in the report to provide guidance on how to remediate and failing the build in case if it is detected.
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'bash'
    args: 
      - '-c' 
      - |
        if grep -q '"severity": "Critical"' report.json; then
          echo "Critical vulnerabilities found. Build failed.";
          echo "To remediate vulnerabilities:";
          echo "1. Review the 'scan_report.json' for detailed vulnerability information.";
          echo "2. Identify the affected software packages or libraries.";
          echo "3. Consult the official vulnerability database for each vulnerability:";
          echo "   - For Debian/Ubuntu: https://security-tracker.debian.org/tracker/";
          echo "   - For CentOS/Red Hat: https://access.redhat.com/security/vulnerabilities/";
          echo "   - For Python packages: https://nvd.nist.gov/vuln/search";
          # Provide guidance on applying fixes based on the vulnerabilities
          echo "4. Determine if patches, upgrades, or changes to code/configuration are needed.";
          echo "   - Apply patches provided by the vendor.";
          echo "   - Upgrade to a non-vulnerable version.";
          echo "   - Modify code/configuration to mitigate the vulnerability.";
          echo "5. Apply necessary fixes, patches, or updates as per vendor recommendations.";
          echo "   - Follow best practices for security updates in your specific technology stack.";
          echo "6. Rebuild the Docker image with the fixes applied.";
          echo "   - Update your Dockerfile or code to include the patched versions.";
          echo "   - Perform necessary testing to ensure the changes don't introduce new issues.";
          echo "7. Re-scan the image using Clair to confirm that vulnerabilities are resolved.";
          echo "   - If vulnerabilities are still detected, review your remediation steps.";
          # If all vulnerabilities are remediated, allow the build to pass
          echo "8. Once all vulnerabilities are remediated, rebuild the image and scan again.";
          echo "   - If no critical vulnerabilities are detected, the build will pass.";
          exit 1;
        else
          echo "No critical vulnerabilities found. Build passed.";
        fi
        
  # Step 4: Push the scanned image to Artifact Registry   
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'us-central1-docker.pkg.dev/mcmp-integration-qa/clair-scan-repo/appimage:latest']

  # Step 5: Store the scan report in a GCS bucket
  - name: 'gcr.io/cloud-builders/gsutil'
    args: ['cp', 'report.json', 'gs://clair_scan_report_bucket/report.json']
