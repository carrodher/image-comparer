# Upstream Version & Image Scanner

This Go tool automates tracking of upstream software versions and evaluates corresponding container images (e.g. from Bitnami, Bitnami Secure, and Chainguard). It collects:
- **Latest upstream version and release date**
- **Container size per architecture**
- **Security scan results (Grype & Trivy)**
- **Version reported inside each image**
- **Delay in days from upstream release to image availability**

Each application is defined in `config.yaml` and results are stored in per-app `.json` files.

## Example Output (`java.json`)

```json
{
  "images": {
    "bitnami": {
      "amd64": {
        "size_mb": "302.44"
      },
      "arm64": {
        "size_mb": "281.24"
      },
      "detected_version": "24.0.1",
      "grype": {
        "critical": "0",
        "high": "17",
        "low": "9",
        "medium": "20"
      },
      "trivy": {
        "critical": "1",
        "high": "16",
        "low": "106",
        "medium": "20"
      }
    },
    "bitnamisecure": {
      "amd64": {
        "size_mb": "101.57"
      },
      "arm64": {
        "size_mb": "84.97"
      },
      "detected_version": "24",
      "grype": {
        "critical": "0",
        "high": "0",
        "low": "0",
        "medium": "0"
      },
      "trivy": {
        "critical": "0",
        "high": "0",
        "low": "0",
        "medium": "0"
      }
    },
    "cg": {
      "amd64": {
        "size_mb": "133.95"
      },
      "arm64": {
        "size_mb": "131.75"
      },
      "detected_version": "24.0.1",
      "grype": {
        "critical": "0",
        "high": "0",
        "low": "2",
        "medium": "0"
      },
      "trivy": {
        "critical": "0",
        "high": "0",
        "low": "0",
        "medium": "0"
      }
    }
  },
  "upstream": {
    "version": "24.0.1"
  }
}
```

## Prerequisites

Ensure the following tools are installed and available in your `$PATH`:
- [Go](https://github.com/golang/go)
- [Docker](https://www.docker.com/get-started/)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Grype](https://github.com/anchore/grype)
- [jq](https://github.com/jqlang/jq) (optional, for inspecting JSON)

## How to use

- Clone the repo:
```
git clone https://github.com/carrodher/image-comparer
cd image-comparer
```

- Define applications in config.yaml:
```yaml
java:
  url: https://github.com/bell-sw/Liberica/tags
  regex: /tag/([0-9A-Za-z.\-_]+)
  bitnami:
    image: docker.io/bitnami/java
    command: "java --version"
    regex: "openjdk ([0-9.]+)"
  bitnamisecure:
    image: docker.io/bitnamisecure/java-min
    command: "--version"
    regex: "openjdk ([0-9.]+)"
  cg:
    image:  cgr.dev/chainguard/jdk
    command: "javac --version"
    regex: "javac ([0-9.]+)"
```

- Run the tool:
```console
$ go run cmd/comparer/main.go
2025/07/05 20:12:02 Reading config.yaml...
2025/07/05 20:12:02 Processing app 'java'...
2025/07/05 20:12:03 Latest stable version found: 24.0.1
2025/07/05 20:12:03 Fetching manifest list for image 'bitnami' (docker.io/bitnami/java:latest)...
2025/07/05 20:12:05 Pulling image for arch 'amd64' with digest sha256:6e659dbbdb7aba26a9cb4e911c5cb9b40596fc74d5d61a1ccf2d6e065fcbeaa9...
2025/07/05 20:12:06 Image size for arch 'amd64': 302.44 MB
2025/07/05 20:12:06 Pulling image for arch 'arm64' with digest sha256:f395ca905ab2ae84e10be5069248a52bed476465b3e2b4d8322ed066148588e0...
2025/07/05 20:12:07 Image size for arch 'arm64': 281.24 MB
2025/07/05 20:12:07 Running Grype scan for image 'docker.io/bitnami/java:latest'...
2025/07/05 20:12:23 Running Trivy scan for image 'docker.io/bitnami/java:latest'...
2025/07/05 20:12:23 Extracting version from container 'docker.io/bitnami/java:latest'...
2025/07/05 20:12:24 Detected version: 24.0.1
2025/07/05 20:12:24 Fetching manifest list for image 'bitnamisecure' (docker.io/bitnamisecure/java-min:latest)...
2025/07/05 20:12:26 Pulling image for arch 'amd64' with digest sha256:20585180c180c5f81d90a0e60a870a9b57e4acecdd834f9cfa27dd5ca1c769b3...
2025/07/05 20:12:27 Image size for arch 'amd64': 101.57 MB
2025/07/05 20:12:27 Pulling image for arch 'arm64' with digest sha256:2f1f0e79607780220550256a2e89f639887663b7cc0d7cdaf38b8beeee445105...
2025/07/05 20:12:27 Image size for arch 'arm64': 84.97 MB
2025/07/05 20:12:27 Running Grype scan for image 'docker.io/bitnamisecure/java-min:latest'...
2025/07/05 20:12:33 Running Trivy scan for image 'docker.io/bitnamisecure/java-min:latest'...
2025/07/05 20:12:33 Fetching manifest list for image 'cg' (cgr.dev/chainguard/jdk:latest)...
2025/07/05 20:12:35 Pulling image for arch 'amd64' with digest sha256:e850c46647bab196aa9530c360dce598f386b25ee328fb6a85ca14959f20259e...
2025/07/05 20:12:35 Image size for arch 'amd64': 133.95 MB
2025/07/05 20:12:35 Pulling image for arch 'arm64' with digest sha256:5412abc1d16d5fcf0364fb4c4f7f59b12b3b09198254f17a0f62d6934a469f89...
2025/07/05 20:12:36 Image size for arch 'arm64': 131.75 MB
2025/07/05 20:12:36 Running Grype scan for image 'cgr.dev/chainguard/jdk:latest'...
2025/07/05 20:12:45 Running Trivy scan for image 'cgr.dev/chainguard/jdk:latest'...
2025/07/05 20:12:45 Extracting version from container 'cgr.dev/chainguard/jdk:latest'...
2025/07/05 20:12:45 Detected version: 24.0.1
2025/07/05 20:12:45 ✅ java processed successfully. JSON saved to data/java.json
```

- Inspect output JSON files:
```
cat data/java.json | jq .
```

## How it works

For each application:
- Scrapes upstream version & release date from the defined URL.
- Pulls the latest image for amd64 and arm64 platforms.
- Measures image size using Docker.
- Runs trivy and grype vulnerability scanners.
- Runs a version command inside each image and compares with upstream.
- Computes delay in days between upstream and container availability.
- Writes all data to APPNAME.json.
