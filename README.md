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
  bitnami: docker.io/bitnami/java:latest
  bitnamisecure: docker.io/bitnamisecure/java-min:latest
  cg: cgr.dev/chainguard/jdk:latest
  version_commands:
    bitnami: "java --version"
    bitnamisecure: "java --version"
    cg: "javac --version"
```

- Run the tool:
```console
$ go run cmd/comparer/main.go
2025/07/05 19:47:31 Reading config.yaml...
2025/07/05 19:47:31 Processing app 'java'...
2025/07/05 19:47:31 Fetching tags page from URL: https://github.com/bell-sw/Liberica/tags
2025/07/05 19:47:32 Latest stable version found: 24.0.1
2025/07/05 19:47:32 ===== Processing bitnamisecure =====
2025/07/05 19:47:32 Fetching manifest list for image 'bitnamisecure' (docker.io/bitnamisecure/java-min)...
2025/07/05 19:47:33 Pulling image for arch 'amd64' with digest sha256:20585180c180c5f81d90a0e60a870a9b57e4acecdd834f9cfa27dd5ca1c769b3...
2025/07/05 19:47:34 Image size for arch 'amd64': 101.57 MB
2025/07/05 19:47:34 Pulling image for arch 'arm64' with digest sha256:2f1f0e79607780220550256a2e89f639887663b7cc0d7cdaf38b8beeee445105...
2025/07/05 19:47:35 Image size for arch 'arm64': 84.97 MB
2025/07/05 19:47:35 Running Grype scan for image 'docker.io/bitnamisecure/java-min'...
2025/07/05 19:47:41 Running Trivy scan for image 'docker.io/bitnamisecure/java-min'...
2025/07/05 19:47:41 ===== Processing cg =====
2025/07/05 19:47:41 Fetching manifest list for image 'cg' (cgr.dev/chainguard/jdk)...
2025/07/05 19:47:42 Pulling image for arch 'amd64' with digest sha256:e850c46647bab196aa9530c360dce598f386b25ee328fb6a85ca14959f20259e...
2025/07/05 19:47:43 Image size for arch 'amd64': 133.95 MB
2025/07/05 19:47:43 Pulling image for arch 'arm64' with digest sha256:5412abc1d16d5fcf0364fb4c4f7f59b12b3b09198254f17a0f62d6934a469f89...
2025/07/05 19:47:44 Image size for arch 'arm64': 131.75 MB
2025/07/05 19:47:44 Running Grype scan for image 'cgr.dev/chainguard/jdk'...
2025/07/05 19:47:52 Running Trivy scan for image 'cgr.dev/chainguard/jdk'...
2025/07/05 19:47:52 ===== Processing bitnami =====
2025/07/05 19:47:52 Fetching manifest list for image 'bitnami' (docker.io/bitnami/java)...
2025/07/05 19:47:54 Pulling image for arch 'amd64' with digest sha256:6e659dbbdb7aba26a9cb4e911c5cb9b40596fc74d5d61a1ccf2d6e065fcbeaa9...
2025/07/05 19:47:55 Image size for arch 'amd64': 302.44 MB
2025/07/05 19:47:55 Pulling image for arch 'arm64' with digest sha256:f395ca905ab2ae84e10be5069248a52bed476465b3e2b4d8322ed066148588e0...
2025/07/05 19:47:56 Image size for arch 'arm64': 281.24 MB
2025/07/05 19:47:56 Running Grype scan for image 'docker.io/bitnami/java'...
2025/07/05 19:48:11 Running Trivy scan for image 'docker.io/bitnami/java'...
2025/07/05 19:48:11 ✅ java processed successfully. JSON saved to data/java.json
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
