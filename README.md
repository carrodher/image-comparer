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
  "upstream": {
    "version": "24.0.1",
    "release_date": "2025-04-15T00:00:00Z"
  },
  "images": {
    "bitnami": {
      "version_inside": "24.0.1",
      "days_delay": 7,
      "amd64": {
        "size_mb": "302.44"
      },
      "arm64": {
        "size_mb": "281.24"
      },
      "grype": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      },
      "trivy": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
      }
    },
    ...
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
```
go run cmd/comparer/main.go
```

- Inspect output JSON files:
```
cat java.json | jq .
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
