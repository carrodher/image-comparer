# Upstream Version & Image Scanner

This Go tool automates tracking of upstream software versions and evaluates corresponding container images (e.g., from Bitnami Secure and Chainguard). It collects:
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
    "bitnamisecure": {
      "amd64": {
        "size_mb": "101.57"
      },
      "arm64": {
        "size_mb": "84.97"
      },
      "detected_version": "24.0.1",
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
2025/07/08 18:26:27 Reading config.yaml...
2025/07/08 18:26:27 Processing app 'java'...
2025/07/08 18:26:28 Latest stable version found: 24.0.1
2025/07/08 18:26:28 Fetching manifest list for image 'bitnamisecure' (docker.io/bitnamisecure/java-min)...
2025/07/08 18:26:32 Pulling image for arch 'amd64' with digest sha256:2c99987f9b810f0b9b0d0baff00fb328d6afe2d4f351f3550cb7f477fe012624...
2025/07/08 18:26:33 Image size for arch 'amd64': 101.57 MB
2025/07/08 18:26:33 Pulling image for arch 'arm64' with digest sha256:543c3c6e7989ba16b111bb1db6be7f8d1eca97ad479b285253997cc8ea257bfc...
2025/07/08 18:26:33 Image size for arch 'arm64': 84.97 MB
2025/07/08 18:26:33 Running Grype scan for image 'docker.io/bitnamisecure/java-min'...
2025/07/08 18:26:51 Running Trivy scan for image 'docker.io/bitnamisecure/java-min'...
2025/07/08 18:28:02 Extracting version from container 'docker.io/bitnamisecure/java-min'...
2025/07/08 18:28:03 Detected version: 24.0.1
2025/07/08 18:28:03 Fetching manifest list for image 'cg' (cgr.dev/chainguard/jdk)...
2025/07/08 18:28:04 Pulling image for arch 'amd64' with digest sha256:e850c46647bab196aa9530c360dce598f386b25ee328fb6a85ca14959f20259e...
2025/07/08 18:28:05 Image size for arch 'amd64': 133.95 MB
2025/07/08 18:28:05 Pulling image for arch 'arm64' with digest sha256:5412abc1d16d5fcf0364fb4c4f7f59b12b3b09198254f17a0f62d6934a469f89...
2025/07/08 18:28:06 Image size for arch 'arm64': 131.75 MB
2025/07/08 18:28:06 Running Grype scan for image 'cgr.dev/chainguard/jdk'...
2025/07/08 18:28:23 Running Trivy scan for image 'cgr.dev/chainguard/jdk'...
2025/07/08 18:28:23 Extracting version from container 'cgr.dev/chainguard/jdk'...
2025/07/08 18:28:23 Detected version: 24.0.1
2025/07/08 18:28:23 ✅ java processed successfully. JSON saved to data/java.json
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
- Runs a version command inside each image and compares it with upstream.
- Computes the delay in days between upstream and container availability.
- Writes all data to APPNAME.json.
