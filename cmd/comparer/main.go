package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/crane"
	"gopkg.in/yaml.v2"
)

type AppConfig struct {
	URL           string `yaml:"url"`
	Regex         string `yaml:"regex"`
	Bitnami       string `yaml:"bitnami"`
	BitnamiSecure string `yaml:"bitnamisecure"`
	CG            string `yaml:"cg"`
}

type TrivyResult struct {
	Results []struct {
		Vulnerabilities []struct {
			Severity string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type GrypeResult struct {
	Matches []struct {
		Vulnerability struct {
			Severity string `json:"severity"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

func main() {
	log.Println("Reading config.yaml...")
	configData, err := os.ReadFile("config.yaml")
	checkErr(err)

	config := map[string]AppConfig{}
	checkErr(yaml.Unmarshal(configData, &config))

	for appName, appConf := range config {
		log.Printf("Processing app '%s'...\n", appName)

		log.Printf("Fetching tags page from URL: %s\n", appConf.URL)
		resp, err := http.Get(appConf.URL)
		checkErr(err)
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		checkErr(err)

		re, err := regexp.Compile(appConf.Regex)
		checkErr(err)

		matches := re.FindAllStringSubmatch(string(body), -1)

		var rawVersions []string
		for _, m := range matches {
			if len(m) > 1 {
				rawVersions = append(rawVersions, m[1])
			}
		}

		var semVersions []*semver.Version
		for _, v := range rawVersions {
			v = strings.TrimPrefix(v, "v")
			if strings.Count(v, ".") < 2 {
				continue
			}
			ver, err := semver.NewVersion(v)
			if err != nil || ver.Prerelease() != "" {
				continue
			}
			semVersions = append(semVersions, ver)
		}

		if len(semVersions) == 0 {
			log.Printf("No valid stable versions found for %s\n", appName)
			continue
		}

		sort.Sort(sort.Reverse(semver.Collection(semVersions)))
		latest := semVersions[0].String()
		log.Printf("Latest stable version found: %s\n", latest)

		images := make(map[string]interface{})
		imageMap := map[string]string{
			"bitnami":       appConf.Bitnami,
			"bitnamisecure": appConf.BitnamiSecure,
			"cg":            appConf.CG,
		}

		for key, ref := range imageMap {
			if ref == "" {
				log.Printf("Skipping empty image reference for key '%s'\n", key)
				continue
			}
			log.Printf("===== Processing %s =====", key)
			log.Printf("Fetching manifest list for image '%s' (%s)...", key, ref)
			manifestList, err := crane.Manifest(ref)
			if err != nil {
				log.Printf("Failed to get manifest list for %s: %v\n", ref, err)
				continue
			}

			var index struct {
				Manifests []struct {
					Digest   string `json:"digest"`
					Platform struct {
						Architecture string `json:"architecture"`
						OS           string `json:"os"`
					} `json:"platform"`
				} `json:"manifests"`
			}

			if err := json.Unmarshal([]byte(manifestList), &index); err != nil {
				log.Printf("Failed to parse manifest list for %s: %v\n", ref, err)
				continue
			}

			archInfo := map[string]interface{}{}

			for _, m := range index.Manifests {
				if m.Platform.OS != "linux" {
					continue
				}
				log.Printf("Pulling image for arch '%s' with digest %s...", m.Platform.Architecture, m.Digest)
				platRef := fmt.Sprintf("%s@%s", ref, m.Digest)
				img, err := crane.Pull(platRef)
				if err != nil {
					log.Printf("Failed to pull image %s: %v\n", platRef, err)
					continue
				}

				manifest, err := img.Manifest()
				if err != nil {
					log.Printf("Failed to get manifest for %s: %v\n", platRef, err)
					continue
				}

				var size int64 = 0
				for _, layer := range manifest.Layers {
					size += layer.Size
				}

				arch := m.Platform.Architecture
				sizeMb := fmt.Sprintf("%.2f", float64(size)/1024/1024)
				log.Printf("Image size for arch '%s': %s MB\n", arch, sizeMb)

				archInfo[arch] = map[string]string{
					"size_mb": sizeMb,
				}
			}

			log.Printf("Running Grype scan for image '%s'...", ref)
			grypeCounts, err := scanGrype(ref)
			if err != nil {
				log.Printf("Grype scan failed for %s: %v\n", ref, err)
				grypeCounts = map[string]string{"critical": "0", "high": "0", "medium": "0", "low": "0"}
			}

			log.Printf("Running Trivy scan for image '%s'...", ref)
			trivyCounts, err := scanTrivy(ref)
			if err != nil {
				log.Printf("Trivy scan failed for %s: %v\n", ref, err)
				trivyCounts = map[string]string{"critical": "0", "high": "0", "medium": "0", "low": "0"}
			}

			archInfo["grype"] = grypeCounts
			archInfo["trivy"] = trivyCounts

			images[key] = archInfo
		}

		output := map[string]interface{}{
			"upstream": map[string]string{
				"version": latest,
			},
			"images": images,
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		checkErr(err)

		err = os.MkdirAll("data", 0755)
		checkErr(err)

		outPath := filepath.Join("data", fmt.Sprintf("%s.json", appName))
		checkErr(os.WriteFile(outPath, jsonData, 0644))

		log.Printf("✅ %s processed successfully. JSON saved to %s\n", appName, outPath)
	}
}

func scanTrivy(image string) (map[string]string, error) {
	cmd := exec.Command("trivy", "image", "--quiet", "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--format", "json", image)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var result TrivyResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return nil, err
	}

	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				counts["critical"]++
			case "high":
				counts["high"]++
			case "medium":
				counts["medium"]++
			case "low":
				counts["low"]++
			}
		}
	}

	return intMapToStrMap(counts), nil
}

func scanGrype(image string) (map[string]string, error) {
	cmd := exec.Command("grype", image, "-o", "json")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var result GrypeResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return nil, err
	}

	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, match := range result.Matches {
		switch strings.ToLower(match.Vulnerability.Severity) {
		case "critical":
			counts["critical"]++
		case "high":
			counts["high"]++
		case "medium":
			counts["medium"]++
		case "low":
			counts["low"]++
		}
	}

	return intMapToStrMap(counts), nil
}

func intMapToStrMap(m map[string]int) map[string]string {
	res := make(map[string]string)
	for k, v := range m {
		res[k] = fmt.Sprintf("%d", v)
	}
	return res
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
