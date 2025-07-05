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

type ImageConfig struct {
	Image   string `yaml:"image"`
	Command string `yaml:"command"`
	Regex   string `yaml:"regex"`
}

type AppConfig struct {
	URL           string      `yaml:"url"`
	Regex         string      `yaml:"regex"`
	Bitnami       ImageConfig `yaml:"bitnami"`
	BitnamiSecure ImageConfig `yaml:"bitnamisecure"`
	CG            ImageConfig `yaml:"cg"`
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
		log.Printf("Processing app '%s'...", appName)
		latest := fetchLatestVersion(appConf.URL, appConf.Regex)
		log.Printf("Latest stable version found: %s", latest)

		images := make(map[string]interface{})
		imageMap := map[string]ImageConfig{
			"bitnami":       appConf.Bitnami,
			"bitnamisecure": appConf.BitnamiSecure,
			"cg":            appConf.CG,
		}

		for key, imgConf := range imageMap {
			if imgConf.Image == "" {
				log.Printf("Skipping empty image reference for key '%s'", key)
				continue
			}

			ref := imgConf.Image + ":latest"
			log.Printf("Fetching manifest list for image '%s' (%s)...", key, ref)
			manifestList, err := crane.Manifest(ref)
			if err != nil {
				log.Printf("Failed to get manifest list for %s: %v", ref, err)
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
				log.Printf("Failed to parse manifest list for %s: %v", ref, err)
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
					log.Printf("Failed to pull image %s: %v", platRef, err)
					continue
				}

				manifest, err := img.Manifest()
				if err != nil {
					log.Printf("Failed to get manifest for %s: %v", platRef, err)
					continue
				}

				var size int64
				for _, layer := range manifest.Layers {
					size += layer.Size
				}

				arch := m.Platform.Architecture
				sizeMb := fmt.Sprintf("%.2f", float64(size)/1024/1024)
				log.Printf("Image size for arch '%s': %s MB", arch, sizeMb)

				archInfo[arch] = map[string]string{
					"size_mb": sizeMb,
				}
			}

			log.Printf("Running Grype scan for image '%s'...", ref)
			grypeCounts, _ := scanGrype(ref)
			log.Printf("Running Trivy scan for image '%s'...", ref)
			trivyCounts, _ := scanTrivy(ref)
			archInfo["grype"] = grypeCounts
			archInfo["trivy"] = trivyCounts

			if imgConf.Command != "" && imgConf.Regex != "" {
				log.Printf("Extracting version from container '%s'...", ref)
				version, err := extractVersionFromImage(imgConf.Image, imgConf.Command, imgConf.Regex)
				if err != nil {
					log.Printf("Failed to extract version from image %s: %v", imgConf.Image, err)
				} else {
					archInfo["detected_version"] = version
					log.Printf("Detected version: %s", version)
				}
			}

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
		log.Printf("✅ %s processed successfully. JSON saved to %s", appName, outPath)
	}
}

func extractVersionFromImage(image, cmdStr, regexStr string) (string, error) {
	parts := strings.Split(cmdStr, " ")
	args := append([]string{"run", "--rm", image}, parts...)
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}

	re := regexp.MustCompile(regexStr)
	matches := re.FindStringSubmatch(out.String())
	if len(matches) > 1 {
		return matches[1], nil
	}
	return "", fmt.Errorf("version not found in output")
}

func fetchLatestVersion(url, regexStr string) string {
	resp, err := http.Get(url)
	checkErr(err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)
	re, err := regexp.Compile(regexStr)
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
	
	    // Convert underscores to dots for ruby-like versions
	    v = strings.ReplaceAll(v, "_", ".")
	
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
		log.Fatal("No valid stable versions found")
	}
	sort.Sort(sort.Reverse(semver.Collection(semVersions)))
	return semVersions[0].String()
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
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
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
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
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
