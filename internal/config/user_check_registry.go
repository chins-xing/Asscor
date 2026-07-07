package config

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/asscor/asscor/internal/checks"
	"github.com/asscor/asscor/internal/model"
)

var registered = make(map[string]bool)

func RegisterUserChecks(cfg *Config) {
	if cfg == nil {
		return
	}

	type entry struct {
		id, domain, name, desc, command, outputMatch, filePath, fileRegex string
		delta                                                             float64
	}
	entries := make(map[string]*entry)

	for k, v := range cfg.AdapterConfig {
		if !strings.HasPrefix(k, "user_check.") {
			continue
		}
		parts := strings.SplitN(k, ".", 3)
		if len(parts) < 3 {
			continue
		}
		suffix := parts[1]
		field := parts[2]

		e, ok := entries[suffix]
		if !ok {
			e = &entry{}
			entries[suffix] = e
		}

		switch field {
		case "id":
			e.id = v
		case "domain":
			e.domain = v
		case "name":
			e.name = v
		case "description":
			e.desc = v
		case "command":
			e.command = v
		case "output_match":
			e.outputMatch = v
		case "file_path":
			e.filePath = v
		case "file_regex":
			e.fileRegex = v
		case "delta":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				e.delta = f
			}
		}
	}

	for _, e := range entries {
		if e.id == "" || e.domain == "" || e.name == "" {
			continue
		}
		if e.command == "" && e.filePath == "" {
			continue
		}
		if registered[e.id] {
			continue
		}

		item := model.CheckItem{
			ID:          e.id,
			Domain:      e.domain,
			Name:        e.name,
			Description: e.desc,
			Delta:       e.delta,
		}

		if e.command != "" {
			cmd := e.command
			match := e.outputMatch
			item.Check = func() (bool, string) {
				out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
				if err != nil {
					return false, fmt.Sprintf("command failed: %v (output: %s)", err, strings.TrimSpace(string(out)))
				}
				if match != "" {
					if strings.Contains(string(out), match) {
						return true, fmt.Sprintf("output matched: %s", match)
					}
					return false, fmt.Sprintf("output did not contain: %s", match)
				}
				return true, "command succeeded"
			}
		} else if e.filePath != "" {
			path := e.filePath
			reStr := e.fileRegex
			item.Check = func() (bool, string) {
				data, err := os.ReadFile(path)
				if err != nil {
					return false, fmt.Sprintf("cannot read %s: %v", path, err)
				}
				if reStr == "" {
					return true, fmt.Sprintf("file %s exists (%d bytes)", path, len(data))
				}
				re, err := regexp.Compile(reStr)
				if err != nil {
					return false, fmt.Sprintf("invalid regex: %v", err)
				}
				if re.Match(data) {
					return true, fmt.Sprintf("file %s matches pattern", path)
				}
				return false, fmt.Sprintf("file %s does not match pattern", path)
			}
		}

		checks.Register(item)
		registered[e.id] = true
	}
}
