//go:build spc

package spc

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/asscor/asscor/internal/kernel"
	"strconv"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

func (m *Module) ImportOSCAL(data []byte, format string) (int, error) {
	var records []kernel.SPCVulnerabilityRecord

	switch strings.ToLower(format) {
	case "json":
		if err := json.Unmarshal(data, &records); err != nil {
			var wrapper struct {
				Findings []kernel.SPCVulnerabilityRecord `json:"findings"`
			}
			if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
				return 0, err
			}
			records = wrapper.Findings
		}
	case "yaml", "yml":
		parsed, err := parseOSCALYAML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL YAML parse: %w", err)
		}
		records = parsed
	case "xml":
		parsed, err := parseOSCALXML(data)
		if err != nil {
			return 0, fmt.Errorf("OSCAL XML parse: %w", err)
		}
		records = parsed
	default:
		return 0, fmt.Errorf("unknown OSCAL format: %s (supported: json, yaml, xml)", format)
	}

	added := 0
	updated := 0
	m.mu.Lock()
	for _, rec := range records {
		if len(m.cveCache) >= m.maxCacheSize {
			logger.WithComponent("spc").Warn("CVE cache reached max size during OSCAL import", "max", m.maxCacheSize, "imported", added)
			break
		}
		pubDate, _ := time.Parse("2006-01-02", rec.DatePublished)
		modDate, _ := time.Parse("2006-01-02", rec.DateModified)

		cve := kernel.SPCCVEScore{
			CVEID:            rec.CVEID,
			Description:      rec.Description,
			CVSS:             rec.CVSSScore,
			CVSSVector:       rec.CVSSVector,
			EPSS:             rec.EPSSScore,
			EPSSPercent:      rec.EPSSPercent,
			InKEV:            rec.InKEV,
			DatePublished:    pubDate,
			DateModified:     modDate,
			AffectedCPEs:     rec.AffectedCPEs,
			AttckTechniques:  rec.AttckTechniques,
			MISPGalaxyTags:   rec.MISPGalaxyTags,
			OSCALFindingUUID: rec.OSCALFindingUUID,
			APTGroupAssoc:    rec.APTGroupAssoc,
		}

		if idx, exists := m.cveIndex[cve.CVEID]; exists {
			m.mergeCVEInPlace(idx, cve)
			updated++
		} else {
			m.cveIndex[cve.CVEID] = len(m.cveCache)
			m.cveCache = append(m.cveCache, cve)
			added++
		}
	}
	m.mu.Unlock()

	logger.WithComponent("spc").Info("OSCAL import completed", "format", format, "added", added, "updated", updated)
	return added, nil
}

func parseOSCALYAML(data []byte) ([]kernel.SPCVulnerabilityRecord, error) {
	var records []kernel.SPCVulnerabilityRecord
	text := strings.TrimSpace(string(data))

	if strings.HasPrefix(text, "---") {
		text = strings.TrimPrefix(text, "---")
		text = strings.TrimSpace(text)
	}

	lines := strings.Split(text, "\n")
	var currentRecord *kernel.SPCVulnerabilityRecord
	var inFindings bool
	var inFinding bool
	var listKey string
	var listItems []string

	flushRecord := func() {
		if currentRecord != nil && currentRecord.CVEID != "" {
			switch listKey {
			case "affected_cpes":
				currentRecord.AffectedCPEs = listItems
			case "attck_techniques":
				currentRecord.AttckTechniques = listItems
			case "misp_galaxy_tags":
				currentRecord.MISPGalaxyTags = listItems
			case "apt_group_assoc":
				currentRecord.APTGroupAssoc = listItems
			}
			records = append(records, *currentRecord)
		}
		currentRecord = nil
		listKey = ""
		listItems = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := 0
		for _, ch := range line {
			if ch == ' ' {
				indent++
			} else {
				break
			}
		}

		if indent == 0 && strings.HasPrefix(trimmed, "findings:") {
			inFindings = true
			inFinding = false
			continue
		}

		if indent == 0 && !strings.HasPrefix(trimmed, "findings:") {
			inFindings = false
			inFinding = false
			flushRecord()
			continue
		}

		if inFindings && indent == 2 && strings.HasSuffix(trimmed, ":") {
			flushRecord()
			currentRecord = &kernel.SPCVulnerabilityRecord{}
			inFinding = true
			listKey = ""
			listItems = nil
			continue
		}

		if inFinding && currentRecord != nil {
			if strings.HasPrefix(trimmed, "- ") {
				item := strings.TrimPrefix(trimmed, "- ")
				item = strings.Trim(item, "\"")
				if listKey != "" {
					listItems = append(listItems, item)
				}
				continue
			}

			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, "\"")

				if listKey != "" && key != listKey {
					switch listKey {
					case "affected_cpes":
						currentRecord.AffectedCPEs = listItems
					case "attck_techniques":
						currentRecord.AttckTechniques = listItems
					case "misp_galaxy_tags":
						currentRecord.MISPGalaxyTags = listItems
					case "apt_group_assoc":
						currentRecord.APTGroupAssoc = listItems
					}
					listKey = ""
					listItems = nil
				}

				if val == "" {
					switch key {
					case "affected_cpes", "attck_techniques", "misp_galaxy_tags", "apt_group_assoc":
						listKey = key
						listItems = nil
					}
					continue
				}

				switch key {
				case "cve_id":
					currentRecord.CVEID = val
				case "description":
					currentRecord.Description = val
				case "cvss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.CVSSScore = f
					}
				case "cvss_vector":
					currentRecord.CVSSVector = val
				case "epss_score":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSScore = f
					}
				case "epss_percentile":
					if f, err := parseFloat(val); err == nil {
						currentRecord.EPSSPercent = f
					}
				case "in_kev":
					currentRecord.InKEV = strings.EqualFold(val, "true") || val == "1"
				case "date_published":
					currentRecord.DatePublished = val
				case "date_modified":
					currentRecord.DateModified = val
				case "oscal_finding_uuid":
					currentRecord.OSCALFindingUUID = val
				}
			}
		}
	}

	flushRecord()

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in YAML")
	}

	return records, nil
}

func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	return strconv.ParseFloat(s, 64)
}

type oscalXMLRoot struct {
	XMLName  struct{}         `xml:"oscal"`
	Findings oscalXMLFindings `xml:"findings"`
}

type oscalXMLFindings struct {
	Finding []oscalXMLFinding `xml:"finding"`
}

type oscalXMLFinding struct {
	CVEID         string  `xml:"cve_id"`
	Description   string  `xml:"description"`
	CVSSScore     float64 `xml:"cvss_score"`
	CVSSVector    string  `xml:"cvss_vector"`
	EPSSScore     float64 `xml:"epss_score"`
	EPSSPercent   float64 `xml:"epss_percentile"`
	InKEV         bool    `xml:"in_kev"`
	DatePublished string  `xml:"date_published"`
	DateModified  string  `xml:"date_modified"`
	AffectedCPEs  struct {
		CPE []string `xml:"cpe"`
	} `xml:"affected_cpes"`
	AttckTechniques struct {
		Technique []string `xml:"technique"`
	} `xml:"attck_techniques"`
	MISPGalaxyTags struct {
		Tag []string `xml:"tag"`
	} `xml:"misp_galaxy_tags"`
	OSCALFindingUUID string `xml:"oscal_finding_uuid"`
	APTGroupAssoc    struct {
		Group []string `xml:"group"`
	} `xml:"apt_group_assoc"`
}

func parseOSCALXML(data []byte) ([]kernel.SPCVulnerabilityRecord, error) {
	var root oscalXMLRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var records []kernel.SPCVulnerabilityRecord
	for _, f := range root.Findings.Finding {
		rec := kernel.SPCVulnerabilityRecord{
			CVEID:            f.CVEID,
			Description:      f.Description,
			CVSSScore:        f.CVSSScore,
			CVSSVector:       f.CVSSVector,
			EPSSScore:        f.EPSSScore,
			EPSSPercent:      f.EPSSPercent,
			InKEV:            f.InKEV,
			DatePublished:    f.DatePublished,
			DateModified:     f.DateModified,
			AffectedCPEs:     f.AffectedCPEs.CPE,
			AttckTechniques:  f.AttckTechniques.Technique,
			MISPGalaxyTags:   f.MISPGalaxyTags.Tag,
			OSCALFindingUUID: f.OSCALFindingUUID,
			APTGroupAssoc:    f.APTGroupAssoc.Group,
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid vulnerability records found in XML")
	}

	return records, nil
}
