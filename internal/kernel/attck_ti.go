package kernel

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/argus-security/argus/internal/logger"
)

func (m *ATTACKModule) AddIOC(entry IOCEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry.Type == "" || entry.Value == "" {
		return fmt.Errorf("IOC type and value must not be empty")
	}

	if entry.ID == "" {
		entry.ID = fmt.Sprintf("ioc-%d", time.Now().UnixNano())
	}

	if entry.FirstSeen.IsZero() {
		entry.FirstSeen = time.Now()
	}
	if entry.LastSeen.IsZero() {
		entry.LastSeen = time.Now()
	}

	for i, existing := range m.iocs {
		if existing.Type == entry.Type && existing.Value == entry.Value {
			m.iocs[i] = entry
			logger.WithComponent("attck.ti").Info("updated IOC", "type", entry.Type, "value", entry.Value)
			return nil
		}
	}

	m.iocs = append(m.iocs, entry)

	m.enrichTechniqueFromIOC(entry)

	logger.WithComponent("attck.ti").Info("added IOC", "id", entry.ID, "type", entry.Type, "value", entry.Value)
	return nil
}

func (m *ATTACKModule) enrichTechniqueFromIOC(entry IOCEntry) {
	if len(entry.TechniqueIDs) == 0 {
		return
	}

	for _, techID := range entry.TechniqueIDs {
		for ti, tactic := range m.tactics {
			for tj, tech := range tactic.Techniques {
				if tech.ID == techID {
					found := false
					for _, check := range tech.ArgusChecks {
						if check == "ioc:"+entry.ID {
							found = true
							break
						}
					}
					if !found {
						m.tactics[ti].Techniques[tj].ArgusChecks = append(tech.ArgusChecks, "ioc:"+entry.ID)
					}
				}
			}
		}
	}
}

func (m *ATTACKModule) GetIOCs(iocType string, techniqueID string, limit int) []IOCEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []IOCEntry
	for _, ioc := range m.iocs {
		if iocType != "" && ioc.Type != iocType {
			continue
		}
		if techniqueID != "" {
			found := false
			for _, t := range ioc.TechniqueIDs {
				if t == techniqueID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		result = append(result, ioc)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func (m *ATTACKModule) SearchIOC(value string) []IOCEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []IOCEntry
	for _, ioc := range m.iocs {
		if ioc.Value == value {
			result = append(result, ioc)
		}
	}
	return result
}

func (m *ATTACKModule) DeleteIOC(iocID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, ioc := range m.iocs {
		if ioc.ID == iocID {
			m.iocs = append(m.iocs[:i], m.iocs[i+1:]...)
			logger.WithComponent("attck.ti").Info("deleted IOC", "id", iocID)
			return true
		}
	}
	return false
}

func (m *ATTACKModule) ExpireIOCs() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expired := 0
	var active []IOCEntry
	for _, ioc := range m.iocs {
		if !ioc.ExpiresAt.IsZero() && now.After(ioc.ExpiresAt) {
			expired++
			continue
		}
		active = append(active, ioc)
	}
	m.iocs = active

	if expired > 0 {
		logger.WithComponent("attck.ti").Info("expired IOCs removed", "count", expired)
	}
	return expired
}

func (m *ATTACKModule) UpsertThreatActor(profile ThreatActorProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if profile.ID == "" || profile.Name == "" {
		return fmt.Errorf("threat actor ID and name must not be empty")
	}

	profile.LastUpdated = time.Now()
	m.threatActors[profile.ID] = profile

	logger.WithComponent("attck.ti").Info("upserted threat actor", "id", profile.ID, "name", profile.Name)
	return nil
}

func (m *ATTACKModule) GetThreatActor(actorID string) *ThreatActorProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if p, ok := m.threatActors[actorID]; ok {
		return &p
	}
	return nil
}

func (m *ATTACKModule) ListThreatActors() []ThreatActorProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ThreatActorProfile, 0, len(m.threatActors))
	for _, p := range m.threatActors {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func (m *ATTACKModule) MatchThreatActor(detectedTechniques []string) []APTMatchResult {
	return m.MatchAPTGroup(detectedTechniques)
}

func (m *ATTACKModule) AddTTPTrack(track TTPTrack) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if track.TechniqueID == "" {
		return fmt.Errorf("TTP track must reference a technique ID")
	}

	if track.ID == "" {
		track.ID = fmt.Sprintf("ttp-%d", time.Now().UnixNano())
	}
	if track.FirstSeen.IsZero() {
		track.FirstSeen = time.Now()
	}
	if track.LastSeen.IsZero() {
		track.LastSeen = time.Now()
	}

	for i, t := range m.ttpTracks {
		if t.ID == track.ID {
			m.ttpTracks[i] = track
			return nil
		}
	}

	m.ttpTracks = append(m.ttpTracks, track)

	logger.WithComponent("attck.ti").Info("added TTP track", "id", track.ID, "technique", track.TechniqueID)
	return nil
}

func (m *ATTACKModule) GetTTPTracks(actorID, techniqueID string) []TTPTrack {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []TTPTrack
	for _, t := range m.ttpTracks {
		if actorID != "" && t.ActorID != actorID {
			continue
		}
		if techniqueID != "" && t.TechniqueID != techniqueID {
			continue
		}
		result = append(result, t)
	}
	return result
}

func (m *ATTACKModule) EnrichAlertWithTI(alertID string) (*DetectionAlert, map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var alert *DetectionAlert
	for i := range m.alerts {
		if m.alerts[i].ID == alertID {
			alert = &m.alerts[i]
			break
		}
	}
	if alert == nil {
		return nil, nil
	}

	enrichment := make(map[string]interface{})

	var relatedIOCs []IOCEntry
	for _, ioc := range m.iocs {
		for _, tid := range ioc.TechniqueIDs {
			if tid == alert.TechniqueID {
				relatedIOCs = append(relatedIOCs, ioc)
			}
		}
	}
	if len(relatedIOCs) > 0 {
		enrichment["related_iocs"] = relatedIOCs
	}

	var relatedActors []ThreatActorProfile
	for _, actor := range m.threatActors {
		if _, ok := actor.Techniques[alert.TechniqueID]; ok {
			relatedActors = append(relatedActors, actor)
		}
	}
	if len(relatedActors) > 0 {
		enrichment["related_actors"] = relatedActors
	}

	var relatedTTPs []TTPTrack
	for _, t := range m.ttpTracks {
		if t.TechniqueID == alert.TechniqueID {
			relatedTTPs = append(relatedTTPs, t)
		}
	}
	if len(relatedTTPs) > 0 {
		enrichment["related_ttps"] = relatedTTPs
	}

	predictedPaths := m.predictFromTechnique(alert.TechniqueID, 2)
	if len(predictedPaths) > 0 {
		enrichment["predicted_next_techniques"] = predictedPaths
	}

	return alert, enrichment
}

func (m *ATTACKModule) predictFromTechnique(techID string, maxDepth int) []PredictedPath {
	transitions, ok := m.transMatrix[techID]
	if !ok {
		return nil
	}

	var paths []PredictedPath
	for nextTech, prob := range transitions {
		paths = append(paths, PredictedPath{
			Path:        []string{techID, nextTech},
			Probability: prob,
			EndTech:     nextTech,
			Risk:        prob,
		})

		if maxDepth > 1 {
			nextTrans, ok := m.transMatrix[nextTech]
			if ok {
				for nextNext, nextProb := range nextTrans {
					combined := prob * nextProb
					paths = append(paths, PredictedPath{
						Path:        []string{techID, nextTech, nextNext},
						Probability: math.Round(combined*1000) / 1000,
						EndTech:     nextNext,
						Risk:        combined,
					})
				}
			}
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Probability > paths[j].Probability
	})

	if len(paths) > 5 {
		paths = paths[:5]
	}

	return paths
}

func (m *ATTACKModule) GetTISummary() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	iocsByType := make(map[string]int)
	for _, ioc := range m.iocs {
		iocsByType[ioc.Type]++
	}

	actorsByMotivation := make(map[string]int)
	for _, actor := range m.threatActors {
		m := actor.Motivation
		if m == "" {
			m = "unknown"
		}
		actorsByMotivation[m]++
	}

	ttpsByTactic := make(map[string]int)
	for _, t := range m.ttpTracks {
		ttpsByTactic[t.TacticID]++
	}

	return map[string]interface{}{
		"total_iocs":          len(m.iocs),
		"iocs_by_type":        iocsByType,
		"total_threat_actors": len(m.threatActors),
		"actors_by_motivation": actorsByMotivation,
		"total_ttp_tracks":    len(m.ttpTracks),
		"ttps_by_tactic":      ttpsByTactic,
		"attck_version":       m.attckVersion,
	}
}

func (m *ATTACKModule) loadDefaultThreatActors() {
	m.threatActors = map[string]ThreatActorProfile{
		"TA-APT29": {
			ID: "TA-APT29", Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"},
			Description: "Russian threat group targeting government and diplomatic organizations.",
			Country: "Russia", Motivation: "espionage",
			TargetSectors: []string{"government", "diplomatic", "think_tank"},
			Techniques: map[string]float64{
				"T1566": 0.9, "T1071": 0.8, "T1003": 0.85, "T1059": 0.7,
				"T1133": 0.6, "T1055": 0.5, "T1485": 0.3, "T1070": 0.6,
			},
			Software: []string{"S0045", "S0132"},
			Campaigns: []CampaignInfo{
				{ID: "C001", Name: "Operation Ghost", Description: "Targeting diplomatic entities", Techniques: []string{"T1566", "T1071", "T1003"}},
			},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"APT 29\"",
			LastUpdated: time.Now(),
		},
		"TA-APT41": {
			ID: "TA-APT41", Name: "APT41", Aliases: []string{"Wicked Spider", "Double Dragon"},
			Description: "Chinese threat group conducting both espionage and financially motivated operations.",
			Country: "China", Motivation: "espionage+financial",
			TargetSectors: []string{"multi_industry", "healthcare", "telecom"},
			Techniques: map[string]float64{
				"T1190": 0.95, "T1059": 0.8, "T1021": 0.7, "T1003": 0.6,
				"T1566": 0.8, "T1574": 0.5, "T1505": 0.6,
			},
			Software: []string{"S0069", "S0200"},
			Campaigns: []CampaignInfo{
				{ID: "C002", Name: "Operation Soft Cell", Description: "Telecom sector targeting", Techniques: []string{"T1190", "T1059", "T1021"}},
			},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"APT 41\"",
			LastUpdated: time.Now(),
		},
		"TA-Lazarus": {
			ID: "TA-Lazarus", Name: "Lazarus Group", Aliases: []string{"HIDDEN COBRA", "Zinc"},
			Description: "North Korean state-sponsored group targeting financial institutions and cryptocurrency exchanges.",
			Country: "North Korea", Motivation: "financial+espionage",
			TargetSectors: []string{"financial", "cryptocurrency", "defense"},
			Techniques: map[string]float64{
				"T1566": 0.85, "T1190": 0.9, "T1059": 0.75, "T1486": 0.8,
				"T1021": 0.6, "T1078": 0.5, "T1498": 0.4,
			},
			Software: []string{"S0089", "S0143"},
			Campaigns: []CampaignInfo{
				{ID: "C003", Name: "Operation AppleJeus", Description: "Cryptocurrency targeting", Techniques: []string{"T1566", "T1190", "T1486"}},
			},
			MISPGalaxyID: "misp-galaxy:threat-actor=\"Lazarus Group\"",
			LastUpdated: time.Now(),
		},
	}
}
