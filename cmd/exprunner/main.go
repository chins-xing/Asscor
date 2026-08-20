//go:build expr

// Package main runs the ACL closed-loop experiment harness (E1-E8) against
// the Containerlab 18-node topology with Caldera/Atomic Red Team TTPs.
//
// Flow per round:
//  1. deploy decoyd (decoy daemon) inside the target container listening on
//     decoy ports (docker cp + docker exec),
//  2. trigger the attacker TTP via docker exec on the attacker container,
//     targeting the decoy ports on the target container,
//  3. collect decoy hits from the decoyd log + the executed TTP,
//  4. build attackerstate.Evidence and run the ACL closed loop,
//  5. append a JSONL record (distribution/sharpness/strategy/...).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/asscor/asscor/internal/attackerstate"
	"github.com/asscor/asscor/internal/defensecycle"
	"github.com/asscor/asscor/internal/engagement"
	"github.com/asscor/asscor/internal/predictor"
)

func dockerExec(container, cmd string) (string, error) {
	c := exec.Command("docker", "exec", container, "bash", "-c", cmd)
	out, err := c.CombinedOutput()
	return string(out), err
}

func dockerCP(src, container, dst string) error {
	c := exec.Command("docker", "cp", src, container+":"+dst)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// decoyHit mirrors cmd/decoyd's output.
type decoyHit struct {
	Port      int       `json:"port"`
	RemoteIP  string    `json:"remote_ip"`
	Timestamp time.Time `json:"timestamp"`
}

type RoundRecord struct {
	Round       int                      `json:"round"`
	Timestamp   time.Time                `json:"timestamp"`
	Evidence    []attackerstate.Evidence `json:"evidence"`
	Intent      string                   `json:"intent"`
	Exp         float64                  `json:"experience"`
	Knowledge   float64                  `json:"target_knowledge"`
	Dist        map[string]float64       `json:"distribution"`
	Sharpness   float64                  `json:"sharpness"`
	Strategy    string                   `json:"strategy"`
	Intervents  []engagement.Intervention `json:"interventions"`
	DecoyHits   []decoyHit               `json:"decoy_hits"`
	GroundTruth string                   `json:"ground_truth"`
	LatencyMs   int64                    `json:"latency_ms"`
}

type ttpStep struct {
	Name   string
	Intent string
	TTP    string
	Target string // target container (decoy host), e.g. asc-asscor-host2
	Attacker string // attacker container, e.g. asc-asscor-host1
	TargetIP string // target IP as seen from attacker
	Cmd    string // attacker command; %DECOYPORT% replaced per decoy port
	Ports  []int
}

var experimentMatrix = map[string][]ttpStep{
	"E1": {
		{Name: "recon-port-scan", Intent: "recon", TTP: "T1046",
			Target: "asc-asscor-host2", Attacker: "asc-asscor-host1", TargetIP: "10.10.2.10",
			Cmd: "for p in %DECOYPORT%; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/$p\" 2>/dev/null; done; echo SCAN-DONE",
			Ports: []int{22221, 22222, 22223, 22280, 22292, 26379}},
		{Name: "recon-active-scan", Intent: "recon", TTP: "T1595",
			Target: "asc-asscor-host2", Attacker: "asc-asscor-host1", TargetIP: "10.10.2.10",
			Cmd: "for p in %DECOYPORT%; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/$p\" 2>/dev/null; done; echo SCAN2-DONE",
			Ports: []int{22222, 22280, 23306, 25432, 227017}},
	},
	"E2": {
		{Name: "cred-bruteforce", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host2", Attacker: "asc-asscor-host1", TargetIP: "10.10.2.10",
			Cmd: "for i in 1 2 3 4 5; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo BRUTE-DONE",
			Ports: []int{22222}},
		{Name: "cred-dump", Intent: "credential", TTP: "T1003",
			Target: "asc-asscor-host2", Attacker: "asc-asscor-host1", TargetIP: "10.10.2.10",
			Cmd: "echo 'root:x:0:0:root:/root:/bin/bash' >> /tmp/fake-passwd; head -1 /tmp/fake-passwd; echo DUMP-DONE",
			Ports: nil},
	},
	"E3": {
		{Name: "lateral-ssh", Intent: "lateral", TTP: "T1021",
			Target: "asc-asscor-host3", Attacker: "asc-asscor-host1", TargetIP: "10.10.3.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo LAT-DONE",
			Ports: []int{22222}},
		{Name: "lateral-transfer", Intent: "lateral", TTP: "T1570",
			Target: "asc-asscor-host3", Attacker: "asc-asscor-host1", TargetIP: "10.10.3.10",
			Cmd: "echo 'payload' | timeout 2 bash -c \"cat > /dev/tcp/%TARGETIP%/23389\" 2>/dev/null; echo XFER-DONE",
			Ports: []int{23389}},
	},
	"E4": {
		{Name: "exfil-web", Intent: "data_theft", TTP: "T1567",
			Target: "asc-asscor-host4", Attacker: "asc-asscor-host1", TargetIP: "10.10.4.10",
			Cmd: "echo 'secret' | timeout 2 bash -c \"cat > /dev/tcp/%TARGETIP%/24443\" 2>/dev/null; echo EXFIL-DONE",
			Ports: []int{24443}},
		{Name: "exfil-alt", Intent: "data_theft", TTP: "T1048",
			Target: "asc-asscor-host4", Attacker: "asc-asscor-host1", TargetIP: "10.10.4.10",
			Cmd: "echo 'data' | timeout 2 bash -c \"cat > /dev/tcp/%TARGETIP%/28080\" 2>/dev/null; echo EXFIL2-DONE",
			Ports: []int{28080}},
	},
	"E5": {
		{Name: "recon-first", Intent: "recon", TTP: "T1595",
			Target: "asc-asscor-host5", Attacker: "asc-asscor-host1", TargetIP: "10.10.5.10",
			Cmd: "for p in %DECOYPORT%; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/$p\" 2>/dev/null; done; echo R-DONE",
			Ports: []int{22221, 22222}},
		{Name: "cred-mid", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host5", Attacker: "asc-asscor-host1", TargetIP: "10.10.5.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "exfil-last", Intent: "data_theft", TTP: "T1048",
			Target: "asc-asscor-host5", Attacker: "asc-asscor-host1", TargetIP: "10.10.5.10",
			Cmd: "echo 'data' | timeout 2 bash -c \"cat > /dev/tcp/%TARGETIP%/28080\" 2>/dev/null; echo X-DONE",
			Ports: []int{28080}},
	},
	"E6": {
		{Name: "unknown-ttp", Intent: "", TTP: "T9999",
			Target: "asc-asscor-host6", Attacker: "asc-asscor-host1", TargetIP: "10.10.6.10",
			Cmd: "echo 'unknown-exec'; echo UNKNOWN-DONE",
			Ports: nil},
	},
	"E7": {
		{Name: "conv-1", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-2", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-3", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-4", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-5", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-6", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-7", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-8", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-9", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
		{Name: "conv-10", Intent: "credential", TTP: "T1110",
			Target: "asc-asscor-host7", Attacker: "asc-asscor-host1", TargetIP: "10.10.7.10",
			Cmd: "for i in 1 2 3; do timeout 1 bash -c \"echo > /dev/tcp/%TARGETIP%/22222\" 2>/dev/null; done; echo C-DONE",
			Ports: []int{22222}},
	},
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: exprunner <E1|E2|...> [--json out.jsonl] [--decoyd /path/to/decoyd]")
	}
	runID := os.Args[1]
	jsonOut := "experiment.jsonl"
	decoydPath := "/tmp/decoyd"
	for i, a := range os.Args {
		if a == "--json" && i+1 < len(os.Args) {
			jsonOut = os.Args[i+1]
		}
		if a == "--decoyd" && i+1 < len(os.Args) {
			decoydPath = os.Args[i+1]
		}
	}
	steps, ok := experimentMatrix[runID]
	if !ok {
		log.Fatalf("unknown experiment %s", runID)
	}

	se := attackerstate.NewEngine()
	pr := predictor.NewEngine()
	pl := engagement.NewPlanner(engagement.DefaultParams())
	ctrl := defensecycle.NewController(se, pr, pl)
	state := attackerstate.NewState("caldera-actor")
	target := predictor.TargetState{ID: "host-target", SSAMScore: 55, Exposure: 0.6}

	f, err := os.Create(jsonOut)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	log.Printf("=== experiment %s: %d rounds ===", runID, len(steps))

	for i, s := range steps {
		round := i + 1
		start := time.Now()
		log.Printf("--- round %d: %s (TTP %s, gt=%s) target=%s ---", round, s.Name, s.TTP, s.Intent, s.Target)

		// 1. deploy decoyd in target container
		decoyLog := fmt.Sprintf("/tmp/decoyd-%d.log", round)
		dockerExec(s.Target, "pkill -f decoyd 2>/dev/null; rm -f "+decoyLog)
		if len(s.Ports) > 0 {
			if err := dockerCP(decoydPath, s.Target, "/tmp/decoyd"); err != nil {
				log.Fatalf("decoyd copy: %v", err)
			}
			portList := []string{}
			for _, p := range s.Ports {
				portList = append(portList, fmt.Sprintf("%d", p))
			}
			cmd := fmt.Sprintf("chmod 755 /tmp/decoyd; nohup /tmp/decoyd %s > %s 2>&1 & sleep 1",
				strings.Join(portList, ","), decoyLog)
			dockerExec(s.Target, cmd)
			time.Sleep(1 * time.Second)
		}

		// 2. execute the attacker step (from attacker container to target decoys)
		atkCmd := s.Cmd
		atkCmd = strings.ReplaceAll(atkCmd, "%TARGETIP%", s.TargetIP)
		portArgs := ""
		if len(s.Ports) > 0 {
			ps := []string{}
			for _, p := range s.Ports {
				ps = append(ps, fmt.Sprintf("%d", p))
			}
			portArgs = strings.Join(ps, " ")
		}
		atkCmd = strings.ReplaceAll(atkCmd, "%DECOYPORT%", portArgs)
		out, err := dockerExec(s.Attacker, atkCmd)
		if err != nil {
			log.Printf("attack exec warn: %v", err)
		}
		log.Printf("attack: %s", strings.TrimSpace(strings.Split(out, "\n")[0]))
		time.Sleep(3 * time.Second) // let decoy hits land

		// 3. collect decoy hits from decoyd log
		var hits []decoyHit
		if len(s.Ports) > 0 {
			logOut, _ := dockerExec(s.Target, "cat "+decoyLog+" 2>/dev/null")
			sc := bufio.NewScanner(strings.NewReader(logOut))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(line, "{") {
					var h decoyHit
					if json.Unmarshal([]byte(line), &h) == nil {
						hits = append(hits, h)
					}
				}
			}
		}

		// 4. build evidence
		evs := []attackerstate.Evidence{}
		for _, h := range hits {
			evs = append(evs, attackerstate.Evidence{
				Source:     fmt.Sprintf("decoy:tcp/%d", h.Port),
				SourceType: "decoy_trigger",
				At:         h.Timestamp,
				Target:     s.TargetIP,
				TTP:        s.TTP,
				Intent:     attackerstate.Intent(s.Intent),
				Confidence: 0.7,
			})
		}
		if len(evs) == 0 {
			evs = append(evs, attackerstate.Evidence{
				Source: "attack-observation", SourceType: "ttp_observation",
				At: time.Now(), Target: s.TargetIP,
				TTP: s.TTP, Intent: attackerstate.Intent(s.Intent), Confidence: 0.8,
			})
		}

		// 5. run closed loop
		res := ctrl.Step(state, evs, target)
		state = res.State

		distStr := map[string]float64{}
		for a, p := range res.Distribution.Probabilities {
			distStr[string(a)] = p
		}
		rec := RoundRecord{
			Round: round, Timestamp: time.Now(),
			Evidence: evs, Intent: string(res.State.Intent),
			Exp: res.State.Experience, Knowledge: res.State.TargetKnowledge,
			Dist: distStr, Sharpness: res.Sharpness, Strategy: string(res.Strategy),
			GroundTruth: s.Intent,
			LatencyMs:   time.Since(start).Milliseconds(),
		}
		for _, inv := range res.Interventions {
			rec.Intervents = append(rec.Intervents, inv.Intervention)
		}
		rec.DecoyHits = hits

		b, _ := json.Marshal(rec)
		w.Write(b)
		w.WriteByte('\n')
		log.Printf("round %d: intent=%s S=%.3f strategy=%s gt=%s hits=%d",
			round, rec.Intent, rec.Sharpness, rec.Strategy, rec.GroundTruth, len(hits))
	}

	log.Printf("=== experiment %s complete -> %s ===", runID, jsonOut)
}
