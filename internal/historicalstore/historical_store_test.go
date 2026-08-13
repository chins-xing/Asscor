package historicalstore

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestHistoricalStore_ComputeTrends(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"score":85.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":72.0,"acceptable":false,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":90.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	fmt.Fprintf(f, `{"score":60.0,"acceptable":false,"host_id":"host-b"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}

	if len(trends) != 2 {
		t.Fatalf("expected 2 host trends, got %d", len(trends))
	}

	sort.Slice(trends, func(i, j int) bool { return trends[i].HostID < trends[j].HostID })

	if trends[0].HostID != "host-a" {
		t.Errorf("HostID = %s, want host-a", trends[0].HostID)
	}
	if trends[0].Count != 3 {
		t.Errorf("host-a count = %d, want 3", trends[0].Count)
	}
	if trends[0].MinScore != 72.0 {
		t.Errorf("host-a MinScore = %f, want 72.0", trends[0].MinScore)
	}
	if trends[0].MaxScore != 90.0 {
		t.Errorf("host-a MaxScore = %f, want 90.0", trends[0].MaxScore)
	}

	acceptablePct := math.Round(float64(2)/3*10000) / 100
	if trends[0].AcceptablePct != acceptablePct {
		t.Errorf("host-a AcceptablePct = %f, want %f", trends[0].AcceptablePct, acceptablePct)
	}
}

func TestHistoricalStore_ComputeRiskLevels(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `{"score":50.0,"acceptable":false,"host_id":"high-risk"}`+"\n")
	fmt.Fprintf(f, `{"score":70.0,"acceptable":true,"host_id":"mid-risk"}`+"\n")
	fmt.Fprintf(f, `{"score":90.0,"acceptable":true,"host_id":"low-risk"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	levels, err := store.ComputeRiskLevels(30)
	if err != nil {
		t.Fatal(err)
	}

	if v := levels["high-risk"]; v != 1.0 {
		t.Errorf("high-risk level = %f, want 1.0", v)
	}
	if v := levels["mid-risk"]; v != 0.5 {
		t.Errorf("mid-risk level = %f, want 0.5", v)
	}
	if v := levels["low-risk"]; v != 0.0 {
		t.Errorf("low-risk level = %f, want 0.0", v)
	}
}

func TestHistoricalStore_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	store := NewHistoricalStore(dir)

	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trends) != 0 {
		t.Errorf("expected 0 trends for empty dir, got %d", len(trends))
	}
}

func TestHistoricalStore_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.Create(filepath.Join(dir, "20260618-assessments.jsonl"))
	fmt.Fprintf(f, "not valid json\n")
	fmt.Fprintf(f, `{"score":85.0,"acceptable":true,"host_id":"host-a"}`+"\n")
	f.Close()

	store := NewHistoricalStore(dir)
	trends, err := store.ComputeTrends(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(trends) != 1 {
		t.Fatalf("expected 1 host (invalid line skipped), got %d", len(trends))
	}
}
