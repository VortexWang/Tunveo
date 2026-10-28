package main

import (
 "compress/gzip"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"
)

// Whole smaps only: matching addresses do not prove unchanged mapping generations.
func captureCycleMapping(folder string, sequence int, r *result, origin time.Time) error {
 start := time.Since(origin).Nanoseconds()
 record := map[string]any{"pid":os.Getpid(),"cycle":r.Settings["diagnostic_cycle_index"],"load_points":len(r.Points),"retention_points":len(r.Retention),"status":r.Status,"read_start_monotonic_ns":start}
 policy := "full"
 if r.Settings["diagnostic_mapping_policy"] == "metadata_only" { policy = "metadata_only" }
 record["mapping_policy"] = policy
 if policy == "full" {
  raw, err := os.ReadFile("/proc/self/smaps"); if err != nil { return err }
  record["read_end_monotonic_ns"] = time.Since(origin).Nanoseconds()
  name := fmt.Sprintf("mapping-%03d.smaps.gz",sequence)
  f, err := os.Create(filepath.Join(folder,name)); if err != nil { return err }
  z := gzip.NewWriter(f)
  _, err = z.Write(raw)
  if e := z.Close(); err == nil { err = e }
  if e := f.Close(); err == nil { err = e }
  if err != nil { return err }
  record["file"] = name
  record["sha256_raw"] = fmt.Sprintf("%x",sha256.Sum256(raw))
 }
 if policy == "metadata_only" { record["read_end_monotonic_ns"] = time.Since(origin).Nanoseconds() }
 status, err := os.ReadFile("/proc/self/status"); if err != nil { return err }
 thp := ""
 for _, line := range strings.Split(string(status), "\n") { if strings.HasPrefix(line,"THP_enabled:") { thp = strings.TrimSpace(strings.TrimPrefix(line,"THP_enabled:")) } }
 record["thp_enabled"] = thp
 record["godebug"] = os.Getenv("GODEBUG")
 index, err := os.OpenFile(filepath.Join(folder,"mapping-index.jsonl"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600); if err != nil { return err }
 err = json.NewEncoder(index).Encode(record)
 if closeErr := index.Close(); err == nil { err = closeErr }
 return err
}
