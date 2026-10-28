package main

import (
 "compress/gzip"
 "crypto/sha256"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "time"
)

// Whole smaps only: matching addresses do not prove unchanged mapping generations.
func captureCycleMapping(folder string, sequence int, r *result, origin time.Time) error {
 start := time.Since(origin).Nanoseconds()
 raw, err := os.ReadFile("/proc/self/smaps")
 end := time.Since(origin).Nanoseconds()
 if err != nil { return err }
 name := fmt.Sprintf("mapping-%03d.smaps.gz", sequence)
 f, err := os.Create(filepath.Join(folder, name)); if err != nil { return err }
 z := gzip.NewWriter(f)
 _, err = z.Write(raw)
 if closeErr := z.Close(); err == nil { err = closeErr }
 if closeErr := f.Close(); err == nil { err = closeErr }
 if err != nil { return err }
 record := map[string]any{"file":name,"sha256_raw":fmt.Sprintf("%x",sha256.Sum256(raw)),"pid":os.Getpid(),"cycle":r.Settings["diagnostic_cycle_index"],"load_points":len(r.Points),"retention_points":len(r.Retention),"status":r.Status,"read_start_monotonic_ns":start,"read_end_monotonic_ns":end}
 index, err := os.OpenFile(filepath.Join(folder,"mapping-index.jsonl"),os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600); if err != nil { return err }
 err = json.NewEncoder(index).Encode(record)
 if closeErr := index.Close(); err == nil { err = closeErr }
 return err
}
