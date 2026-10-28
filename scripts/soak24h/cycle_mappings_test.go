package main
import (
 "bufio"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func TestCycleMappingIndex(t *testing.T) {
 folder:=t.TempDir()
 r:=&result{Status:"running", Settings:map[string]any{"diagnostic_cycle_index":2}}
 origin:=time.Now()
 for i:=1;i<=2;i++ { if err:=captureCycleMapping(folder,i,r,origin);err!=nil { t.Fatal(err) } }
 f,err:=os.Open(filepath.Join(folder,"mapping-index.jsonl"));if err!=nil { t.Fatal(err) };defer f.Close()
 s:=bufio.NewScanner(f);n:=0;var last float64
 for s.Scan() { var r map[string]any;if err:=json.Unmarshal(s.Bytes(),&r);err!=nil { t.Fatal(err) };n++
  if r["cycle"].(float64)!=2 || r["pid"].(float64)!=float64(os.Getpid()) || r["read_start_monotonic_ns"].(float64)<last { t.Fatal(r) }
  last=r["read_end_monotonic_ns"].(float64)
  if r["read_start_monotonic_ns"].(float64)>last { t.Fatal(r) }
  if _,err:=os.Stat(filepath.Join(folder,r["file"].(string)));err!=nil { t.Fatal(err) }
 }
 if s.Err()!=nil || n!=2 { t.Fatalf("records=%d err=%v",n,s.Err()) }
}

func TestMetadataOnlyOmitsFullMappingFiles(t *testing.T) {
 folder:=t.TempDir()
 r:=&result{Status:"running",Settings:map[string]any{"diagnostic_cycle_index":1,"diagnostic_mapping_policy":"metadata_only"}}
 if err:=captureCycleMapping(folder,1,r,time.Now());err!=nil { t.Fatal(err) }
 raw,err:=os.ReadFile(filepath.Join(folder,"mapping-index.jsonl"));if err!=nil {t.Fatal(err)}
 var record map[string]any;if err:=json.Unmarshal(raw,&record);err!=nil {t.Fatal(err)}
 if record["mapping_policy"]!="metadata_only" || record["pid"].(float64)!=float64(os.Getpid()) { t.Fatal(record) }
 if _,ok:=record["file"];ok {t.Fatal("metadata-only falsely advertises raw mapping")}
 if _,ok:=record["sha256_raw"];ok {t.Fatal("metadata-only falsely advertises hash")}
 files,err:=filepath.Glob(filepath.Join(folder,"mapping-*.smaps.gz"));if err!=nil || len(files)!=0 {t.Fatal(files,err)}
 if _,ok:=record["thp_enabled"];!ok {t.Fatal("missing target THP status")}
}
