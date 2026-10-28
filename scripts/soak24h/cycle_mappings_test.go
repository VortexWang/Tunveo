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
