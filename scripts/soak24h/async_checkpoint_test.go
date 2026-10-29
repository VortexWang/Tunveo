package main

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "testing"
    "time"
)

func TestCheckpointWriterPreservesImmutableOrder(t *testing.T) {
    var mu sync.Mutex
    var got []int
    w := newCheckpointWriter("unused", 8, func(_ string, b []byte) error {
        var r result
        if err := json.Unmarshal(b, &r); err != nil { return err }
        mu.Lock(); got = append(got, r.Transport); mu.Unlock()
        return nil
    })
    r := &result{}
    for i:=0;i<4;i++ { r.Transport=i; if err:=w.submit(r);err!=nil {t.Fatal(err)} }
    r.Transport=99
    if err:=w.finish();err!=nil {t.Fatal(err)}
    if len(got)!=4 {t.Fatalf("wrong count %v",got)}
    for i,v:=range got {if i!=v {t.Fatalf("wrong order or mutable snapshot %v",got)}}
}

func TestCheckpointWriterRejectsQueueOverflowAndReportsWriteFailure(t *testing.T) {
    entered:=make(chan struct{}); release:=make(chan struct{})
    failure:=errors.New("controlled write failure")
    w:=newCheckpointWriter("unused",1,func(_ string,_ []byte) error {close(entered);<-release;return failure})
    if err:=w.submit(&result{});err!=nil {t.Fatal(err)}
    <-entered
    if err:=w.submit(&result{});err!=nil {t.Fatal(err)}
    if err:=w.submit(&result{});err==nil || !strings.Contains(err.Error(),"queue full") {t.Fatalf("overflow accepted: %v",err)}
    close(release)
    if err:=w.finish();!errors.Is(err,failure) {t.Fatalf("write error lost: %v",err)}
}

func TestSlowCheckpointDoesNotBlockLoad(t *testing.T) {
    f,err:=newFixture();if err!=nil {t.Fatal(err)};defer f.close()
    a,err:=newAudit(filepath.Join(t.TempDir(),"events.gz"));if err!=nil {t.Fatal(err)};defer a.close()
    first:=true
    w:=newCheckpointWriter("unused",8,func(_ string,_ []byte) error {
        if first {first=false;time.Sleep(2900*time.Millisecond)}
        return nil
    })
    r:=&result{}
    err=runLoad(r,f.port,1,10,time.Second,3*time.Second,time.Second,a,make(chan error),make(chan os.Signal),func() error{return w.submit(r)},nil)
    writeErr:=w.finish()
    if err!=nil || writeErr!=nil {t.Fatalf("slow writer blocked load: load=%v write=%v",err,writeErr)}
    if r.Warmup.Dropped!=0 || r.Counts.Dropped!=0 {t.Fatalf("dropped work: warm=%+v measured=%+v",r.Warmup,r.Counts)}
}
