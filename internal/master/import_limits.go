package master

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

func validateInstance(i *Instance) error {
	if len(i.Alias) > MaxValueLen || len(i.URL) > 8192 || len(i.Meta.Tags) > 128 {
		return fmt.Errorf("instance metadata exceeds limits")
	}
	for k, v := range i.Meta.Tags {
		if len(k) > MaxValueLen || len(v) > MaxValueLen {
			return fmt.Errorf("instance tag exceeds limits")
		}
	}
	if len(i.Meta.Peer.SID) > MaxValueLen || len(i.Meta.Peer.Type) > MaxValueLen || len(i.Meta.Peer.Alias) > MaxValueLen {
		return fmt.Errorf("peer metadata exceeds limits")
	}
	if i.ID != APIKeyID {
		u, err := url.Parse(i.URL)
		if err != nil || (u.Scheme != "client" && u.Scheme != "server") {
			return fmt.Errorf("invalid instance URL")
		}
	}
	return nil
}

// Validate the entire batch and available registry capacity before publication
// or child scheduling. An error does not partially import/start a prefix.
func (m *Master) importLocked(ctx context.Context) (int, error) {
	path := filepath.Join(filepath.Dir(m.StatePath), ExportFileName)
	var imports []importEntry
	err := func() error {
		m.dataMu.Unlock()
		defer m.dataMu.Lock()
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > MaxImportBytes {
			return fmt.Errorf("import must be a regular file of at most %d bytes", MaxImportBytes)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, MaxImportBytes+1))
		if err != nil {
			return err
		}
		if len(data) > MaxImportBytes {
			return fmt.Errorf("import too large")
		}

		if err = json.Unmarshal(data, &imports); err != nil {
			return fmt.Errorf("invalid import JSON")
		}
		return nil
	}()
	if err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if len(imports) > MaxImportInstances {
		return 0, fmt.Errorf("import batch exceeds %d instances", MaxImportInstances)
	}
	count := 0
	m.Instances.Range(func(k, v any) bool {
		if k.(string) != APIKeyID {
			count++
		}
		return true
	})
	if count+len(imports) > MaxManagedInstances {
		return 0, fmt.Errorf("managed instance limit reached")
	}
	batch := make([]*Instance, 0, len(imports))
	ids := make(map[string]bool)
	for _, entry := range imports {
		parsed, err := url.Parse(entry.URL)
		if err != nil || (parsed.Scheme != "client" && parsed.Scheme != "server") {
			return 0, fmt.Errorf("invalid import instance URL")
		}
		id := GenerateID()
		for {
			_, exists := m.Instances.Load(id)
			if !exists && !ids[id] {
				break
			}
			id = GenerateID()
		}
		ids[id] = true
		i := &Instance{ID: id, Alias: entry.Alias, URL: m.EnhanceURL(entry.URL, parsed.Scheme), Type: parsed.Scheme, Status: "stopped", Restart: true, Meta: entry.Meta, TCPRX: entry.TCPRX, TCPTX: entry.TCPTX, UDPRX: entry.UDPRX, UDPTX: entry.UDPTX}
		if entry.Restart != nil {
			i.Restart = *entry.Restart
		}
		if i.Meta.Tags == nil {
			i.Meta.Tags = map[string]string{}
		}
		if err = validateInstance(i); err != nil {
			return 0, err
		}
		i.Config = m.GenerateConfigURL(i)
		batch = append(batch, i)
	}
	if m.managementStopped.Load() {
		return 0, fmt.Errorf("management is stopping")
	}
	for _, i := range batch {
		m.Instances.Store(i.ID, i)
	}
	for _, i := range batch {
		if i.Restart {
			m.queueActionLocked(i, "start")
		}
	}
	m.requestSaveLocked()
	return len(batch), nil
}

type importEntry struct {
	Alias   string `json:"alias"`
	URL     string `json:"url"`
	Restart *bool  `json:"restart"`
	Meta    Meta   `json:"meta"`
	TCPRX   uint64 `json:"tcprx"`
	TCPTX   uint64 `json:"tcptx"`
	UDPRX   uint64 `json:"udprx"`
	UDPTX   uint64 `json:"udptx"`
}

func validateMetadataArguments(args map[string]any) error {
	if alias, ok := args["alias"].(string); ok && len(alias) > MaxValueLen {
		return fmt.Errorf("alias exceeds limit")
	}
	if peer, ok := args["peer"].(map[string]any); ok {
		for _, k := range []string{"sid", "type", "alias"} {
			if v, ok := peer[k].(string); ok && len(v) > MaxValueLen {
				return fmt.Errorf("peer field exceeds limit")
			}
		}
	}
	if tags, ok := args["tags"].(map[string]any); ok {
		if len(tags) > 128 {
			return fmt.Errorf("too many tags")
		}
		for k, v := range tags {
			if len(k) > MaxValueLen || len(fmt.Sprint(v)) > MaxValueLen {
				return fmt.Errorf("tag exceeds limit")
			}
		}
	}
	return nil
}
