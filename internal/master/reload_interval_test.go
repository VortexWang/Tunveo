package master

import (
	"strings"
	"testing"
	"time"

	"github.com/VortexWang/Tunveo/internal/common"
)

func TestNewMasterRejectsNonpositiveReloadBeforeSideEffects(t *testing.T) {
	old := common.ReloadInterval
	defer func() { common.ReloadInterval = old }()
	for _, value := range []int64{0, -1} {
		common.ReloadInterval = time.Duration(value)
		// No URL/logger: validation must precede address lookup, LoadState and workers.
		master, err := NewMaster(nil, "0", nil, nil, "test")
		if err == nil || master != nil || !strings.Contains(err.Error(), "NP_RELOAD_INTERVAL") {
			t.Fatal("master accepted invalid interval")
		}
	}
}
