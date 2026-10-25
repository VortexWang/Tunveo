package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/VortexWang/Tunveo/internal/master"
)

func runStateCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tunveo state <inspect|migrate|restore> [options]")
	}
	action := args[0]
	fs := flag.NewFlagSet("state "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", "", "Existing state file to inspect")
	source := fs.String("source", "", "Existing operator-owned GOB state")
	target := fs.String("target", "", "New target path; parent directory must exist")
	backup := fs.String("backup", "", "New backup path required for migration")
	offline := fs.Bool("offline", false, "Confirm source/target services are stopped")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected state arguments")
	}
	switch action {
	case "inspect":
		if *state == "" || *source != "" || *target != "" || *backup != "" || *offline {
			return fmt.Errorf("usage: tunveo state inspect --state <file>")
		}
		report, err := master.InspectState(*state)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	case "migrate", "restore":
		if !*offline || *state != "" {
			return fmt.Errorf("transfer requires --offline and explicit --source/--target; migration also requires --backup")
		}
		report, err := master.TransferState(action, *source, *target, *backup)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	default:
		return fmt.Errorf("unknown state operation")
	}
}
