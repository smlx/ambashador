package main

import (
	"encoding/json/v2"
	"fmt"
	"runtime"

	"github.com/alecthomas/kong"
)

// These variables are set by GoReleaser during the build.
var (
	commit      string
	date        string
	projectName string
	version     string
)

// VersionFlag is a boolean flag that prints version information and exits.
type VersionFlag bool

// AfterApply prints version info and terminates when --version is supplied.
func (v VersionFlag) AfterApply(app *kong.Kong) error {
	out, err := json.Marshal(
		struct {
			ProjectName string
			Version     string
			Commit      string
			BuildDate   string
			GoVersion   string
		}{
			projectName,
			version,
			commit,
			date,
			runtime.Version(),
		})
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	app.Exit(0)
	return nil
}
