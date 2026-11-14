package main

import (
	"embed"
	"log"
	"os"

	"github.com/plu-nz/mono.passport/internal/ghauth"
	"github.com/plu-nz/mono.passport/internal/rename"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:dist
var assets embed.FS

func main() {
	// Upgrades from Passage keep their settings, pairings and WebView data.
	rename.Migrate()
	// Git runs `passport git-credential get` for the vault's github.com remote.
	// It must answer before Wails starts: no window, no single-instance hand-off.
	if len(os.Args) > 1 && os.Args[1] == "git-credential" {
		os.Exit(ghauth.CredentialHelper(os.Args[2:], os.Stdin, os.Stdout))
	}
	// Keep a Passport-managed vault's credential helper pointing at this binary.
	go refreshHelper()
	var window *application.WebviewWindow
	title := "Passport"
	var linux application.LinuxOptions
	if devRun() {
		// A distinct app ID gives the development window its own Wayland
		// class (nz.plu.passport.dev), so window rules and shortcuts can
		// target it apart from an installed Passport.
		title = "Passport (dev)"
		linux.ApplicationID = devInstanceID
	}
	app := application.New(application.Options{
		Name:  "Passport",
		Linux: linux,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Services: []application.Service{
			application.NewService(&DesktopService{}),
		},
		// A second launch exits and brings the existing window to the front.
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: instanceID(),
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if window != nil {
					window.UnMinimise()
					window.Show()
					window.Focus()
				}
			},
		},
	})
	themeApp = app
	go watchColorScheme(scheduleThemeRefresh)
	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     title,
		Width:     1060,
		Height:    720,
		MinWidth:  740,
		MinHeight: 520,
	})
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

const devInstanceID = "nz.plu.passport.dev"

// devRun reports a development run started by scripts/dev-desktop.sh.
func devRun() bool { return os.Getenv("FRONTEND_DEVSERVER_URL") != "" }

// instanceID keeps a development run from handing off to an installed
// Passport that is already open.
func instanceID() string {
	if devRun() {
		return devInstanceID
	}
	return "nz.plu.passport"
}
