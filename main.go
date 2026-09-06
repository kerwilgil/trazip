package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Create an instance of the app structure
	app := NewApp()

	// Create application with options
	err := wails.Run(&options.App{
		Title:            "TRAZIP",
		Width:            1440,
		Height:           900,
		MinWidth:         1024,
		MinHeight:        640,
		WindowStartState: options.Maximised,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 6, G: 18, B: 37, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		// Wails disables the browser's default context menu in production
		// builds by default, which also removes copy/paste on text inputs.
		EnableDefaultContextMenu: true,
		Bind: []interface{}{
			app,
			app.Service(),
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
