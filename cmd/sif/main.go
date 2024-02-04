package main

import (
	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif"
	"github.com/dropalldatabases/sif/pkg/config"
)

func main() {
	settings := config.Parse()

	app, err := sif.New(settings)
	if err != nil {
		log.Fatal(err)
	}

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
