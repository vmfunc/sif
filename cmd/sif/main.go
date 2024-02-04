package main

import (
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/config"
)

func main() {
	fmt.Println(styles.Box.Render("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n"))
	fmt.Println(styles.Subheading.Render("\nhttps://sif.sh\nman's best friend\n\ncopyright (c) 2023-2024 lunchcat and contributors.\n\n"))

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
