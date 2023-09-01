package main

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var style = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#FAFAFA")).
	BorderStyle(lipgloss.RoundedBorder()).
	PaddingRight(5).
	PaddingLeft(5).
	Width(30)

func main() {
	fmt.Println(style.Render("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/"))
}
