package main

import (
	"fmt"
	"os"

	"github.com/mizerael/infsec_ssu/task_5/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if _, err := os.Stat("/usr/bin/netstat"); err != nil {
		if _, err := os.Stat("/bin/netstat"); err != nil {
			fmt.Println("Error: netstat not found in standard paths")
			fmt.Println("Please install netstat: sudo apt install net-tools")
			os.Exit(1)
		}
	}

	p := tea.NewProgram(ui.InitialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
