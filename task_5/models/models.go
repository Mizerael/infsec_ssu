package models

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
)

type ConnectionItem struct {
	Proto  string
	Local  string
	Remote string
	State  string
	PID    string
}

func (c ConnectionItem) Title() string {
	return fmt.Sprintf("%s %s → %s", c.Proto, c.Local, c.Remote)
}

func (c ConnectionItem) Description() string {
	return fmt.Sprintf("State: %s | PID: %s", c.State, c.PID)
}

func (c ConnectionItem) FilterValue() string {
	return fmt.Sprintf("%s %s %s %s", c.Proto, c.Local, c.Remote, c.State)
}

type AppModel struct {
	ConnectionsList list.Model
	FilterState     string
	LastUpdate      time.Time
	Loading         bool
	ErrorMsg        string
	RefreshInterval time.Duration
	AutoRefresh     bool
	Width           int
	Height          int
	ShowHelp        bool
	InputMode       bool
	IntervalInput   textinput.Model
	StatusMsg       string
}

type KeyMap struct {
	ToggleRefresh  key.Binding
	Refresh        key.Binding
	Filter         key.Binding
	ChangeInterval key.Binding
	ToggleHelp     key.Binding
	Netstat        key.Binding
	Quit           key.Binding
}

type ConnectionsLoadedMsg struct {
	Connections []ConnectionItem
	FilterState string
}

type ConnectionErrorMsg string
type TickMsg time.Time

func DefaultKeys() KeyMap {
	return KeyMap{
		ToggleRefresh: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "toggle auto-refresh"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh now"),
		),
		Filter: key.NewBinding(
			key.WithKeys("f"),
			key.WithHelp("f", "change filter"),
		),
		ChangeInterval: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "change interval"),
		),
		ToggleHelp: key.NewBinding(
			key.WithKeys("h"),
			key.WithHelp("h", "toggle help"),
		),
		Quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}
}
