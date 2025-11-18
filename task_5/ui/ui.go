package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mizerael/infsec_ssu/task_5/connections"
	"github.com/mizerael/infsec_ssu/task_5/models"
)

type Model models.AppModel

func InitialModel() Model {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("229")).
		BorderForeground(lipgloss.Color("229"))
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(lipgloss.Color("201"))

	l := list.New([]list.Item{}, delegate, 80, 20)
	l.Title = "StatTUI (glamourous netstat)"
	l.Styles.Title = lipgloss.NewStyle().
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("62")).
		Padding(0, 1)

	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false)
	l.SetShowTitle(true)

	ti := textinput.New()
	ti.Placeholder = "Enter refresh interval in seconds (e.g., 5)"
	ti.CharLimit = 4
	ti.Width = 30

	return Model{
		ConnectionsList: l,
		FilterState:     "all",
		LastUpdate:      time.Now(),
		Loading:         false,
		RefreshInterval: 5 * time.Second,
		AutoRefresh:     true,
		ShowHelp:        true,
		InputMode:       false,
		IntervalInput:   ti,
		Width:           80,
		Height:          24,
		StatusMsg:       "Ready",
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.getConnectionsCmd(),
		m.tickCmd(),
	)
}

func (m Model) getConnectionsCmd() tea.Cmd {
	return func() tea.Msg {
		connections, err := connections.GetConnections(m.FilterState)
		if err != nil {
			return models.ConnectionErrorMsg(err.Error())
		}
		return models.ConnectionsLoadedMsg{
			Connections: connections,
			FilterState: m.FilterState,
		}
	}
}

func (m Model) tickCmd() tea.Cmd {
	return tea.Tick(m.RefreshInterval, func(t time.Time) tea.Msg {
		return models.TickMsg(t)
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.ConnectionsList.SetSize(msg.Width-4, max(10, msg.Height-12))

	case tea.KeyMsg:
		if m.InputMode {
			return m.handleInputMode(msg)
		}
		return m.handleNormalMode(msg)

	case models.TickMsg:
		if m.AutoRefresh && !m.Loading && !m.InputMode {
			m.Loading = true
			cmds = append(cmds, m.getConnectionsCmd())
		}
		if m.AutoRefresh {
			cmds = append(cmds, m.tickCmd())
		}

	case models.ConnectionsLoadedMsg:
		m.Loading = false
		m.ErrorMsg = ""
		m.LastUpdate = time.Now()
		m.StatusMsg = fmt.Sprintf("Loaded %d connections", len(msg.Connections))

		items := make([]list.Item, len(msg.Connections))
		for i, conn := range msg.Connections {
			items[i] = list.Item(conn)
		}

		cmd := m.ConnectionsList.SetItems(items)
		cmds = append(cmds, cmd)

	case models.ConnectionErrorMsg:
		m.Loading = false
		m.ErrorMsg = string(msg)
		m.StatusMsg = "Error loading connections"
	}

	var listCmd tea.Cmd
	m.ConnectionsList, listCmd = m.ConnectionsList.Update(msg)
	cmds = append(cmds, listCmd)

	return m, tea.Batch(cmds...)
}

func (m Model) handleInputMode(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if value := m.IntervalInput.Value(); value != "" {
			if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
				m.RefreshInterval = time.Duration(secs) * time.Second
				m.StatusMsg = fmt.Sprintf("Interval set to %d seconds", secs)
			}
		}
		m.InputMode = false
		var cmds []tea.Cmd
		if m.AutoRefresh {
			cmds = append(cmds, m.tickCmd())
		}
		return m, tea.Batch(cmds...)

	case "esc", "ctrl+c":
		m.InputMode = false
		return m, nil
	}

	var inputCmd tea.Cmd
	m.IntervalInput, inputCmd = m.IntervalInput.Update(msg)
	return m, inputCmd
}

func (m Model) handleNormalMode(msg tea.KeyMsg) (Model, tea.Cmd) {
	keys := models.DefaultKeys()
	var cmds []tea.Cmd

	switch {
	case key.Matches(msg, keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, keys.Refresh):
		m.Loading = true
		m.StatusMsg = "Refreshing connections..."
		return m, m.getConnectionsCmd()

	case key.Matches(msg, keys.Filter):
		switch m.FilterState {
		case "all":
			m.FilterState = "listening"
		case "listening":
			m.FilterState = "established"
		case "established":
			m.FilterState = "all"
		}
		m.Loading = true
		m.StatusMsg = fmt.Sprintf("Filter changed to: %s", strings.ToUpper(m.FilterState))
		return m, m.getConnectionsCmd()

	case key.Matches(msg, keys.ToggleRefresh):
		m.AutoRefresh = !m.AutoRefresh
		if m.AutoRefresh {
			m.StatusMsg = "Auto-refresh: ON"
			cmds = append(cmds, m.tickCmd())
		} else {
			m.StatusMsg = "Auto-refresh: OFF"
		}
		return m, tea.Batch(cmds...)

	case key.Matches(msg, keys.ChangeInterval):
		m.InputMode = true
		m.IntervalInput.SetValue(fmt.Sprintf("%.0f", m.RefreshInterval.Seconds()))
		m.IntervalInput.Focus()
		return m, nil

	case key.Matches(msg, keys.Netstat):
		m.StatusMsg = "Already using netstat"
		return m, nil

	case key.Matches(msg, keys.ToggleHelp):
		m.ShowHelp = !m.ShowHelp
		return m, nil

	default:
		m.ConnectionsList, _ = m.ConnectionsList.Update(msg)
		return m, nil
	}
}

func (m Model) View() string {
	if m.InputMode {
		return m.renderInputMode()
	}

	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("62")).
		Padding(0, 1).
		Bold(true).
		Width(m.Width).
		Align(lipgloss.Center)

	s.WriteString(titleStyle.Render("StatTUI (netstat)"))
	s.WriteString("\n")

	statusStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Italic(true).
		Padding(0, 1)

	autoRefreshStatus := "ON"
	if !m.AutoRefresh {
		autoRefreshStatus = "OFF"
	}

	status := fmt.Sprintf("Filter: %s | Auto-refresh: %s (%v) | Last: %s | %s",
		strings.ToUpper(m.FilterState),
		autoRefreshStatus,
		m.RefreshInterval,
		m.LastUpdate.Format("15:04:05"),
		m.StatusMsg,
	)

	if m.ErrorMsg != "" {
		status += fmt.Sprintf(" | Error: %s", m.ErrorMsg)
	}

	if m.Loading {
		status += " | Loading..."
	}

	s.WriteString(statusStyle.Render(status))
	s.WriteString("\n")

	listView := m.ConnectionsList.View()
	s.WriteString(listView)
	if m.ShowHelp {
		helpStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("241")).
			Padding(0, 1).
			Width(80)

		navLine := lipgloss.NewStyle().
			Foreground(lipgloss.Color("255")).
			Bold(true).
			Render("Navigation: ") +
			"↑/k ↓/j • PgUp/PgDn • Home/End • / search • Esc cancel"

		cmdLine := lipgloss.NewStyle().
			Foreground(lipgloss.Color("255")).
			Bold(true).
			Render("Commands: ") +
			"f filter • r refresh • a auto-refresh • i interval • ? help • q quit"

		helpContent := navLine + "\n" + cmdLine

		s.WriteString("\n")
		s.WriteString(helpStyle.Render(helpContent))
	}

	return s.String()
}

func (m Model) renderInputMode() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("62")).
		Padding(0, 1).
		Bold(true).
		Width(m.Width - 1).
		Align(lipgloss.Center)

	s.WriteString(titleStyle.Render("Set Refresh Interval"))
	s.WriteString("\n\n")

	s.WriteString("Enter refresh interval in seconds:\n\n")
	s.WriteString(m.IntervalInput.View())
	s.WriteString("\n\n")
	s.WriteString("(Press Enter to confirm, ESC to cancel)")

	return s.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
