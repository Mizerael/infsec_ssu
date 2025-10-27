package netstat

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mizerael/infsec_ssu/task_5/models"
)

func GetConnections(filterState string) ([]models.ConnectionItem, error) {
	return getConnectionsViaNetstat(filterState)
}

func getConnectionsViaNetstat(filterState string) ([]models.ConnectionItem, error) {
	cmd := exec.Command("netstat", "-tuanp")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat error: %v", err)
	}

	connections := parseNetstatOutput(string(output))
	return filterConnections(connections, filterState), nil
}

func parseNetstatOutput(output string) []models.ConnectionItem {
	var connections []models.ConnectionItem
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		if strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp") {
			connection := parseConnectionLine(fields)
			if connection != nil {
				connections = append(connections, *connection)
			}
		}
	}

	return connections
}

func parseConnectionLine(fields []string) *models.ConnectionItem {
	proto := strings.ToUpper(strings.TrimSuffix(fields[0], ":"))

	localAddrIndex := 3
	remoteAddrIndex := 4
	stateIndex := 5
	pidIndex := 6

	if len(fields) <= pidIndex {
		return nil
	}

	local := fields[localAddrIndex]
	remote := fields[remoteAddrIndex]
	state := fields[stateIndex]

	pid := extractPID(fields[pidIndex])

	if state == "LISTEN" {
		state = "LISTENING"
	}

	return &models.ConnectionItem{
		Proto:  proto,
		Local:  local,
		Remote: remote,
		State:  state,
		PID:    pid,
	}
}

func extractPID(pidField string) string {
	if pidField == "-" {
		return "N/A"
	}

	pidParts := strings.Split(pidField, "/")
	if len(pidParts) > 0 {
		if _, err := strconv.Atoi(pidParts[0]); err == nil {
			return pidParts[0]
		}
	}

	return "N/A"
}

func filterConnections(connections []models.ConnectionItem, filterState string) []models.ConnectionItem {
	if filterState == "all" {
		return connections
	}

	var filtered []models.ConnectionItem
	for _, conn := range connections {
		connState := strings.ToUpper(conn.State)
		switch filterState {
		case "listening":
			if strings.Contains(connState, "LISTEN") {
				filtered = append(filtered, conn)
			}
		case "established":
			if strings.Contains(connState, "ESTABLISHED") {
				filtered = append(filtered, conn)
			}
		}
	}
	return filtered
}
