package connections

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/mizerael/infsec_ssu/task_5/models"
)

func GetConnections(filterState string) ([]models.ConnectionItem, error) {
	connections, err := readAllConnections()
	if err != nil {
		return nil, err
	}
	return filterConnections(connections, filterState), nil
}

func readAllConnections() ([]models.ConnectionItem, error) {
	var connections []models.ConnectionItem
	var errors []string

	tcpConnections, err := readTCPConnections()
	if err != nil {
		errors = append(errors, fmt.Sprintf("TCP: %v", err))
	} else {
		connections = append(connections, tcpConnections...)
	}

	udpConnections, err := readUDPConnections()
	if err != nil {
		errors = append(errors, fmt.Sprintf("UDP: %v", err))
	} else {
		connections = append(connections, udpConnections...)
	}

	connections = enrichWithProcessInfo(connections)

	if len(errors) > 0 && len(connections) == 0 {
		return nil, fmt.Errorf("failed to read connections: %s", strings.Join(errors, "; "))
	}

	return connections, nil
}

func readTCPConnections() ([]models.ConnectionItem, error) {
	var connections []models.ConnectionItem

	if tcp4, err := readProcNetFile("/proc/net/tcp", "TCP"); err == nil {
		connections = append(connections, tcp4...)
	}

	if tcp6, err := readProcNetFile("/proc/net/tcp6", "TCP6"); err == nil {
		connections = append(connections, tcp6...)
	}

	return connections, nil
}

func readUDPConnections() ([]models.ConnectionItem, error) {
	var connections []models.ConnectionItem

	if udp4, err := readProcNetFile("/proc/net/udp", "UDP"); err == nil {
		connections = append(connections, udp4...)
	}

	if udp6, err := readProcNetFile("/proc/net/udp6", "UDP6"); err == nil {
		connections = append(connections, udp6...)
	}

	return connections, nil
}

func readProcNetFile(filename, proto string) ([]models.ConnectionItem, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parseProcNetFile(file, proto)
}

func parseProcNetFile(reader io.Reader, proto string) ([]models.ConnectionItem, error) {
	var connections []models.ConnectionItem
	scanner := bufio.NewScanner(reader)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		connection, err := parseConnectionLine(line, proto)
		if err != nil {
			continue
		}

		if connection != nil {
			connections = append(connections, *connection)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading: %v", err)
	}

	return connections, nil
}

func parseConnectionLine(line, proto string) (*models.ConnectionItem, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil, fmt.Errorf("invalid line format")
	}

	localAddr := fields[1]
	remoteAddr := fields[2]
	state := fields[3]
	inode := fields[9]

	localIP, localPort, err := parseHexIPPort(localAddr)
	if err != nil {
		return nil, fmt.Errorf("error parsing local address: %v", err)
	}

	remoteIP, remotePort, err := parseHexIPPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("error parsing remote address: %v", err)
	}

	stateName := getTCPStateName(state, proto)
	local := formatAddress(localIP, localPort)
	remote := formatAddress(remoteIP, remotePort)

	return &models.ConnectionItem{
		Proto:  proto,
		Local:  local,
		Remote: remote,
		State:  stateName,
		PID:    inode,
	}, nil
}

func parseHexIPPort(hexAddr string) (string, string, error) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid address format: %s", hexAddr)
	}

	hexIP := parts[0]
	hexPort := parts[1]

	port, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return "", "", fmt.Errorf("error parsing port: %v", err)
	}

	ip, err := parseHexIP(hexIP)
	if err != nil {
		return "", "", err
	}

	return ip, strconv.Itoa(int(port)), nil
}

func parseHexIP(hexIP string) (string, error) {
	for len(hexIP) < 8 {
		hexIP = "0" + hexIP
	}

	if len(hexIP) == 8 {
		ipBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			start := (3 - i) * 2
			b, err := strconv.ParseInt(hexIP[start:start+2], 16, 16)
			if err != nil {
				return "", fmt.Errorf("error parsing IP byte: %v", err)
			}
			ipBytes[i] = byte(b)
		}
		return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String(), nil
	}

	if len(hexIP) == 32 {
		ipBytes := make([]byte, 16)
		for i := 0; i < 16; i++ {
			start := (15 - i) * 2
			b, err := strconv.ParseInt(hexIP[start:start+2], 16, 16)
			if err != nil {
				return "", fmt.Errorf("error parsing IP byte: %v", err)
			}
			ipBytes[i] = byte(b)
		}
		return net.IP(ipBytes).String(), nil
	}

	return "", fmt.Errorf("unexpected IP length: %d", len(hexIP))
}

func getTCPStateName(stateHex, proto string) string {
	state, err := strconv.ParseInt(stateHex, 16, 32)
	if err != nil {
		return "UNKNOWN"
	}

	if proto == "UDP" || proto == "UDP6" {
		states := map[int64]string{
			1: "ESTABLISHED",
			7: "LISTEN",
		}

		if name, exists := states[state]; exists {
			return name
		}
		return "UNKNOWN"
	}

	states := map[int64]string{
		1:  "ESTABLISHED",
		10: "LISTEN",
	}

	if name, exists := states[state]; exists {
		return name
	}
	return "UNKNOWN"
}

func formatAddress(ip, port string) string {
	if ip == "0.0.0.0" || ip == "::" {
		return "*:" + port
	}
	return ip + ":" + port
}

func enrichWithProcessInfo(connections []models.ConnectionItem) []models.ConnectionItem {
	if len(connections) == 0 {
		return connections
	}

	inodeToPID := buildInodeToPIDMap()

	for i := range connections {
		inode := connections[i].PID
		if pid, exists := inodeToPID[inode]; exists {
			connections[i].PID = pid
			connections[i].Process = getProcessName(pid)
		} else {
			connections[i].PID = "N/A"
		}
	}

	return connections
}

func buildInodeToPIDMap() map[string]string {
	inodeToPID := make(map[string]string)

	procDirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return inodeToPID
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex

	semaphore := make(chan struct{}, 10)

	for _, procDir := range procDirs {
		wg.Add(1)
		go func(procDir string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			pid := filepath.Base(procDir)

			fdDir := filepath.Join(procDir, "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				return
			}

			for _, fd := range fds {
				fdPath := filepath.Join(fdDir, fd.Name())
				target, err := os.Readlink(fdPath)
				if err != nil {
					continue
				}

				if strings.HasPrefix(target, "socket:[") {
					inode := strings.TrimPrefix(target, "socket:[")
					inode = strings.TrimSuffix(inode, "]")

					mutex.Lock()
					inodeToPID[inode] = pid
					mutex.Unlock()
				}
			}
		}(procDir)
	}

	wg.Wait()
	return inodeToPID
}

func getProcessName(pid string) string {
	if data, err := os.ReadFile(filepath.Join("/proc", pid, "comm")); err == nil {
		return strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline")); err == nil {
		cmdline := strings.TrimSpace(string(data))
		if idx := strings.IndexAny(cmdline, "\x00 "); idx != -1 {
			cmdline = cmdline[:idx]
		}
		if cmdline != "" {
			return filepath.Base(cmdline)
		}
	}

	return "unknown"
}

func filterConnections(connections []models.ConnectionItem, filterState string) []models.ConnectionItem {
	if filterState == "all" || len(connections) == 0 {
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
