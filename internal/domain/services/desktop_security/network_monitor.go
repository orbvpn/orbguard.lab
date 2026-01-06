package desktop_security

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// NetworkMonitor monitors network connections and manages firewall rules
type NetworkMonitor struct {
	logger     *logger.Logger
	cache      *cache.RedisCache
	platform   models.DesktopPlatform
	config     models.NetworkMonitorConfig
	rules      []models.FirewallRule
	rulesMutex sync.RWMutex

	// Connection tracking
	connections     map[string]models.NetworkConnection
	connMutex       sync.RWMutex

	// Process resolver
	processResolver *ProcessResolver

	// IOC lists for blocking
	blockedIPs     map[string]string // IP -> reason
	blockedDomains map[string]string // domain -> reason
	iocMutex       sync.RWMutex
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(redisCache *cache.RedisCache, log *logger.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		logger:          log.WithComponent("network-monitor"),
		cache:           redisCache,
		platform:        detectPlatform(),
		config:          defaultNetworkConfig(),
		rules:           []models.FirewallRule{},
		connections:     make(map[string]models.NetworkConnection),
		processResolver: NewProcessResolver(log),
		blockedIPs:      make(map[string]string),
		blockedDomains:  make(map[string]string),
	}
}

// defaultNetworkConfig returns default network monitor configuration
func defaultNetworkConfig() models.NetworkMonitorConfig {
	return models.NetworkMonitorConfig{
		Enabled:            true,
		MonitorOutbound:    true,
		MonitorInbound:     true,
		BlockUnknown:       false,
		AlertOnBadIP:       true,
		AlertOnCnC:         true,
		WhitelistApple:     true,
		WhitelistMicrosoft: true,
		LogConnections:     true,
		ExcludedPorts:      []int{53, 80, 443}, // Common ports
	}
}

// GetConnections returns current network connections
func (m *NetworkMonitor) GetConnections(ctx context.Context) ([]models.NetworkConnection, error) {
	switch m.platform {
	case models.DesktopPlatformMacOS:
		return m.getConnectionsMacOS(ctx)
	case models.DesktopPlatformWindows:
		return m.getConnectionsWindows(ctx)
	case models.DesktopPlatformLinux:
		return m.getConnectionsLinux(ctx)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", m.platform)
	}
}

// getConnectionsMacOS gets network connections on macOS using netstat/lsof
func (m *NetworkMonitor) getConnectionsMacOS(ctx context.Context) ([]models.NetworkConnection, error) {
	var connections []models.NetworkConnection

	// Use lsof to get connections with process info
	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P")
	output, err := cmd.Output()
	if err != nil {
		m.logger.Debug().Err(err).Msg("lsof failed, falling back to netstat")
		return m.getConnectionsNetstat(ctx)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || line == "" { // Skip header
			continue
		}

		conn := m.parseLsofLine(line)
		if conn != nil {
			connections = append(connections, *conn)
		}
	}

	return connections, nil
}

// parseLsofLine parses a line from lsof output
func (m *NetworkMonitor) parseLsofLine(line string) *models.NetworkConnection {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil
	}

	conn := &models.NetworkConnection{
		ID:          uuid.New(),
		ProcessName: fields[0],
		CreatedAt:   time.Now(),
		LastSeen:    time.Now(),
	}

	// Parse PID
	if pid, err := strconv.Atoi(fields[1]); err == nil {
		conn.ProcessID = pid
	}

	// Parse protocol
	protocolField := strings.ToLower(fields[7])
	if strings.Contains(protocolField, "tcp") {
		conn.Protocol = "tcp"
	} else if strings.Contains(protocolField, "udp") {
		conn.Protocol = "udp"
	}

	// Parse addresses (field 8)
	addrField := fields[8]
	if strings.Contains(addrField, "->") {
		// Established connection: local->remote
		parts := strings.Split(addrField, "->")
		if len(parts) == 2 {
			m.parseAddress(parts[0], &conn.LocalAddress, &conn.LocalPort)
			m.parseAddress(parts[1], &conn.RemoteAddress, &conn.RemotePort)
			conn.State = "ESTABLISHED"
		}
	} else if strings.Contains(addrField, ":") {
		// Listening socket
		m.parseAddress(addrField, &conn.LocalAddress, &conn.LocalPort)
		conn.State = "LISTEN"
	}

	// Get process path
	if conn.ProcessID > 0 {
		if procInfo, err := m.processResolver.GetProcessInfo(conn.ProcessID); err == nil {
			conn.ProcessPath = procInfo.Path
			conn.ProcessUser = procInfo.User
			conn.CodeSigning = procInfo.CodeSigning
		}
	}

	return conn
}

// parseAddress parses an address:port string
func (m *NetworkMonitor) parseAddress(addr string, ip *string, port *int) {
	lastColon := strings.LastIndex(addr, ":")
	if lastColon == -1 {
		*ip = addr
		return
	}

	*ip = addr[:lastColon]
	if p, err := strconv.Atoi(addr[lastColon+1:]); err == nil {
		*port = p
	}
}

// getConnectionsLinux gets network connections on Linux using /proc/net
func (m *NetworkMonitor) getConnectionsLinux(ctx context.Context) ([]models.NetworkConnection, error) {
	var connections []models.NetworkConnection

	// Parse TCP connections
	tcpConns, err := m.parseLinuxNetFile("/proc/net/tcp", "tcp")
	if err == nil {
		connections = append(connections, tcpConns...)
	}

	// Parse TCP6 connections
	tcp6Conns, err := m.parseLinuxNetFile("/proc/net/tcp6", "tcp6")
	if err == nil {
		connections = append(connections, tcp6Conns...)
	}

	// Parse UDP connections
	udpConns, err := m.parseLinuxNetFile("/proc/net/udp", "udp")
	if err == nil {
		connections = append(connections, udpConns...)
	}

	return connections, nil
}

// parseLinuxNetFile parses /proc/net/tcp, udp, etc.
func (m *NetworkMonitor) parseLinuxNetFile(path, protocol string) ([]models.NetworkConnection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var connections []models.NetworkConnection
	scanner := bufio.NewScanner(file)

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		conn := m.parseLinuxNetLine(line, protocol)
		if conn != nil {
			connections = append(connections, *conn)
		}
	}

	return connections, scanner.Err()
}

// parseLinuxNetLine parses a line from /proc/net/tcp
func (m *NetworkMonitor) parseLinuxNetLine(line, protocol string) *models.NetworkConnection {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil
	}

	conn := &models.NetworkConnection{
		ID:        uuid.New(),
		Protocol:  protocol,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Parse local address (field 1)
	localAddr := fields[1]
	m.parseHexAddress(localAddr, &conn.LocalAddress, &conn.LocalPort)

	// Parse remote address (field 2)
	remoteAddr := fields[2]
	m.parseHexAddress(remoteAddr, &conn.RemoteAddress, &conn.RemotePort)

	// Parse state (field 3)
	stateHex := fields[3]
	conn.State = m.tcpStateFromHex(stateHex)

	// Parse inode and find process
	if len(fields) > 9 {
		inode := fields[9]
		if pid := m.findProcessByInode(inode); pid > 0 {
			conn.ProcessID = pid
			if procInfo, err := m.processResolver.GetProcessInfo(pid); err == nil {
				conn.ProcessName = procInfo.Name
				conn.ProcessPath = procInfo.Path
				conn.ProcessUser = procInfo.User
			}
		}
	}

	return conn
}

// parseHexAddress parses hex-encoded address from /proc/net
func (m *NetworkMonitor) parseHexAddress(hex string, ip *string, port *int) {
	parts := strings.Split(hex, ":")
	if len(parts) != 2 {
		return
	}

	// Parse IP (little-endian hex)
	ipHex := parts[0]
	if len(ipHex) == 8 {
		// IPv4
		var octets [4]byte
		for i := 0; i < 4; i++ {
			b, _ := strconv.ParseUint(ipHex[6-2*i:8-2*i], 16, 8)
			octets[i] = byte(b)
		}
		*ip = fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3])
	}

	// Parse port (big-endian hex)
	portVal, _ := strconv.ParseUint(parts[1], 16, 16)
	*port = int(portVal)
}

// tcpStateFromHex converts TCP state hex to string
func (m *NetworkMonitor) tcpStateFromHex(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if state, ok := states[strings.ToUpper(hex)]; ok {
		return state
	}
	return "UNKNOWN"
}

// findProcessByInode finds process by socket inode
func (m *NetworkMonitor) findProcessByInode(inode string) int {
	// Scan /proc/*/fd for socket:[inode]
	socketLink := fmt.Sprintf("socket:[%s]", inode)

	procs, _ := os.ReadDir("/proc")
	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, fd.Name()))
			if err == nil && link == socketLink {
				return pid
			}
		}
	}

	return 0
}

// getConnectionsWindows gets network connections on Windows
func (m *NetworkMonitor) getConnectionsWindows(ctx context.Context) ([]models.NetworkConnection, error) {
	var connections []models.NetworkConnection

	// Use netstat with process info
	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		conn := m.parseNetstatWindowsLine(line)
		if conn != nil {
			connections = append(connections, *conn)
		}
	}

	return connections, nil
}

// parseNetstatWindowsLine parses Windows netstat output
func (m *NetworkMonitor) parseNetstatWindowsLine(line string) *models.NetworkConnection {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "TCP") && !strings.HasPrefix(line, "UDP") {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	conn := &models.NetworkConnection{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Protocol
	conn.Protocol = strings.ToLower(fields[0])

	// Local address
	m.parseAddress(fields[1], &conn.LocalAddress, &conn.LocalPort)

	// Remote address
	m.parseAddress(fields[2], &conn.RemoteAddress, &conn.RemotePort)

	// State and PID
	if conn.Protocol == "tcp" && len(fields) >= 5 {
		conn.State = fields[3]
		if pid, err := strconv.Atoi(fields[4]); err == nil {
			conn.ProcessID = pid
		}
	} else if len(fields) >= 4 {
		if pid, err := strconv.Atoi(fields[3]); err == nil {
			conn.ProcessID = pid
		}
	}

	return conn
}

// getConnectionsNetstat fallback using netstat
func (m *NetworkMonitor) getConnectionsNetstat(ctx context.Context) ([]models.NetworkConnection, error) {
	var connections []models.NetworkConnection

	cmd := exec.CommandContext(ctx, "netstat", "-anv")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
			conn := m.parseNetstatLine(line)
			if conn != nil {
				connections = append(connections, *conn)
			}
		}
	}

	return connections, nil
}

// parseNetstatLine parses netstat output
func (m *NetworkMonitor) parseNetstatLine(line string) *models.NetworkConnection {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	conn := &models.NetworkConnection{
		ID:        uuid.New(),
		Protocol:  strings.TrimSuffix(fields[0], "4"),
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}

	// Parse addresses
	m.parseAddress(fields[3], &conn.LocalAddress, &conn.LocalPort)
	if len(fields) > 4 {
		m.parseAddress(fields[4], &conn.RemoteAddress, &conn.RemotePort)
	}

	// State
	if len(fields) > 5 {
		conn.State = fields[5]
	}

	// PID (if available)
	for _, field := range fields {
		if pid, err := strconv.Atoi(field); err == nil && pid > 0 {
			conn.ProcessID = pid
			break
		}
	}

	return conn
}

// AddFirewallRule adds a firewall rule
func (m *NetworkMonitor) AddFirewallRule(rule models.FirewallRule) error {
	m.rulesMutex.Lock()
	defer m.rulesMutex.Unlock()

	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.Platform = m.platform

	m.rules = append(m.rules, rule)

	m.logger.Info().
		Str("rule_id", rule.ID.String()).
		Str("action", rule.Action).
		Str("process", rule.ProcessName).
		Msg("added firewall rule")

	return nil
}

// RemoveFirewallRule removes a firewall rule
func (m *NetworkMonitor) RemoveFirewallRule(ruleID uuid.UUID) error {
	m.rulesMutex.Lock()
	defer m.rulesMutex.Unlock()

	for i, rule := range m.rules {
		if rule.ID == ruleID {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.logger.Info().Str("rule_id", ruleID.String()).Msg("removed firewall rule")
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", ruleID)
}

// GetFirewallRules returns all firewall rules
func (m *NetworkMonitor) GetFirewallRules() []models.FirewallRule {
	m.rulesMutex.RLock()
	defer m.rulesMutex.RUnlock()

	rules := make([]models.FirewallRule, len(m.rules))
	copy(rules, m.rules)
	return rules
}

// CheckConnection checks if a connection should be allowed
func (m *NetworkMonitor) CheckConnection(conn models.NetworkConnection) (allowed bool, rule *models.FirewallRule) {
	m.rulesMutex.RLock()
	defer m.rulesMutex.RUnlock()

	// Check IOC blocklists first
	m.iocMutex.RLock()
	if reason, blocked := m.blockedIPs[conn.RemoteAddress]; blocked {
		m.iocMutex.RUnlock()
		return false, &models.FirewallRule{
			Action:      "block",
			DestAddress: conn.RemoteAddress,
			IsFromIOC:   true,
			IOCSource:   reason,
		}
	}
	m.iocMutex.RUnlock()

	// Check rules in priority order
	for _, r := range m.rules {
		if m.ruleMatches(&r, &conn) {
			// Update hit count
			r.HitCount++
			now := time.Now()
			r.LastHit = &now

			return r.Action == "allow", &r
		}
	}

	// Default: allow (or block if config says so)
	if m.config.BlockUnknown {
		return false, nil
	}
	return true, nil
}

// ruleMatches checks if a rule matches a connection
func (m *NetworkMonitor) ruleMatches(rule *models.FirewallRule, conn *models.NetworkConnection) bool {
	if !rule.Enabled {
		return false
	}

	// Check direction
	if rule.Direction == "inbound" && conn.State != "LISTEN" {
		return false
	}
	if rule.Direction == "outbound" && conn.State == "LISTEN" {
		return false
	}

	// Check protocol
	if rule.Protocol != "" && rule.Protocol != "any" && rule.Protocol != conn.Protocol {
		return false
	}

	// Check process
	if rule.ProcessName != "" && rule.ProcessName != conn.ProcessName {
		return false
	}
	if rule.ProcessPath != "" && rule.ProcessPath != conn.ProcessPath {
		return false
	}

	// Check destination
	if rule.DestAddress != "" && rule.DestAddress != "any" {
		if !m.addressMatches(rule.DestAddress, conn.RemoteAddress) {
			return false
		}
	}

	if rule.DestPort != "" && rule.DestPort != "any" {
		if !m.portMatches(rule.DestPort, conn.RemotePort) {
			return false
		}
	}

	// Check source
	if rule.SourceAddress != "" && rule.SourceAddress != "any" {
		if !m.addressMatches(rule.SourceAddress, conn.LocalAddress) {
			return false
		}
	}

	if rule.SourcePort != "" && rule.SourcePort != "any" {
		if !m.portMatches(rule.SourcePort, conn.LocalPort) {
			return false
		}
	}

	return true
}

// addressMatches checks if an address matches a rule (supports CIDR)
func (m *NetworkMonitor) addressMatches(ruleAddr, connAddr string) bool {
	if ruleAddr == connAddr {
		return true
	}

	// Try CIDR match
	_, cidr, err := net.ParseCIDR(ruleAddr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(connAddr)
	return ip != nil && cidr.Contains(ip)
}

// portMatches checks if a port matches (supports ranges like "80-443")
func (m *NetworkMonitor) portMatches(rulePort string, connPort int) bool {
	if strings.Contains(rulePort, "-") {
		parts := strings.Split(rulePort, "-")
		if len(parts) == 2 {
			low, _ := strconv.Atoi(parts[0])
			high, _ := strconv.Atoi(parts[1])
			return connPort >= low && connPort <= high
		}
	}

	port, err := strconv.Atoi(rulePort)
	if err != nil {
		return false
	}
	return port == connPort
}

// BlockIP adds an IP to the blocklist
func (m *NetworkMonitor) BlockIP(ip, reason string) {
	m.iocMutex.Lock()
	defer m.iocMutex.Unlock()
	m.blockedIPs[ip] = reason
}

// BlockDomain adds a domain to the blocklist
func (m *NetworkMonitor) BlockDomain(domain, reason string) {
	m.iocMutex.Lock()
	defer m.iocMutex.Unlock()
	m.blockedDomains[domain] = reason
}

// LoadIOCBlocklist loads IOCs from a threat feed
func (m *NetworkMonitor) LoadIOCBlocklist(ips []string, domains []string, source string) {
	m.iocMutex.Lock()
	defer m.iocMutex.Unlock()

	for _, ip := range ips {
		m.blockedIPs[ip] = source
	}
	for _, domain := range domains {
		m.blockedDomains[domain] = source
	}

	m.logger.Info().
		Int("ips", len(ips)).
		Int("domains", len(domains)).
		Str("source", source).
		Msg("loaded IOC blocklist")
}

// GetListeningPorts returns all listening ports
func (m *NetworkMonitor) GetListeningPorts(ctx context.Context) ([]models.NetworkConnection, error) {
	conns, err := m.GetConnections(ctx)
	if err != nil {
		return nil, err
	}

	var listening []models.NetworkConnection
	for _, conn := range conns {
		if conn.State == "LISTEN" {
			listening = append(listening, conn)
		}
	}

	return listening, nil
}

// GetOutboundConnections returns all outbound connections
func (m *NetworkMonitor) GetOutboundConnections(ctx context.Context) ([]models.NetworkConnection, error) {
	conns, err := m.GetConnections(ctx)
	if err != nil {
		return nil, err
	}

	var outbound []models.NetworkConnection
	for _, conn := range conns {
		if conn.State == "ESTABLISHED" && conn.RemotePort > 0 {
			outbound = append(outbound, conn)
		}
	}

	return outbound, nil
}

// AnalyzeConnection enriches a connection with threat intel
func (m *NetworkMonitor) AnalyzeConnection(conn *models.NetworkConnection) {
	// Check if remote IP is in blocklist
	m.iocMutex.RLock()
	if reason, blocked := m.blockedIPs[conn.RemoteAddress]; blocked {
		conn.IsKnownBad = true
		conn.ThreatTags = append(conn.ThreatTags, reason)
	}
	m.iocMutex.RUnlock()

	// Resolve hostname
	if conn.RemoteAddress != "" && conn.RemoteHostname == "" {
		names, err := net.LookupAddr(conn.RemoteAddress)
		if err == nil && len(names) > 0 {
			conn.RemoteHostname = strings.TrimSuffix(names[0], ".")
		}
	}

	// Check common C2 indicators
	c2Indicators := []struct {
		pattern string
		tag     string
	}{
		{`\.onion$`, "tor_hidden_service"},
		{`duckdns\.org$`, "dynamic_dns"},
		{`no-ip\.org$`, "dynamic_dns"},
		{`ddns\.net$`, "dynamic_dns"},
	}

	for _, ind := range c2Indicators {
		if matched, _ := regexp.MatchString(ind.pattern, conn.RemoteHostname); matched {
			conn.IsCnC = true
			conn.ThreatTags = append(conn.ThreatTags, ind.tag)
		}
	}

	// High-risk ports
	riskyPorts := map[int]string{
		4444: "metasploit_default",
		5555: "android_debug",
		6666: "irc_common",
		6667: "irc_common",
		8080: "proxy_common",
		9001: "tor_common",
		9050: "tor_socks",
	}

	if tag, risky := riskyPorts[conn.RemotePort]; risky {
		conn.ThreatTags = append(conn.ThreatTags, tag)
		conn.ThreatConfidence += 0.2
	}
}

// ProcessResolver resolves process information
type ProcessResolver struct {
	logger *logger.Logger
}

// NewProcessResolver creates a new process resolver
func NewProcessResolver(log *logger.Logger) *ProcessResolver {
	return &ProcessResolver{
		logger: log.WithComponent("process-resolver"),
	}
}

// GetProcessInfo gets information about a process
func (r *ProcessResolver) GetProcessInfo(pid int) (*models.ProcessInfo, error) {
	info := &models.ProcessInfo{
		PID: pid,
	}

	switch runtime.GOOS {
	case "darwin":
		return r.getProcessInfoMacOS(pid)
	case "linux":
		return r.getProcessInfoLinux(pid)
	case "windows":
		return r.getProcessInfoWindows(pid)
	}

	return info, nil
}

// getProcessInfoMacOS gets process info on macOS
func (r *ProcessResolver) getProcessInfoMacOS(pid int) (*models.ProcessInfo, error) {
	info := &models.ProcessInfo{
		PID: pid,
	}

	// Get process path using ps
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if output, err := cmd.Output(); err == nil {
		info.Path = strings.TrimSpace(string(output))
		info.Name = info.Path[strings.LastIndex(info.Path, "/")+1:]
	}

	// Get user
	cmd = exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "user=")
	if output, err := cmd.Output(); err == nil {
		info.User = strings.TrimSpace(string(output))
	}

	// Get command line
	cmd = exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "args=")
	if output, err := cmd.Output(); err == nil {
		info.CommandLine = strings.TrimSpace(string(output))
	}

	return info, nil
}

// getProcessInfoLinux gets process info on Linux
func (r *ProcessResolver) getProcessInfoLinux(pid int) (*models.ProcessInfo, error) {
	info := &models.ProcessInfo{
		PID: pid,
	}

	// Read /proc/[pid]/exe
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if path, err := os.Readlink(exePath); err == nil {
		info.Path = path
		info.Name = path[strings.LastIndex(path, "/")+1:]
	}

	// Read /proc/[pid]/cmdline
	cmdPath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if data, err := os.ReadFile(cmdPath); err == nil {
		info.CommandLine = strings.ReplaceAll(string(data), "\x00", " ")
	}

	// Read /proc/[pid]/status for user
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if data, err := os.ReadFile(statusPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if uid, err := strconv.Atoi(fields[1]); err == nil {
						if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
							info.User = u.Username
						}
					}
				}
				break
			}
		}
	}

	return info, nil
}

// getProcessInfoWindows gets process info on Windows
func (r *ProcessResolver) getProcessInfoWindows(pid int) (*models.ProcessInfo, error) {
	info := &models.ProcessInfo{
		PID: pid,
	}

	// Use wmic to get process info
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid), "get", "executablepath,name", "/format:list")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ExecutablePath=") {
				info.Path = strings.TrimPrefix(line, "ExecutablePath=")
			}
			if strings.HasPrefix(line, "Name=") {
				info.Name = strings.TrimPrefix(line, "Name=")
			}
		}
	}

	return info, nil
}
