package subscriptionexport

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func convertSingboxOutboundToClash(raw json.RawMessage) (map[string]any, bool) {
	var outbound map[string]any
	if err := json.Unmarshal(raw, &outbound); err != nil {
		return nil, false
	}

	nodeType := strings.ToLower(strings.TrimSpace(getString(outbound, "type")))
	server := strings.TrimSpace(getString(outbound, "server"))
	port, ok := getUint(outbound, "server_port", "port")
	if server == "" || !ok || port == 0 {
		return nil, false
	}

	base := map[string]any{
		"name":   defaultName(outbound, nodeType, server, port),
		"server": server,
		"port":   port,
	}

	switch nodeType {
	case "shadowsocks", "ss":
		method := strings.TrimSpace(getString(outbound, "method"))
		password := strings.TrimSpace(getString(outbound, "password"))
		if method == "" || password == "" {
			return nil, false
		}
		base["type"] = "ss"
		base["cipher"] = method
		base["password"] = password
		setShadowsocksPlugin(base, outbound)
		return base, true
	case "vmess":
		uuid := strings.TrimSpace(getString(outbound, "uuid"))
		if uuid == "" {
			return nil, false
		}
		base["type"] = "vmess"
		base["uuid"] = uuid
		base["cipher"] = firstNonEmpty(getString(outbound, "security"), "auto")
		if alterID, ok := getUint(outbound, "alter_id", "alterId", "aid"); ok {
			base["alterId"] = alterID
		} else {
			base["alterId"] = uint64(0)
		}
		setClashTLS(base, outbound, "servername", true)
		setV2RayTransport(base, outbound)
		return base, true
	case "vless":
		uuid := strings.TrimSpace(getString(outbound, "uuid"))
		if uuid == "" {
			return nil, false
		}
		base["type"] = "vless"
		base["uuid"] = uuid
		if flow := strings.TrimSpace(getString(outbound, "flow")); flow != "" {
			base["flow"] = flow
		}
		setClashTLS(base, outbound, "servername", true)
		setV2RayTransport(base, outbound)
		return base, true
	case "trojan":
		password := strings.TrimSpace(getString(outbound, "password"))
		if password == "" {
			return nil, false
		}
		base["type"] = "trojan"
		base["password"] = password
		setClashTLS(base, outbound, "sni", true)
		setV2RayTransport(base, outbound)
		return base, true
	case "hysteria":
		base["type"] = "hysteria"
		copyString(base, outbound, "auth-str", "auth_str")
		copyString(base, outbound, "auth", "auth")
		copyString(base, outbound, "up", "up")
		copyString(base, outbound, "down", "down")
		copyString(base, outbound, "obfs", "obfs")
		copyString(base, outbound, "recv-window-conn", "recv_window_conn")
		copyString(base, outbound, "recv-window", "recv_window")
		copyString(base, outbound, "hop-interval", "hop_interval")
		copyBool(base, outbound, "disable-mtu-discovery", "disable_mtu_discovery")
		if strings.EqualFold(strings.TrimSpace(getString(outbound, "network")), "udp") {
			base["protocol"] = "udp"
		}
		setPortList(base, outbound)
		setClashTLS(base, outbound, "sni", false)
		return base, true
	case "hysteria2", "hy2":
		password := strings.TrimSpace(getString(outbound, "password"))
		if password == "" {
			return nil, false
		}
		base["type"] = "hysteria2"
		base["password"] = password
		copyUint(base, outbound, "up", "up_mbps")
		copyUint(base, outbound, "down", "down_mbps")
		copyString(base, outbound, "hop-interval", "hop_interval")
		if obfs, ok := getMap(outbound, "obfs"); ok {
			copyString(base, obfs, "obfs", "type")
			copyString(base, obfs, "obfs-password", "password")
		}
		setPortList(base, outbound)
		setClashTLS(base, outbound, "sni", false)
		return base, true
	case "tuic":
		uuid := strings.TrimSpace(getString(outbound, "uuid"))
		if uuid == "" {
			return nil, false
		}
		base["type"] = "tuic"
		base["uuid"] = uuid
		copyString(base, outbound, "password", "password")
		copyString(base, outbound, "congestion-controller", "congestion_control")
		copyString(base, outbound, "udp-relay-mode", "udp_relay_mode")
		copyBool(base, outbound, "reduce-rtt", "zero_rtt_handshake")
		copyString(base, outbound, "heartbeat-interval", "heartbeat")
		if tls, ok := getMap(outbound, "tls"); ok {
			copyBool(base, tls, "disable-sni", "disable_sni")
		}
		setClashTLS(base, outbound, "sni", false)
		return base, true
	case "anytls":
		password := strings.TrimSpace(getString(outbound, "password"))
		if password == "" {
			return nil, false
		}
		base["type"] = "anytls"
		base["password"] = password
		copyString(base, outbound, "idle-session-check-interval", "idle_session_check_interval")
		copyString(base, outbound, "idle-session-timeout", "idle_session_timeout")
		copyUint(base, outbound, "min-idle-session", "min_idle_session")
		setClashTLS(base, outbound, "sni", false)
		return base, true
	case "wireguard":
		privateKey := strings.TrimSpace(getString(outbound, "private_key"))
		publicKey := firstNonEmpty(getString(outbound, "peer_public_key"), firstPeerString(outbound, "public_key"))
		if privateKey == "" || publicKey == "" {
			return nil, false
		}
		base["type"] = "wireguard"
		base["private-key"] = privateKey
		base["public-key"] = publicKey
		copyString(base, outbound, "pre-shared-key", "pre_shared_key")
		copyUint(base, outbound, "mtu", "mtu")
		setWireGuardAddresses(base, outbound)
		if allowedIPs := firstPeerStringList(outbound, "allowed_ips"); len(allowedIPs) > 0 {
			base["allowed-ips"] = allowedIPs
		}
		if reserved, ok := getAny(outbound, "reserved"); ok {
			base["reserved"] = reserved
		}
		return base, true
	default:
		return nil, false
	}
}

func defaultName(outbound map[string]any, nodeType string, server string, port uint64) string {
	if tag := strings.TrimSpace(getString(outbound, "tag", "name")); tag != "" {
		return tag
	}
	if nodeType == "" {
		nodeType = "node"
	}
	return fmt.Sprintf("%s-%s-%d", nodeType, server, port)
}

func ensureUniqueClashName(proxy map[string]any, used map[string]int, hashSuffix string) {
	name := strings.TrimSpace(fmt.Sprint(proxy["name"]))
	if name == "" {
		name = "node"
	}
	if count := used[name]; count > 0 {
		suffix := strings.TrimSpace(hashSuffix)
		if suffix == "" {
			suffix = strconv.Itoa(count + 1)
		}
		name = name + "-" + suffix
	}
	used[name]++
	proxy["name"] = name
}

func setShadowsocksPlugin(proxy map[string]any, outbound map[string]any) {
	plugin := strings.TrimSpace(getString(outbound, "plugin"))
	pluginOpts := strings.TrimSpace(getString(outbound, "plugin_opts", "plugin-opts"))
	if plugin == "" {
		return
	}

	switch strings.ToLower(plugin) {
	case "obfs-local", "simple-obfs", "obfs":
		proxy["plugin"] = "obfs"
		opts := parseSemicolonOptions(pluginOpts)
		pluginMap := map[string]any{}
		if mode := firstNonEmpty(opts["obfs"], opts["mode"]); mode != "" {
			pluginMap["mode"] = mode
		}
		if host := firstNonEmpty(opts["obfs-host"], opts["host"]); host != "" {
			pluginMap["host"] = host
		}
		if len(pluginMap) > 0 {
			proxy["plugin-opts"] = pluginMap
		}
	default:
		proxy["plugin"] = plugin
		if pluginOpts != "" {
			proxy["plugin-opts"] = pluginOpts
		}
	}
}

func setClashTLS(proxy map[string]any, outbound map[string]any, serverNameKey string, includeTLSFlag bool) {
	tls, ok := getMap(outbound, "tls")
	if !ok {
		return
	}
	enabled, enabledSet := getBool(tls, "enabled")
	if enabledSet && !enabled {
		if includeTLSFlag {
			proxy["tls"] = false
		}
		return
	}
	if includeTLSFlag {
		proxy["tls"] = true
	}
	if serverName := strings.TrimSpace(getString(tls, "server_name", "servername", "sni")); serverName != "" {
		proxy[serverNameKey] = serverName
	}
	if insecure, ok := getBool(tls, "insecure"); ok {
		proxy["skip-cert-verify"] = insecure
	}
	if alpn := getStringList(tls, "alpn"); len(alpn) > 0 {
		proxy["alpn"] = alpn
	}
	if utls, ok := getMap(tls, "utls"); ok {
		if fingerprint := strings.TrimSpace(getString(utls, "fingerprint")); fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
	}
	if reality, ok := getMap(tls, "reality"); ok {
		opts := map[string]any{}
		if publicKey := strings.TrimSpace(getString(reality, "public_key")); publicKey != "" {
			opts["public-key"] = publicKey
		}
		if shortID := strings.TrimSpace(getString(reality, "short_id")); shortID != "" {
			opts["short-id"] = shortID
		}
		if len(opts) > 0 {
			proxy["reality-opts"] = opts
		}
	}
}

func setV2RayTransport(proxy map[string]any, outbound map[string]any) {
	transport, ok := getMap(outbound, "transport")
	if !ok {
		return
	}
	switch strings.ToLower(strings.TrimSpace(getString(transport, "type"))) {
	case "ws", "websocket":
		proxy["network"] = "ws"
		opts := map[string]any{}
		copyString(opts, transport, "path", "path")
		if headers, ok := getMap(transport, "headers"); ok && len(headers) > 0 {
			opts["headers"] = headers
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	case "grpc":
		proxy["network"] = "grpc"
		opts := map[string]any{}
		copyString(opts, transport, "grpc-service-name", "service_name")
		if len(opts) > 0 {
			proxy["grpc-opts"] = opts
		}
	case "http", "h2":
		proxy["network"] = "h2"
		opts := map[string]any{}
		copyString(opts, transport, "path", "path")
		if hosts := getStringList(transport, "host"); len(hosts) > 0 {
			opts["host"] = hosts
		}
		if len(opts) > 0 {
			proxy["h2-opts"] = opts
		}
	case "quic":
		proxy["network"] = "quic"
	case "httpupgrade", "http-upgrade":
		proxy["network"] = "httpupgrade"
		opts := map[string]any{}
		copyString(opts, transport, "path", "path")
		copyString(opts, transport, "host", "host")
		if headers, ok := getMap(transport, "headers"); ok && len(headers) > 0 {
			opts["headers"] = headers
		}
		if len(opts) > 0 {
			proxy["http-upgrade-opts"] = opts
		}
	}
}

func setPortList(proxy map[string]any, outbound map[string]any) {
	ports := getStringList(outbound, "server_ports")
	if len(ports) == 0 {
		return
	}
	proxy["ports"] = strings.Join(ports, ",")
}

func setWireGuardAddresses(proxy map[string]any, outbound map[string]any) {
	for _, address := range getStringList(outbound, "local_address") {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		key := "ip"
		if strings.Contains(address, ":") {
			key = "ipv6"
		}
		if _, exists := proxy[key]; !exists {
			proxy[key] = address
		}
	}
}

func firstPeerString(outbound map[string]any, key string) string {
	for _, peer := range getMapList(outbound, "peers") {
		if value := strings.TrimSpace(getString(peer, key)); value != "" {
			return value
		}
	}
	return ""
}

func firstPeerStringList(outbound map[string]any, key string) []string {
	for _, peer := range getMapList(outbound, "peers") {
		if values := getStringList(peer, key); len(values) > 0 {
			return values
		}
	}
	return nil
}

func parseSemicolonOptions(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}

func copyString(dst map[string]any, src map[string]any, dstKey string, srcKeys ...string) {
	if value := strings.TrimSpace(getString(src, srcKeys...)); value != "" {
		dst[dstKey] = value
	}
}

func copyUint(dst map[string]any, src map[string]any, dstKey string, srcKeys ...string) {
	if value, ok := getUint(src, srcKeys...); ok {
		dst[dstKey] = value
	}
}

func copyBool(dst map[string]any, src map[string]any, dstKey string, srcKeys ...string) {
	if value, ok := getBool(src, srcKeys...); ok {
		dst[dstKey] = value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func getAny(m map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := m[key]; ok && value != nil {
			return value, true
		}
	}
	return nil, false
}

func getString(m map[string]any, keys ...string) string {
	value, ok := getAny(m, keys...)
	if !ok {
		return ""
	}
	switch t := value.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case fmt.Stringer:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

func getUint(m map[string]any, keys ...string) (uint64, bool) {
	value, ok := getAny(m, keys...)
	if !ok {
		return 0, false
	}
	switch t := value.(type) {
	case uint64:
		return t, true
	case int:
		if t >= 0 {
			return uint64(t), true
		}
	case int64:
		if t >= 0 {
			return uint64(t), true
		}
	case float64:
		if t >= 0 && t == float64(uint64(t)) {
			return uint64(t), true
		}
	case json.Number:
		v, err := strconv.ParseUint(t.String(), 10, 64)
		return v, err == nil
	case string:
		v, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		return v, err == nil
	}
	return 0, false
}

func getBool(m map[string]any, keys ...string) (bool, bool) {
	value, ok := getAny(m, keys...)
	if !ok {
		return false, false
	}
	switch t := value.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		}
	case float64:
		if t == 1 {
			return true, true
		}
		if t == 0 {
			return false, true
		}
	}
	return false, false
}

func getMap(m map[string]any, keys ...string) (map[string]any, bool) {
	value, ok := getAny(m, keys...)
	if !ok {
		return nil, false
	}
	switch t := value.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		out := make(map[string]any, len(t))
		for key, val := range t {
			out[fmt.Sprint(key)] = val
		}
		return out, true
	default:
		return nil, false
	}
}

func getMapList(m map[string]any, keys ...string) []map[string]any {
	value, ok := getAny(m, keys...)
	if !ok {
		return nil
	}
	switch t := value.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			switch typed := item.(type) {
			case map[string]any:
				out = append(out, typed)
			case map[any]any:
				converted := make(map[string]any, len(typed))
				for key, val := range typed {
					converted[fmt.Sprint(key)] = val
				}
				out = append(out, converted)
			}
		}
		return out
	default:
		return nil
	}
}

func getStringList(m map[string]any, keys ...string) []string {
	value, ok := getAny(m, keys...)
	if !ok {
		return nil
	}
	switch t := value.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		raw := strings.TrimSpace(t)
		if raw == "" {
			return nil
		}
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}
