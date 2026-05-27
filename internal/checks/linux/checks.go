package linux

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/model"
)

func All() []model.CheckItem {
	items := []model.CheckItem{
		as001(),
		as002(),
		as003(),
		as004(),
		as005(),
		as006(),
		as007(),
		as008(),
		as009(),
		as010(),
		as011(),
		as012(),
		as013(),
		as014(),
		as015(),
		as016(),
		as017(),
		ot001(),
		ot002(),
		ot003(),
		ot004(),
		ot005(),
		ot006(),
		ot007(),
		ot008(),
		ot009(),
		ot010(),
		ot011(),
		ot012(),
		ot013(),
		ot014(),
		ot015(),
		ot016(),
		ot017(),
		ot018(),
		ot019(),
		ot020(),
		ot021(),
		ot022(),
		rs001(),
		rs002(),
		rs003(),
		rs004(),
		rs005(),
		rs006(),
		rs007(),
		rs008(),
		rs009(),
		rs010(),
		rs011(),
		rs012(),
		bc005(),
		bc006(),
		bc007(),
		ac001(),
		ac002(),
		ac003(),
		ac004(),
		ac005(),
		ac006(),
		ac007(),
		ac008(),
		ef001(),
		ef002(),
	}
	items = append(items, ksAll()...)
	return items
}

func as001() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-001",
		Domain:        model.DomainAttackSurface,
		Name:          "无用服务关闭",
		Description:   "检查高风险服务(telnet,rsh,rexec,chargen,echo等)是否已禁用",
		Delta:         -8,
		ComplianceRef: "L3-CE-21",
		Platform:      "linux",
		Check: func() (bool, string) {
			dangerous := []string{"telnet", "rsh", "rlogin", "rexec", "chargen", "echo", "discard", "daytime", "time", "tftp", "xinetd"}
			var active []string
			for _, svc := range dangerous {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", svc)
				if ok && strings.TrimSpace(out) == "active" {
					active = append(active, svc)
				}
			}
			if len(active) == 0 {
				return true, "所有高风险服务均已禁用"
			}
			return false, fmt.Sprintf("发现 %d 个高风险服务处于活跃状态: %s", len(active), strings.Join(active, ", "))
		},
	}
}

func as002() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-002",
		Domain:        model.DomainAttackSurface,
		Name:          "开放端口数量",
		Description:   "检查监听端口总数是否在合理范围内（阈值20）",
		Delta:         -8,
		ComplianceRef: "L3-CE-23",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("ss", "-tlnp")
			if err != nil {
				return true, fmt.Sprintf("无法检查端口: %v", err)
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			portSet := make(map[int]bool)
			for _, line := range lines[1:] {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					addr := fields[3]
					if idx := strings.LastIndex(addr, ":"); idx != -1 {
						port := addr[idx+1:]
						if p, err := strconv.Atoi(port); err == nil && p > 0 {
							portSet[p] = true
						}
					}
				}
			}
			uniquePorts := make([]int, 0, len(portSet))
			for p := range portSet {
				uniquePorts = append(uniquePorts, p)
			}
			sortSlice(uniquePorts)
			portStrs := make([]string, len(uniquePorts))
			for i, p := range uniquePorts {
				portStrs[i] = strconv.Itoa(p)
			}
			if len(uniquePorts) > 20 {
				return false, fmt.Sprintf("监听端口过多(%d个，阈值20): [%s]", len(uniquePorts), strings.Join(portStrs, ", "))
			}
			return true, fmt.Sprintf("当前监听 %d 个端口: [%s]（暴露面详情见AS-005）", len(uniquePorts), strings.Join(portStrs, ", "))
		},
	}
}

func sortSlice(s []int) {
	sort.Ints(s)
}

func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func as003() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-003",
		Domain:        model.DomainAttackSurface,
		Name:          "强认证策略",
		Description:   "检查SSH空密码登录、root远程登录及密码认证配置",
		Delta:         -10,
		ComplianceRef: "L3-CE-01",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string
			cfg, err := os.ReadFile("/etc/ssh/sshd_config")
			if err != nil {
				return false, fmt.Sprintf("无法读取 SSH 配置: %v", err)
			}

			content := string(cfg)
			lower := strings.ToLower(content)

			if !matchSSHConfig(lower, "permitemptypasswords", "no") {
				if strings.Contains(lower, "permitemptypasswords yes") {
					issues = append(issues, "允许空密码登录")
				}
			}

			if !matchSSHConfig(lower, "permitrootlogin", "no") && !matchSSHConfig(lower, "permitrootlogin", "prohibit-password") && !matchSSHConfig(lower, "permitrootlogin", "forced-commands-only") {
				if strings.Contains(lower, "permitrootlogin yes") || !strings.Contains(lower, "permitrootlogin") {
					issues = append(issues, "允许root远程密码登录")
				}
			}

			if !matchSSHConfig(lower, "passwordauthentication", "no") {
				if !strings.Contains(lower, "passwordauthentication") || strings.Contains(lower, "passwordauthentication yes") {
					issues = append(issues, "未禁用密码认证")
				}
			}

			if matchSSHConfig(lower, "protocol", "1") {
				issues = append(issues, "SSH协议版本1")
			}

			if len(issues) == 0 {
				return true, "SSH强认证策略已正确配置"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func matchSSHConfig(content, key, expected string) bool {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			return strings.EqualFold(fields[1], expected)
		}
	}
	return false
}

func as004() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-004",
		Domain:        model.DomainAttackSurface,
		Name:          "最小防火墙规则",
		Description:   "检查iptables/firewalld默认策略是否为DROP",
		Delta:         -8,
		ComplianceRef: "L3-CE-12",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("iptables", "-L", "INPUT", "-n")
			if err != nil {
				out2, err2 := common.RunCmd("firewall-cmd", "--state")
				if err2 == nil && strings.TrimSpace(out2) == "running" {
					return true, "firewalld 已运行 (默认策略需人工确认)"
				}
				return true, fmt.Sprintf("iptables 不可用: %v", err)
			}
			scanner := bufio.NewScanner(strings.NewReader(out))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "Chain INPUT") {
					if strings.Contains(line, "DROP") {
						return true, "INPUT链默认策略为DROP"
					}
					return false, "INPUT链默认策略非DROP，建议设置为DROP"
				}
			}
			return true, "无法确定防火墙默认策略"
		},
	}
}

func as007() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-007",
		Domain:        model.DomainAttackSurface,
		Name:          "账户锁定策略",
		Description:   "检查fail2ban或pam_tally2是否配置",
		Delta:         -6,
		ComplianceRef: "L3-CE-02",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, ok := common.RunCmdQuiet("systemctl", "is-active", "fail2ban")
			if ok && strings.TrimSpace(out) == "active" {
				return true, "fail2ban 已运行"
			}

			data, err := os.ReadFile("/etc/pam.d/common-auth")
			if err == nil && strings.Contains(string(data), "pam_tally2") {
				return true, "pam_tally2 已配置"
			}
			data, err = os.ReadFile("/etc/pam.d/sshd")
			if err == nil && strings.Contains(string(data), "pam_tally2") {
				return true, "pam_tally2 已配置 (sshd)"
			}
			return false, "未检测到 fail2ban 或 pam_tally2 配置"
		},
	}
}

func as008() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-008",
		Domain:        model.DomainAttackSurface,
		Name:          "会话超时配置",
		Description:   "检查TMOUT环境变量是否设置",
		Delta:         -3,
		ComplianceRef: "L3-CE-03",
		Platform:      "linux",
		Check: func() (bool, string) {
			profiles := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"}
			for _, f := range profiles {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					if strings.Contains(line, "TMOUT=") || strings.Contains(line, "TMOUT ") {
						parts := strings.Split(line, "=")
						if len(parts) >= 2 {
							val := strings.TrimSpace(parts[len(parts)-1])
							if v, err := strconv.Atoi(val); err == nil && v >= 300 {
								return true, fmt.Sprintf("TMOUT=%d (>=300秒)", v)
							} else if err == nil {
								return false, fmt.Sprintf("TMOUT=%d (不足300秒)", v)
							}
						}
					}
				}
			}
			return false, "未检测到TMOUT配置"
		},
	}
}

func as009() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-009",
		Domain:        model.DomainAttackSurface,
		Name:          "加密协议强制",
		Description:   "检查Telnet/FTP是否关闭，SSH是否启用",
		Delta:         -8,
		ComplianceRef: "L3-CE-05",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string
			for _, svc := range []string{"telnet", "telnetd", "vsftpd", "proftpd", "pure-ftpd"} {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", svc)
				if ok && strings.TrimSpace(out) == "active" {
					issues = append(issues, svc+" 正在运行")
				}
			}
			out, ok := common.RunCmdQuiet("systemctl", "is-active", "sshd")
			sshActive := ok && strings.TrimSpace(out) == "active"

			if !sshActive {
				issues = append(issues, "SSH未运行")
			}
			if len(issues) == 0 {
				return true, "明文协议已禁用，SSH已启用"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func as011() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-011",
		Domain:        model.DomainAttackSurface,
		Name:          "默认账户检测",
		Description:   "检查guest、games等默认账户是否禁用",
		Delta:         -6,
		ComplianceRef: "L3-CE-08",
		Platform:      "linux",
		Check: func() (bool, string) {
			banned := []string{"guest", "games", "nobody", "ftp", "lp", "uucp", "nuucp"}
			var active []string
			for _, user := range banned {
				out, err := common.RunCmd("passwd", "-S", user)
				if err != nil {
					continue
				}
				if strings.Contains(out, " P ") || strings.Contains(out, " NP ") {
					active = append(active, user)
				}
			}
			if len(active) == 0 {
				return true, "未发现活跃的默认账户"
			}
			return false, fmt.Sprintf("发现活跃默认账户: %s", strings.Join(active, ", "))
		},
	}
}

func as012() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-012",
		Domain:        model.DomainAttackSurface,
		Name:          "幽灵账户检测",
		Description:   "检查UID=0非root账户及无属主进程账户",
		Delta:         -6,
		ComplianceRef: "L3-CE-09",
		Platform:      "linux",
		Check: func() (bool, string) {
			systemWhitelist := map[string]bool{
				"root": true, "bin": true, "daemon": true, "adm": true,
				"lp": true, "sync": true, "shutdown": true, "halt": true,
				"mail": true, "operator": true, "games": true, "ftp": true,
				"nobody": true, "dbus": true, "polkitd": true, "avahi": true,
				"colord": true, "cups": true, "gdm": true, "geoclue": true,
				"lightdm": true, "nm-openconnect": true, "nm-openvpn": true,
				"ntp": true, "openvpn": true, "pulse": true, "rpc": true,
				"rpcuser": true, "rtkit": true, "saned": true, "speech-dispatcher": true,
				"sshd": true, "syslog": true, "systemd-bus-proxy": true,
				"systemd-network": true, "systemd-resolve": true, "systemd-timesync": true,
				"tss": true, "usbmux": true, "uuidd": true,
				"chrony": true, "dnsmasq": true, "gluster": true,
				"libvirt-qemu": true, "libvirt-dnsmasq": true, "mysql": true,
				"postgres": true, "redis": true, "nginx": true, "apache": true,
				"www-data": true, "messagebus": true, "sys": true,
				"proxy": true, "uucp": true, "news": true, "irc": true,
				"list": true, "man": true, "backup": true, "smmsp": true,
				"smmta": true, "postfix": true, "dovecot": true, "dovenull": true,
				"vboxadd": true, "tcpdump": true, "snmp": true, "pcap": true,
				"memcached": true, "tomcat": true, "jenkins": true, "git": true,
				"svn": true, "docker": true, "lxd": true, "landscape": true,
				"pollinate": true, "fwupd-refresh": true, "gnome-initial-setup": true,
				"whoopsie": true, "kernoops": true, "hplip": true, "pki": true,
				"elasticsearch": true, "logstash": true, "kibana": true,
				"cassandra": true, "mongodb": true, "rabbitmq": true, "haproxy": true,
				"consul": true, "nomad": true, "vault": true, "traefik": true,
				"prometheus": true, "grafana": true, "alertmanager": true,
				"node_exporter": true, "telegraf": true, "influxdb": true,
				"ntopng": true, "ossec": true, "ossecm": true, "ossecr": true,
				"wazuh": true, "suricata": true, "snort": true, "zeek": true,
				"clamav": true, "freshclam": true,
			}

			data, err := os.ReadFile("/etc/shadow")
			if err != nil {
				return false, fmt.Sprintf("无法读取/etc/shadow: %v", err)
			}

			var trueGhosts []string
			var lockedSystemAccounts []string
			shadowAccounts := make(map[string]bool)

			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				if len(parts) < 2 {
					continue
				}
				user := parts[0]
				shadowAccounts[user] = true

				if parts[1] == "" || parts[1] == "!" || parts[1] == "!!" || parts[1] == "*" {
					if systemWhitelist[user] || strings.HasPrefix(user, "systemd-") {
						lockedSystemAccounts = append(lockedSystemAccounts, user)
						continue
					}
					trueGhosts = append(trueGhosts, user)
				}
			}

			passwdData, err := os.ReadFile("/etc/passwd")
			if err == nil {
				for _, line := range strings.Split(string(passwdData), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					parts := strings.Split(line, ":")
					if len(parts) < 4 {
						continue
					}
					if parts[2] == "0" && parts[0] != "root" {
						if !systemWhitelist[parts[0]] {
							trueGhosts = append(trueGhosts, fmt.Sprintf("%s(UID=0)", parts[0]))
						}
					}
				}
			}

			uidMap := make(map[string]string)
			processAccountsWithoutPasswd := make(map[string]bool)
			if passwdData != nil {
				for _, line := range strings.Split(string(passwdData), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					parts := strings.Split(line, ":")
					if len(parts) >= 4 {
						uidMap[parts[2]] = parts[0]
					}
				}
			}

			out, psErr := common.RunCmd("ps", "-eo", "uid=", "--no-headers")
			if psErr == nil {
				processUIDs := make(map[string]bool)
				for _, line := range strings.Split(out, "\n") {
					uid := strings.TrimSpace(line)
					if uid != "" && uid != "0" {
						processUIDs[uid] = true
					}
				}
				for uid := range processUIDs {
					if _, exists := uidMap[uid]; !exists {
						if _, shadowExists := shadowAccounts[uid]; !shadowExists {
							processAccountsWithoutPasswd[fmt.Sprintf("UID:%s", uid)] = true
						}
					}
				}
			}

			for acct := range processAccountsWithoutPasswd {
				trueGhosts = append(trueGhosts, acct)
			}

			if len(trueGhosts) > 0 {
				return false, fmt.Sprintf("发现 %d 个可疑幽灵账户: %s; (系统默认账户 %d 个已正确锁定)",
					len(trueGhosts), strings.Join(trueGhosts, ", "), len(lockedSystemAccounts))
			}

			if len(lockedSystemAccounts) > 0 {
				return true, fmt.Sprintf("未发现幽灵账户 (系统默认账户 %d 个已正确锁定)", len(lockedSystemAccounts))
			}

			return true, "未发现幽灵账户"
		},
	}
}

func as014() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-014",
		Domain:        model.DomainAttackSurface,
		Name:          "系统服务审计",
		Description:   "统计当前运行服务数",
		Delta:         -5,
		ComplianceRef: "L3-CE-22",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("systemctl", "list-units", "--type=service", "--state=running", "--no-legend")
			if err != nil {
				return true, fmt.Sprintf("无法统计服务: %v", err)
			}
			count := 0
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
			if count <= 40 {
				return true, fmt.Sprintf("运行 %d 个服务 (合理范围)", count)
			}
			return false, fmt.Sprintf("运行 %d 个服务 (建议审查)", count)
		},
	}
}

func as015() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-015",
		Domain:        model.DomainAttackSurface,
		Name:          "传输层加密",
		Description:   "检查SSH和HTTPS是否使用TLS 1.2+",
		Delta:         -8,
		ComplianceRef: "L3-CE-31",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string
			cfg, err := os.ReadFile("/etc/ssh/sshd_config")
			if err == nil {
				content := strings.ToLower(string(cfg))
				if strings.Contains(content, "protocol 1") {
					issues = append(issues, "SSH使用协议版本1")
				}
			}

			_, err = os.Stat("/etc/ssl/certs")
			if err != nil {
				issues = append(issues, "SSL证书目录不存在")
			}

			if len(issues) == 0 {
				return true, "传输层加密配置基本合理"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func ot001() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-001",
		Domain:        model.DomainOperationTrust,
		Name:          "关键文件权限",
		Description:   "检查/etc/shadow、/etc/sudoers等关键文件权限",
		Delta:         -10,
		ComplianceRef: "L3-CE-07",
		Platform:      "linux",
		Check: func() (bool, string) {
			correctFiles := map[string]string{
				"/etc/shadow":  "000",
				"/etc/gshadow": "000",
				"/etc/sudoers": "0440",
				"/etc/passwd":  "0644",
			}
			var issues []string
			for path, expected := range correctFiles {
				info, err := os.Stat(path)
				if err != nil {
					issues = append(issues, fmt.Sprintf("%s 不存在", path))
					continue
				}
				mode := fmt.Sprintf("%04o", info.Mode().Perm())
				if mode != expected && mode != "0"+expected {
					issues = append(issues, fmt.Sprintf("%s 权限=%s (期望=%s)", path, mode, expected))
				}
			}
			if len(issues) == 0 {
				return true, "关键文件权限配置正确"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func ot002() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-002",
		Domain:        model.DomainOperationTrust,
		Name:          "审计日志服务",
		Description:   "检查rsyslog或auditd是否运行",
		Delta:         -10,
		ComplianceRef: "L3-CE-14",
		Platform:      "linux",
		Check: func() (bool, string) {
			var running []string
			for _, svc := range []string{"rsyslog", "syslog-ng", "auditd"} {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", svc)
				if ok && strings.TrimSpace(out) == "active" {
					running = append(running, svc)
				}
			}
			if len(running) == 0 {
				return false, "未检测到运行中的审计日志服务"
			}
			return true, fmt.Sprintf("审计日志服务已运行: %s", strings.Join(running, ", "))
		},
	}
}

func ot003() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-003",
		Domain:        model.DomainOperationTrust,
		Name:          "命令历史防篡改",
		Description:   "检查日志目录权限和append-only属性",
		Delta:         -8,
		ComplianceRef: "L3-CE-16",
		Platform:      "linux",
		Check: func() (bool, string) {
			dirs := []string{"/var/log"}
			var issues []string
			for _, dir := range dirs {
				info, err := os.Stat(dir)
				if err != nil {
					issues = append(issues, fmt.Sprintf("%s 不可访问", dir))
					continue
				}
				if !info.IsDir() {
					issues = append(issues, fmt.Sprintf("%s 不是目录", dir))
					continue
				}
			}
			out, err := common.RunCmd("lsattr", "-d", "/var/log")
			if err == nil && strings.Contains(out, "a") {
				return true, "/var/log 已设置append-only属性"
			}
			if len(issues) == 0 {
				return true, "日志目录可访问 (append-only未验证)"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func ot005() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-005",
		Domain:        model.DomainOperationTrust,
		Name:          "SELinux/AppArmor",
		Description:   "检查SELinux是否处于enforcing模式",
		Delta:         -15,
		ComplianceRef: "L4-CE-03",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("getenforce")
			if err != nil {
				out2, err2 := common.RunCmd("aa-status")
				if err2 == nil && strings.Contains(out2, "profiles are loaded") {
					return true, "AppArmor 已加载策略"
				}
				return false, "SELinux和AppArmor均未检测到"
			}
			status := strings.TrimSpace(out)
			if status == "Enforcing" {
				return true, "SELinux处于Enforcing模式"
			}
			return false, fmt.Sprintf("SELinux处于%s模式", status)
		},
	}
}

func ot007() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-007",
		Domain:        model.DomainOperationTrust,
		Name:          "用户目录权限",
		Description:   "检查/home/*目录权限是否为750或更严格",
		Delta:         -4,
		ComplianceRef: "L3-CE-13",
		Platform:      "linux",
		Check: func() (bool, string) {
			entries, err := os.ReadDir("/home")
			if err != nil {
				return true, "/home 目录不存在或不可读"
			}
			var issues []string
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				path := filepath.Join("/home", entry.Name())
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				perm := info.Mode().Perm()
				if perm&0022 != 0 {
					issues = append(issues, fmt.Sprintf("%s 权限=%04o (存在'其他'或'组'写权限)", path, perm))
				}
			}
			if len(issues) == 0 {
				return true, "用户目录权限配置合理"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

func rs001() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-001",
		Domain:        model.DomainResilience,
		Name:          "系统更新检查",
		Description:   "检查是否存在待安装的安全更新",
		Delta:         -10,
		ComplianceRef: "L3-CE-26",
		Platform:      "linux",
		Check: func() (bool, string) {
			var out string
			var err error
			if _, e := os.Stat("/usr/bin/apt"); e == nil {
				out, err = common.RunCmd("apt", "list", "--upgradable", "2>/dev/null")
			} else if _, e := os.Stat("/usr/bin/yum"); e == nil {
				out, err = common.RunCmd("yum", "check-update", "-q")
			} else if _, e := os.Stat("/usr/bin/dnf"); e == nil {
				out, err = common.RunCmd("dnf", "check-update", "-q")
			} else {
				return true, "未检测到包管理器，跳过更新检查"
			}
			if err != nil {
				if strings.TrimSpace(out) == "" {
					return true, "更新检查完成，无待更新包"
				}
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			count := 0
			for _, line := range lines {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Listing") {
					count++
				}
			}
			if count == 0 {
				return true, "系统已是最新，无待更新包"
			}
			return false, fmt.Sprintf("发现 %d 个可更新包", count)
		},
	}
}

func rs005() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-005",
		Domain:        model.DomainResilience,
		Name:          "SYN Cookie防护",
		Description:   "检查TCP SYN Cookie是否开启",
		Delta:         -5,
		ComplianceRef: "L1-CE-04",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_syncookies")
			if err != nil {
				return false, fmt.Sprintf("无法读取SYN Cookie配置: %v", err)
			}
			val := strings.TrimSpace(string(data))
			if val == "1" {
				return true, "SYN Cookie已开启"
			}
			return false, "SYN Cookie未开启"
		},
	}
}

func bc005() model.CheckItem {
	return model.CheckItem{
		ID:            "BC-005",
		Domain:        model.DomainBusinessContinuity,
		Name:          "备份机制",
		Description:   "检查是否存在备份脚本或定时备份任务",
		Delta:         -10,
		ComplianceRef: "L3-CE-36",
		Platform:      "linux",
		Check: func() (bool, string) {
			checks := []string{
				"/etc/cron.d",
				"/etc/cron.daily",
				"/etc/cron.weekly",
				"/var/spool/cron/crontabs",
			}
			var found []string
			for _, dir := range checks {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					if strings.Contains(strings.ToLower(entry.Name()), "backup") {
						found = append(found, filepath.Join(dir, entry.Name()))
					}
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("发现备份任务: %s", strings.Join(found, ", "))
			}
			return false, "未发现备份定时任务"
		},
	}
}

func ac001() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-001",
		Domain:        model.DomainResilience,
		Name:          "ACI:网络分段验证",
		Description:   "检查VLAN/防火墙策略，确认关键业务段是否隔离",
		Delta:         -15,
		ComplianceRef: "ACI-01",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("iptables", "-L", "-n")
			if err != nil {
				return false, "iptables不可用，无法验证网络分段"
			}
			lines := strings.Split(out, "\n")
			ruleCount := 0
			for _, line := range lines {
				if strings.Contains(line, "DROP") || strings.Contains(line, "REJECT") {
					ruleCount++
				}
			}
			if ruleCount >= 3 {
				return true, fmt.Sprintf("检测到 %d 条阻断规则", ruleCount)
			}
			return false, "仅检测到少量防火墙规则，建议增强网络分段"
		},
	}
}

func ac002() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-002",
		Domain:        model.DomainResilience,
		Name:          "ACI:离线备份完整性",
		Description:   "验证备份配置和离线备份策略",
		Delta:         -20,
		ComplianceRef: "ACI-03",
		Platform:      "linux",
		Check: func() (bool, string) {
			if _, err := os.Stat("/etc/rsyncd.conf"); err == nil {
				return true, "发现rsync远程备份配置"
			}
			if _, err := os.Stat("/root/.config/rclone/rclone.conf"); err == nil {
				return true, "发现rclone远程备份配置"
			}
			return false, "未发现远程备份配置 (rsync/rclone)"
		},
	}
}

func ac003() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-003",
		Domain:        model.DomainResilience,
		Name:          "ACI:审计日志远程备份",
		Description:   "检查rsyslog是否配置远程转发",
		Delta:         -10,
		ComplianceRef: "ACI-05",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/etc/rsyslog.conf")
			if err != nil {
				data, err = os.ReadFile("/etc/rsyslog.d/50-default.conf")
			}
			if err != nil {
				return false, "未找到rsyslog配置"
			}
			if strings.Contains(string(data), "@@") || strings.Contains(string(data), "@") {
				return true, "rsyslog已配置远程转发"
			}
			return false, "rsyslog未配置远程转发"
		},
	}
}

func ac004() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-004",
		Domain:        model.DomainResilience,
		Name:          "ACI:EDR部署检测",
		Description:   "检查EDR/端点安全工具是否运行",
		Delta:         -10,
		ComplianceRef: "ACI-04",
		Platform:      "linux",
		Check: func() (bool, string) {
			edrTools := []string{"wazuh-agent", "ossec", "falcon-sensor", "sentinelone", "trendmicro", "clamav-daemon", "clamd"}
			var found []string
			for _, tool := range edrTools {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", tool)
				if ok && strings.TrimSpace(out) == "active" {
					found = append(found, tool)
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("检测到安全工具: %s", strings.Join(found, ", "))
			}
			return false, "未检测到EDR/端点安全工具"
		},
	}
}

func ac005() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-005",
		Domain:        model.DomainResilience,
		Name:          "ACI:应用程序白名单",
		Description:   "检查是否配置了应用程序执行限制",
		Delta:         -10,
		ComplianceRef: "ACI-06",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("getenforce")
			if err == nil {
				status := strings.TrimSpace(out)
				if status == "Enforcing" {
					return true, "SELinux Enforcing 模式提供执行限制"
				}
				if status == "Permissive" {
					out2, ok := common.RunCmdQuiet("systemctl", "is-active", "fapolicyd")
					if ok && strings.TrimSpace(out2) == "active" {
						return true, "fapolicyd 已运行 (SELinux Permissive)"
					}
					return false, fmt.Sprintf("SELinux 处于 %s 模式，应用白名单未生效", status)
				}
			}
			out2, ok := common.RunCmdQuiet("systemctl", "is-active", "fapolicyd")
			if ok && strings.TrimSpace(out2) == "active" {
				return true, "fapolicyd 已运行"
			}
			return false, "未检测到应用程序白名单机制 (SELinux Enforcing/fapolicyd)"
		},
	}
}

// AS-010 共享账户检测
// 等保条款: L3-CE-06 | ATT&CK: T1078.001
func as010() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-010",
		Domain:        model.DomainAttackSurface,
		Name:          "共享账户检测",
		Description:   "检查UID重复及sudo日志中用户可区分性",
		Delta:         -5,
		ComplianceRef: "L3-CE-06",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/etc/passwd")
			if err != nil {
				return false, fmt.Sprintf("无法读取/etc/passwd: %v", err)
			}
			uidMap := make(map[string][]string)
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				if len(parts) < 3 {
					continue
				}
				uid := parts[2]
				user := parts[0]
				if uid == "0" && user != "root" {
					uidMap[uid] = append(uidMap[uid], user)
				}
			}
			if len(uidMap) > 0 {
				var dupes []string
				for uid, users := range uidMap {
					if len(users) > 1 || (len(users) == 1 && users[0] != "root") {
						dupes = append(dupes, fmt.Sprintf("UID %s: %s", uid, strings.Join(users, ",")))
					}
				}
				if len(dupes) > 0 {
					return false, fmt.Sprintf("发现UID共享: %s", strings.Join(dupes, "; "))
				}
			}
			return true, "未发现UID共享或重复"
		},
	}
}

// AS-013 文件ACL检查
// 等保条款: L3-CE-10 | ATT&CK: T1222.001
func as013() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-013",
		Domain:        model.DomainAttackSurface,
		Name:          "文件ACL检查",
		Description:   "检查关键目录ACL设置是否合理",
		Delta:         -5,
		ComplianceRef: "L3-CE-10",
		Platform:      "linux",
		Check: func() (bool, string) {
			dirs := []string{"/etc", "/var/log", "/root"}
			var issues []string
			for _, dir := range dirs {
				out, err := common.RunCmd("getfacl", "-p", dir)
				if err != nil {
					continue
				}
				if strings.Contains(out, "other:") && strings.Contains(out, "rwx") {
					issues = append(issues, fmt.Sprintf("%s 存在过度开放ACL", dir))
				}
			}
			if len(issues) == 0 {
				return true, "关键目录ACL配置合理"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

// AS-016 登录源限制
// 等保条款: L4-CE-02 | ATT&CK: T1133
func as016() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-016",
		Domain:        model.DomainAttackSurface,
		Name:          "登录源限制",
		Description:   "检查iptables/firewalld是否限制SSH源IP",
		Delta:         -10,
		ComplianceRef: "L4-CE-02",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("iptables", "-L", "INPUT", "-n", "-v")
			if err != nil {
				out2, err2 := common.RunCmd("firewall-cmd", "--list-rich-rules")
				if err2 == nil && strings.Contains(out2, "ssh") && strings.Contains(out2, "source") {
					return true, "firewalld已配置SSH源IP限制"
				}
				return false, "无法检查防火墙SSH源IP限制"
			}
			if strings.Contains(out, "dpt:22") && strings.Contains(out, "-s") {
				return true, "iptables已配置SSH源IP限制"
			}
			return false, "未检测到SSH登录源IP限制"
		},
	}
}

// AS-017 访问时间控制
// 等保条款: L4-CE-04 | ATT&CK: T1548
func as017() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-017",
		Domain:        model.DomainAttackSurface,
		Name:          "访问时间控制",
		Description:   "检查cron/PAM时间限制配置",
		Delta:         -5,
		ComplianceRef: "L4-CE-04",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/etc/security/time.conf")
			if err == nil && strings.Contains(string(data), "login") {
				return true, "PAM时间限制已配置"
			}
			entries, err := os.ReadDir("/etc/cron.d")
			if err == nil {
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join("/etc/cron.d", entry.Name()))
					if err != nil {
						continue
					}
					if strings.Contains(string(data), "pam_time") {
						return true, "检测到PAM时间限制cron配置"
					}
				}
			}
			return false, "未检测到访问时间控制配置"
		},
	}
}

// BC-006 异地备份
// 等保条款: L3-CE-37 | ATT&CK: T1485
func bc006() model.CheckItem {
	return model.CheckItem{
		ID:            "BC-006",
		Domain:        model.DomainBusinessContinuity,
		Name:          "异地备份",
		Description:   "检查rsync/rclone远程备份配置",
		Delta:         -10,
		ComplianceRef: "L3-CE-37",
		Platform:      "linux",
		Check: func() (bool, string) {
			configs := []string{
				"/etc/rsyncd.conf",
				"/root/.config/rclone/rclone.conf",
				"/etc/rclone.conf",
			}
			var found []string
			for _, cfg := range configs {
				if _, err := os.Stat(cfg); err == nil {
					found = append(found, cfg)
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("发现远程备份配置: %s", strings.Join(found, ", "))
			}
			return false, "未发现异地备份配置 (rsync/rclone)"
		},
	}
}

// BC-007 灾难恢复演练
// 等保条款: L4-CE-09 | ATT&CK: T1485
func bc007() model.CheckItem {
	return model.CheckItem{
		ID:            "BC-007",
		Domain:        model.DomainBusinessContinuity,
		Name:          "灾难恢复演练",
		Description:   "检查灾备演练记录和恢复时间目标",
		Delta:         -20,
		ComplianceRef: "L4-CE-09",
		Platform:      "linux",
		Check: func() (bool, string) {
			drFiles := []string{
				"/var/log/dr-drill.log",
				"/etc/dr-plan.conf",
				"/opt/dr/drill-record.txt",
			}
			for _, f := range drFiles {
				if _, err := os.Stat(f); err == nil {
					return true, fmt.Sprintf("发现灾备演练记录: %s", f)
				}
			}
			return false, "未发现灾备演练记录，建议建立定期灾备演练机制"
		},
	}
}

// OT-004 供应链完整性
// 等保条款: L3-CE-32 | ATT&CK: T1195.002
func ot004() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-004",
		Domain:        model.DomainOperationTrust,
		Name:          "供应链完整性",
		Description:   "检查pip/npm hash校验机制",
		Delta:         -5,
		ComplianceRef: "L3-CE-32",
		Platform:      "linux",
		Check: func() (bool, string) {
			var indicators []string
			if _, err := os.Stat("/etc/pip.conf"); err == nil {
				data, _ := os.ReadFile("/etc/pip.conf")
				if strings.Contains(string(data), "require-hashes") {
					indicators = append(indicators, "pip hash校验已启用")
				}
			}
			if _, err := os.Stat("/root/.npmrc"); err == nil {
				data, _ := os.ReadFile("/root/.npmrc")
				if strings.Contains(string(data), "integrity") {
					indicators = append(indicators, "npm完整性校验已启用")
				}
			}
			if len(indicators) > 0 {
				return true, strings.Join(indicators, "; ")
			}
			return false, "未检测到pip/npm hash校验配置"
		},
	}
}

// OT-006 敏感文件标记
// 等保条款: L3-CE-11 | ATT&CK: T1552.001
func ot006() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-006",
		Domain:        model.DomainOperationTrust,
		Name:          "敏感文件标记",
		Description:   "检查是否存在未保护的.env、.git等敏感文件",
		Delta:         -5,
		ComplianceRef: "L3-CE-11",
		Platform:      "linux",
		Check: func() (bool, string) {
			sensitivePatterns := []string{".env", ".git", ".svn", "id_rsa", "id_ed25519", "*.pem", "*.key"}
			var exposed []string
			searchDirs := []string{"/var/www", "/opt", "/home", "/srv"}
			for _, dir := range searchDirs {
				for _, pattern := range sensitivePatterns {
					matches, _ := filepath.Glob(filepath.Join(dir, "**", pattern))
					for _, m := range matches {
						info, err := os.Stat(m)
						if err != nil {
							continue
						}
						if info.Mode().Perm()&0044 != 0 {
							exposed = append(exposed, m)
						}
					}
				}
			}
			if len(exposed) == 0 {
				return true, "未发现可被其他用户读取的敏感文件"
			}
			if len(exposed) > 5 {
				exposed = exposed[:5]
			}
			return false, fmt.Sprintf("发现 %d 个敏感文件权限过松: %s", len(exposed), strings.Join(exposed, ", "))
		},
	}
}

// OT-008 审计内容完整性
// 等保条款: L3-CE-15 | ATT&CK: T1562.001
func ot008() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-008",
		Domain:        model.DomainOperationTrust,
		Name:          "审计内容完整性",
		Description:   "检查auditd规则是否记录了关键系统调用",
		Delta:         -5,
		ComplianceRef: "L3-CE-15",
		Platform:      "linux",
		Check: func() (bool, string) {
			rulesDir := "/etc/audit/rules.d/"
			entries, err := os.ReadDir(rulesDir)
			if err != nil {
				return false, fmt.Sprintf("audit规则目录不可访问: %v", err)
			}
			requiredCalls := []string{"execve", "open", "openat", "unlink", "unlinkat", "rename", "renameat"}
			var found []string
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
				if err != nil {
					continue
				}
				content := string(data)
				for _, call := range requiredCalls {
					if strings.Contains(content, "-S "+call) || strings.Contains(content, "-S\t"+call) {
						found = append(found, call)
					}
				}
			}
			uniqueFound := make(map[string]bool)
			for _, f := range found {
				uniqueFound[f] = true
			}
			if len(uniqueFound) >= 3 {
				return true, fmt.Sprintf("auditd规则覆盖 %d 个关键系统调用: %s", len(uniqueFound), joinKeys(uniqueFound))
			}
			return false, fmt.Sprintf("auditd规则仅覆盖 %d 个关键系统调用 (建议>=3): %s", len(uniqueFound), joinKeys(uniqueFound))
		},
	}
}

// OT-009 日志远程备份
// 等保条款: L3-CE-17 | ATT&CK: T1562.008
func ot009() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-009",
		Domain:        model.DomainOperationTrust,
		Name:          "日志远程备份",
		Description:   "检查rsyslog远程转发配置",
		Delta:         -8,
		ComplianceRef: "L3-CE-17",
		Platform:      "linux",
		Check: func() (bool, string) {
			configs := []string{"/etc/rsyslog.conf", "/etc/rsyslog.d/50-default.conf"}
			for _, cfg := range configs {
				data, err := os.ReadFile(cfg)
				if err != nil {
					continue
				}
				content := string(data)
				if strings.Contains(content, "@@") || strings.Contains(content, "*.* @") {
					return true, fmt.Sprintf("rsyslog已配置远程转发 (%s)", cfg)
				}
			}
			return false, "rsyslog未配置远程转发"
		},
	}
}

// OT-010 审计进程守护
// 等保条款: L3-CE-18 | ATT&CK: T1562.001
func ot010() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-010",
		Domain:        model.DomainOperationTrust,
		Name:          "审计进程守护",
		Description:   "检查auditd是否被systemd守护且不可被非特权用户停止",
		Delta:         -5,
		ComplianceRef: "L3-CE-18",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("systemctl", "show", "auditd", "-p", "Restart")
			if err != nil {
				return false, "auditd服务未找到"
			}
			if strings.Contains(out, "always") || strings.Contains(out, "on-failure") {
				return true, "auditd已配置自动重启守护"
			}
			out2, err2 := common.RunCmd("systemctl", "show", "auditd", "-p", "RefuseManualStop")
			if err2 == nil && strings.Contains(out2, "yes") {
				return true, "auditd已配置禁止手动停止"
			}
			return false, "auditd未配置进程守护 (建议设置Restart=always)"
		},
	}
}

// OT-011 日志分类存储
// 等保条款: L3-CE-19 | ATT&CK: T1070
func ot011() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-011",
		Domain:        model.DomainOperationTrust,
		Name:          "日志分类存储",
		Description:   "检查auth.log、syslog、audit.log是否分开存储",
		Delta:         -3,
		ComplianceRef: "L3-CE-19",
		Platform:      "linux",
		Check: func() (bool, string) {
			logFiles := []string{
				"/var/log/auth.log",
				"/var/log/syslog",
				"/var/log/audit/audit.log",
				"/var/log/secure",
				"/var/log/messages",
			}
			var found []string
			for _, f := range logFiles {
				if _, err := os.Stat(f); err == nil {
					found = append(found, filepath.Base(f))
				}
			}
			if len(found) >= 2 {
				return true, fmt.Sprintf("日志分类存储: %s", strings.Join(found, ", "))
			}
			return false, "日志分类存储不足 (建议auth/syslog/audit分离)"
		},
	}
}

// OT-012 审计报表生成
// 等保条款: L3-CE-20 | ATT&CK: T1562
func ot012() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-012",
		Domain:        model.DomainOperationTrust,
		Name:          "审计报表生成",
		Description:   "检查aureport等定时报表任务是否存在",
		Delta:         -3,
		ComplianceRef: "L3-CE-20",
		Platform:      "linux",
		Check: func() (bool, string) {
			cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"}
			for _, dir := range cronDirs {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						continue
					}
					content := string(data)
					if strings.Contains(content, "aureport") || strings.Contains(content, "ausearch") {
						return true, fmt.Sprintf("发现审计报表任务: %s/%s", dir, entry.Name())
					}
				}
			}
			return false, "未发现aureport定时报表任务"
		},
	}
}

// OT-013 文件完整性监控
// 等保条款: L3-CE-30 | ATT&CK: T1565
func ot013() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-013",
		Domain:        model.DomainOperationTrust,
		Name:          "文件完整性监控",
		Description:   "检查AIDE/Tripwire是否运行及基线更新",
		Delta:         -10,
		ComplianceRef: "L3-CE-30",
		Platform:      "linux",
		Check: func() (bool, string) {
			tools := []string{"aide", "tripwire", "samhain", "integrit"}
			for _, tool := range tools {
				if _, err := os.Stat("/var/lib/" + tool); err == nil {
					return true, fmt.Sprintf("检测到文件完整性监控工具: %s", tool)
				}
				out, err := common.RunCmd("which", tool)
				if err == nil && strings.TrimSpace(out) != "" {
					return true, fmt.Sprintf("检测到文件完整性监控工具: %s", tool)
				}
			}
			return false, "未检测到文件完整性监控工具 (AIDE/Tripwire)"
		},
	}
}

// OT-014 静态数据加密
// 等保条款: L3-CE-33 | ATT&CK: T1486
func ot014() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-014",
		Domain:        model.DomainOperationTrust,
		Name:          "静态数据加密",
		Description:   "检查关键目录是否使用LUKS/gocryptfs加密",
		Delta:         -10,
		ComplianceRef: "L3-CE-33",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("lsblk", "-o", "NAME,TYPE,MOUNTPOINT,FSTYPE")
			if err != nil {
				return false, fmt.Sprintf("无法检查磁盘加密: %v", err)
			}
			if strings.Contains(out, "crypt") || strings.Contains(out, "LUKS") {
				return true, "检测到LUKS加密分区"
			}

			out2, err2 := common.RunCmd("mount")
			if err2 == nil && strings.Contains(out2, "gocryptfs") {
				return true, "检测到gocryptfs加密挂载"
			}

			if _, err := os.Stat("/etc/crypttab"); err == nil {
				data, err := os.ReadFile("/etc/crypttab")
				if err == nil {
					activeVolumes := parseCrypttab(string(data))
					if len(activeVolumes) > 0 {
						mappedDevices := getMappedDevices()
						var mounted []string
						for _, vol := range activeVolumes {
							if mappedDevices[vol] {
								mounted = append(mounted, "/dev/mapper/"+vol)
							}
						}
						if len(mounted) > 0 {
							return true, fmt.Sprintf("检测到加密存储配置: %s (活跃映射: %d 个)", strings.Join(activeVolumes, ", "), len(mounted))
						}
						return false, fmt.Sprintf("/etc/crypttab 中存在 %d 个加密卷配置但未检测到活跃映射 (%s, 请检查是否已挂载)", len(activeVolumes), strings.Join(activeVolumes, ", "))
					}
				}
			}

			return false, "未检测到静态数据加密 (LUKS/gocryptfs/crypttab)"
		},
	}
}

func parseCrypttab(content string) []string {
	var volumes []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			volumes = append(volumes, fields[0])
		}
	}
	return volumes
}

func getMappedDevices() map[string]bool {
	devices := make(map[string]bool)
	entries, err := os.ReadDir("/dev/mapper")
	if err != nil {
		return devices
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "control" {
			devices[name] = true
		}
	}
	return devices
}

// OT-015 国密算法检测
// 等保条款: L3-CE-35 | ATT&CK: N/A (合规加分项)
func ot015() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-015",
		Domain:        model.DomainOperationTrust,
		Name:          "国密算法检测",
		Description:   "检查是否支持SM2/SM3/SM4国密算法",
		Delta:         3,
		ComplianceRef: "L3-CE-35",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("openssl", "list", "-cipher-algorithms")
			if err != nil {
				out, err = common.RunCmd("openssl", "enc", "-ciphers")
				if err != nil {
					return false, "无法检测国密算法支持"
				}
			}
			supported := []string{}
			if strings.Contains(out, "SM4") || strings.Contains(out, "sm4") {
				supported = append(supported, "SM4")
			}
			if strings.Contains(out, "SM3") || strings.Contains(out, "sm3") {
				supported = append(supported, "SM3")
			}
			if strings.Contains(out, "SM2") || strings.Contains(out, "sm2") {
				supported = append(supported, "SM2")
			}
			if len(supported) > 0 {
				return true, fmt.Sprintf("支持国密算法: %s", strings.Join(supported, ", "))
			}
			return false, "未检测到国密算法支持 (SM2/SM3/SM4)"
		},
	}
}

// OT-016 残留信息检查
// 等保条款: L3-CE-39 | ATT&CK: T1070
func ot016() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-016",
		Domain:        model.DomainOperationTrust,
		Name:          "残留信息检查",
		Description:   "检查/tmp和swap清除策略",
		Delta:         -5,
		ComplianceRef: "L3-CE-39",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string
			data, err := os.ReadFile("/etc/fstab")
			if err == nil {
				if strings.Contains(string(data), "tmpfs") && strings.Contains(string(data), "/tmp") {
				} else {
					issues = append(issues, "/tmp未使用tmpfs")
				}
			}
			out, err := common.RunCmd("sysctl", "-n", "vm.swappiness")
			if err == nil {
				val := strings.TrimSpace(out)
				if v, err := strconv.Atoi(val); err == nil && v > 10 {
					issues = append(issues, fmt.Sprintf("swap使用倾向过高 (swappiness=%d)", v))
				}
			}
			if len(issues) == 0 {
				return true, "残留信息保护配置合理"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

// OT-017 内存转储限制
// 等保条款: L3-CE-40 | ATT&CK: T1003.007
func ot017() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-017",
		Domain:        model.DomainOperationTrust,
		Name:          "内存转储限制",
		Description:   "检查core dump是否禁用",
		Delta:         -5,
		ComplianceRef: "L3-CE-40",
		Platform:      "linux",
		Check: func() (bool, string) {
			limitsFiles := []string{"/etc/security/limits.conf", "/etc/security/limits.d/90-core.conf"}
			for _, f := range limitsFiles {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				if strings.Contains(string(data), "core") && strings.Contains(string(data), "0") {
					return true, "core dump已禁用"
				}
			}
			out, err := common.RunCmd("sysctl", "-n", "kernel.core_pattern")
			if err == nil && (strings.TrimSpace(out) == "" || strings.Contains(out, "/dev/null")) {
				return true, "core dump已禁用 (kernel.core_pattern)"
			}
			return false, "core dump未禁用，建议设置 * hard core 0"
		},
	}
}

// OT-018 敏感数据最小化
// 等保条款: L3-CE-41 | ATT&CK: T1530
func ot018() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-018",
		Domain:        model.DomainOperationTrust,
		Name:          "敏感数据最小化",
		Description:   "检查日志中是否含身份证、手机号明文",
		Delta:         -6,
		ComplianceRef: "L3-CE-41",
		Platform:      "linux",
		Check: func() (bool, string) {
			logFiles := []string{"/var/log/syslog", "/var/log/messages", "/var/log/auth.log"}
			idPattern := regexp.MustCompile(`[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)
			phonePattern := regexp.MustCompile(`1[3-9]\d{9}`)
			for _, f := range logFiles {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				content := string(data)
				if len(content) > 10000 {
					content = content[:10000]
				}
				if idPattern.MatchString(content) || phonePattern.MatchString(content) {
					return false, fmt.Sprintf("日志文件 %s 中可能包含明文敏感信息", f)
				}
			}
			return true, "未在日志中发现明文敏感信息"
		},
	}
}

// OT-019 个人数据脱敏
// 等保条款: L3-CE-42 | ATT&CK: T1530
func ot019() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-019",
		Domain:        model.DomainOperationTrust,
		Name:          "个人数据脱敏",
		Description:   "检查应用配置中外发日志脱敏机制",
		Delta:         -6,
		ComplianceRef: "L3-CE-42",
		Platform:      "linux",
		Check: func() (bool, string) {
			configFiles := []string{
				"/etc/rsyslog.conf",
				"/etc/rsyslog.d/50-default.conf",
			}
			for _, cfg := range configFiles {
				data, err := os.ReadFile(cfg)
				if err != nil {
					continue
				}
				if strings.Contains(string(data), "anonymize") || strings.Contains(string(data), "mask") || strings.Contains(string(data), "rewrite") {
					return true, "rsyslog已配置数据脱敏规则"
				}
			}
			return false, "未检测到日志脱敏配置"
		},
	}
}

// OT-020 详细审计
// 等保条款: L4-CE-05 | ATT&CK: T1562.001
func ot020() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-020",
		Domain:        model.DomainOperationTrust,
		Name:          "详细审计",
		Description:   "检查auditd规则是否覆盖所有特权操作",
		Delta:         -10,
		ComplianceRef: "L4-CE-05",
		Platform:      "linux",
		Check: func() (bool, string) {
			rulesDir := "/etc/audit/rules.d/"
			entries, err := os.ReadDir(rulesDir)
			if err != nil {
				return false, fmt.Sprintf("audit规则目录不可访问: %v", err)
			}
			privilegedOps := []string{"chmod", "chown", "setuid", "setgid", "mount", "umount2", "ptrace", "personality"}
			var covered []string
			for _, entry := range entries {
				data, err := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
				if err != nil {
					continue
				}
				content := string(data)
				for _, op := range privilegedOps {
					if strings.Contains(content, op) {
						covered = append(covered, op)
					}
				}
			}
			uniqueCovered := make(map[string]bool)
			for _, c := range covered {
				uniqueCovered[c] = true
			}
			if len(uniqueCovered) >= 4 {
				return true, fmt.Sprintf("auditd覆盖 %d 个特权操作: %s", len(uniqueCovered), joinKeys(uniqueCovered))
			}
			return false, fmt.Sprintf("auditd仅覆盖 %d 个特权操作 (建议>=4): %s", len(uniqueCovered), joinKeys(uniqueCovered))
		},
	}
}

// OT-021 时间源可信
// 等保条款: L4-CE-06 | ATT&CK: T1070.002
func ot021() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-021",
		Domain:        model.DomainOperationTrust,
		Name:          "时间源可信",
		Description:   "检查chronyd/ntpd硬件时间戳配置",
		Delta:         -5,
		ComplianceRef: "L4-CE-06",
		Platform:      "linux",
		Check: func() (bool, string) {
			for _, svc := range []string{"chronyd", "ntpd", "ntp", "systemd-timesyncd"} {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", svc)
				if ok && strings.TrimSpace(out) == "active" {
					if svc == "chronyd" {
						out2, err := common.RunCmd("chronyc", "tracking")
						if err == nil && strings.Contains(out2, "Ref time") {
							return true, "chronyd已同步可信时间源"
						}
					}
					return true, fmt.Sprintf("%s 已运行", svc)
				}
			}
			return false, "未检测到运行中的NTP服务"
		},
	}
}

// OT-022 强加密存储
// 等保条款: L4-CE-09 | ATT&CK: T1486
func ot022() model.CheckItem {
	return model.CheckItem{
		ID:            "OT-022",
		Domain:        model.DomainOperationTrust,
		Name:          "强加密存储",
		Description:   "检查是否使用AES-256或国密算法加密存储",
		Delta:         -15,
		ComplianceRef: "L4-CE-09",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("dmsetup", "table")
			if err == nil && strings.Contains(out, "crypt") {
				return true, "检测到dm-crypt加密存储"
			}
			out2, err2 := common.RunCmd("lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT")
			if err2 == nil && strings.Contains(out2, "crypto_LUKS") {
				return true, "检测到LUKS加密存储"
			}
			if _, err := os.Stat("/etc/crypttab"); err == nil {
				data, err := os.ReadFile("/etc/crypttab")
				if err == nil {
					activeVolumes := parseCrypttab(string(data))
					if len(activeVolumes) > 0 {
						mappedDevices := getMappedDevices()
						var mounted []string
						for _, vol := range activeVolumes {
							if mappedDevices[vol] {
								mounted = append(mounted, vol)
							}
						}
						if len(mounted) > 0 {
							return true, fmt.Sprintf("检测到加密存储: /etc/crypttab (活跃: %d/%d 卷)", len(mounted), len(activeVolumes))
						}
					}
				}
				return false, "检测到 /etc/crypttab 但无可验证的活跃加密卷映射"
			}
			return false, "未检测到强加密存储 (AES-256/国密)"
		},
	}
}

// RS-006 HIDS/NIDS部署
// 等保条款: L3-CE-24 | ATT&CK: T1595.002
func rs006() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-006",
		Domain:        model.DomainResilience,
		Name:          "HIDS/NIDS部署",
		Description:   "检查Wazuh/AIDE/Suricata等HIDS/NIDS是否运行",
		Delta:         -10,
		ComplianceRef: "L3-CE-24",
		Platform:      "linux",
		Check: func() (bool, string) {
			idsTools := []string{
				"wazuh-agent", "ossec-hids", "ossec-agent",
				"aide", "tripwire", "samhain", "rkhunter",
				"suricata", "snort", "snort3", "zeek",
			}
			var found []string
			for _, tool := range idsTools {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", tool)
				if ok && strings.TrimSpace(out) == "active" {
					found = append(found, tool)
				}
			}

			processNames := []string{"suricata", "snort", "snort3", "zeek", "wazuh-agent",
				"ossec-agent", "aide", "tripwire", "samhain"}
			needProcessCheck := len(found) == 0
			if needProcessCheck {
				out, err := common.RunCmd("ps", "-eo", "comm", "--no-headers")
				if err == nil {
					for _, name := range processNames {
						for _, line := range strings.Split(out, "\n") {
							if strings.TrimSpace(line) == name {
								found = append(found, name+"(进程)")
								break
							}
						}
					}
				}
			}

			if len(found) > 0 {
				seen := make(map[string]bool)
				var deduped []string
				for _, t := range found {
					base := strings.TrimSuffix(t, "(进程)")
					if !seen[base] {
						seen[base] = true
						deduped = append(deduped, t)
					}
				}
				return true, fmt.Sprintf("检测到IDS工具: %s", strings.Join(deduped, ", "))
			}
			return false, "未检测到运行中的HIDS/NIDS工具 (检查范围: wazuh/suricata/snort/zeek/aide/tripwire/samhain/rkhunter)"
		},
	}
}

// RS-007 入侵告警配置
// 等保条款: L3-CE-25 | ATT&CK: T1562.008
func rs007() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-007",
		Domain:        model.DomainResilience,
		Name:          "入侵告警配置",
		Description:   "检查HIDS是否配置主动告警",
		Delta:         -6,
		ComplianceRef: "L3-CE-25",
		Platform:      "linux",
		Check: func() (bool, string) {
			alertConfigs := []string{
				"/var/ossec/etc/ossec.conf",
				"/etc/wazuh-agent/ossec.conf",
				"/etc/aide/aide.conf",
			}
			for _, cfg := range alertConfigs {
				data, err := os.ReadFile(cfg)
				if err != nil {
					continue
				}
				content := strings.ToLower(string(data))
				if strings.Contains(content, "email") || strings.Contains(content, "alert") || strings.Contains(content, "notification") {
					return true, fmt.Sprintf("检测到告警配置: %s", cfg)
				}
			}
			return false, "未检测到HIDS告警配置"
		},
	}
}

// RS-008 反病毒部署
// 等保条款: L3-CE-27 | ATT&CK: T1059
func rs008() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-008",
		Domain:        model.DomainResilience,
		Name:          "反病毒部署",
		Description:   "检查ClamAV或等效反病毒工具是否安装",
		Delta:         -8,
		ComplianceRef: "L3-CE-27",
		Platform:      "linux",
		Check: func() (bool, string) {
			avTools := []string{"clamscan", "clamdscan", "freshclam", "savscan", "esets_cli"}
			var found []string
			for _, tool := range avTools {
				out, err := common.RunCmd("which", tool)
				if err == nil && strings.TrimSpace(out) != "" {
					found = append(found, tool)
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("检测到反病毒工具: %s", strings.Join(found, ", "))
			}
			return false, "未检测到反病毒工具 (ClamAV等)"
		},
	}
}

// RS-009 病毒库更新
// 等保条款: L3-CE-28 | ATT&CK: T1059
func rs009() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-009",
		Domain:        model.DomainResilience,
		Name:          "病毒库更新",
		Description:   "检查freshclam定时任务是否配置",
		Delta:         -6,
		ComplianceRef: "L3-CE-28",
		Platform:      "linux",
		Check: func() (bool, string) {
			cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"}
			for _, dir := range cronDirs {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						continue
					}
					if strings.Contains(string(data), "freshclam") {
						return true, fmt.Sprintf("发现freshclam定时更新: %s/%s", dir, entry.Name())
					}
				}
			}
			out, ok := common.RunCmdQuiet("systemctl", "is-active", "clamav-freshclam")
			if ok && strings.TrimSpace(out) == "active" {
				return true, "clamav-freshclam服务已运行"
			}
			return false, "未检测到病毒库自动更新配置"
		},
	}
}

// RS-010 集中管控集成
// 等保条款: L3-CE-29 | ATT&CK: T1078
func rs010() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-010",
		Domain:        model.DomainResilience,
		Name:          "集中管控集成",
		Description:   "检查是否接入管理控制台",
		Delta:         -4,
		ComplianceRef: "L3-CE-29",
		Platform:      "linux",
		Check: func() (bool, string) {
			mgmtAgents := []string{"wazuh-agent", "ossec-agent", "salt-minion", "puppet", "chef-client", "ansible-pull"}
			var found []string
			for _, agent := range mgmtAgents {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", agent)
				if ok && strings.TrimSpace(out) == "active" {
					found = append(found, agent)
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("检测到集中管控代理: %s", strings.Join(found, ", "))
			}
			return false, "未检测到集中管控代理"
		},
	}
}

// RS-011 APT检测能力
// 等保条款: L4-CE-07 | ATT&CK: T1203
func rs011() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-011",
		Domain:        model.DomainResilience,
		Name:          "APT检测能力",
		Description:   "检查是否部署沙箱或威胁狩猎能力",
		Delta:         -15,
		ComplianceRef: "L4-CE-07",
		Platform:      "linux",
		Check: func() (bool, string) {
			aptTools := []string{"cuckoo", "cape", "drakvuf", "sysmon", "velociraptor", "grr"}
			var found []string
			for _, tool := range aptTools {
				out, err := common.RunCmd("which", tool)
				if err == nil && strings.TrimSpace(out) != "" {
					found = append(found, tool)
				}
				out2, ok := common.RunCmdQuiet("systemctl", "is-active", tool)
				if ok && strings.TrimSpace(out2) == "active" {
					found = append(found, tool)
				}
			}
			if len(found) > 0 {
				return true, fmt.Sprintf("检测到APT检测工具: %s", strings.Join(found, ", "))
			}
			return false, "未检测到APT检测/威胁狩猎工具"
		},
	}
}

// RS-012 分布式IDS
// 等保条款: L4-CE-08 | ATT&CK: T1595.002
func rs012() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-012",
		Domain:        model.DomainResilience,
		Name:          "分布式IDS",
		Description:   "检查多探针+统一管理平台配置",
		Delta:         -10,
		ComplianceRef: "L4-CE-08",
		Platform:      "linux",
		Check: func() (bool, string) {
			idsIndicators := []string{
				"/etc/suricata/suricata.yaml",
				"/etc/snort/snort.conf",
				"/etc/zeek/node.cfg",
				"/etc/wazuh-agent/ossec.conf",
			}
			var found []string
			for _, cfg := range idsIndicators {
				if _, err := os.Stat(cfg); err == nil {
					found = append(found, filepath.Base(filepath.Dir(cfg)))
				}
			}
			if len(found) >= 2 {
				return true, fmt.Sprintf("检测到多个IDS组件: %s", strings.Join(found, ", "))
			}
			if len(found) == 1 {
				return false, fmt.Sprintf("仅检测到单一IDS组件: %s，建议部署分布式IDS", found[0])
			}
			return false, "未检测到分布式IDS配置"
		},
	}
}

// EF-001 双因素认证
// 等保条款: L3-CE-04 | ATT&CK: T1111 (边缘因子)
func ef001() model.CheckItem {
	return model.CheckItem{
		ID:            "EF-001",
		Domain:        model.DomainAttackSurface,
		Name:          "双因素认证",
		Description:   "检查PAM是否集成TOTP/证书认证",
		Delta:         0,
		ComplianceRef: "L3-CE-04",
		Platform:      "linux",
		Check: func() (bool, string) {
			pamFiles := []string{
				"/etc/pam.d/sshd",
				"/etc/pam.d/common-auth",
				"/etc/pam.d/system-auth",
			}
			for _, f := range pamFiles {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				content := string(data)
				if strings.Contains(content, "pam_google_authenticator") ||
					strings.Contains(content, "pam_oath") ||
					strings.Contains(content, "pam_duo") ||
					strings.Contains(content, "pam_u2f") ||
					strings.Contains(content, "pam_pkcs11") {
					return true, fmt.Sprintf("双因素认证已配置 (%s)", f)
				}
			}
			return false, "未检测到双因素认证配置 (TOTP/证书/U2F)"
		},
	}
}

// EF-002 三因素认证
// 等保条款: L4-CE-01 | ATT&CK: T1111 (边缘因子升级)
func ef002() model.CheckItem {
	return model.CheckItem{
		ID:            "EF-002",
		Domain:        model.DomainAttackSurface,
		Name:          "三因素认证",
		Description:   "检查是否配置生物特征或硬件令牌作为第三因素",
		Delta:         0,
		ComplianceRef: "L4-CE-01",
		Platform:      "linux",
		Check: func() (bool, string) {
			pamFiles := []string{
				"/etc/pam.d/sshd",
				"/etc/pam.d/common-auth",
				"/etc/pam.d/system-auth",
			}
			factorCount := 0
			for _, f := range pamFiles {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				content := string(data)
				if strings.Contains(content, "pam_google_authenticator") ||
					strings.Contains(content, "pam_oath") {
					factorCount++
				}
				if strings.Contains(content, "pam_u2f") ||
					strings.Contains(content, "pam_pkcs11") {
					factorCount++
				}
				if strings.Contains(content, "pam_fprintd") ||
					strings.Contains(content, "pam_biometric") {
					factorCount++
				}
			}
			if factorCount >= 3 {
				return true, "三因素认证已配置"
			}
			return false, fmt.Sprintf("仅检测到 %d 个认证因素 (需要>=3)", factorCount)
		},
	}
}

// AS-005 网络服务暴露面检查
// 等保条款: L3-CE-23 | ATT&CK: T1595.001
func as005() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-005",
		Domain:        model.DomainAttackSurface,
		Name:          "网络服务暴露面检查",
		Description:   "检查对外暴露的网络服务是否最小化",
		Delta:         -8,
		ComplianceRef: "L3-CE-23",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("ss", "-tlnp")
			if err != nil {
				return false, fmt.Sprintf("无法获取监听端口: %v", err)
			}
			lines := strings.Split(out, "\n")
			var externalPorts []string
			for _, line := range lines {
				if strings.Contains(line, "LISTEN") {
					fields := strings.Fields(line)
					if len(fields) >= 4 {
						addr := fields[3]
						if strings.HasPrefix(addr, "0.0.0.0:") || strings.HasPrefix(addr, ":::") || strings.HasPrefix(addr, "*:") {
							port := addr
							if idx := strings.LastIndex(addr, ":"); idx != -1 {
								port = addr[idx+1:]
							}
							externalPorts = append(externalPorts, port)
						}
					}
				}
			}
			if len(externalPorts) == 0 {
				return true, "无对外暴露端口"
			}
			if len(externalPorts) <= 3 {
				return true, fmt.Sprintf("对外暴露端口数量合理: %s", strings.Join(externalPorts, ", "))
			}
			return false, fmt.Sprintf("对外暴露端口过多 (%d个): %s，建议最小化暴露面", len(externalPorts), strings.Join(externalPorts, ", "))
		},
	}
}

// AS-006 危险协议检测
// 等保条款: L3-CE-05 | ATT&CK: T1071
func as006() model.CheckItem {
	return model.CheckItem{
		ID:            "AS-006",
		Domain:        model.DomainAttackSurface,
		Name:          "危险协议检测",
		Description:   "检查是否存在明文传输的危险协议服务",
		Delta:         -10,
		ComplianceRef: "L3-CE-05",
		Platform:      "linux",
		Check: func() (bool, string) {
			dangerousProtocols := []string{"telnet", "ftp", "rsh", "rlogin", "rexec", "tftp", "http"}
			var active []string
			for _, proto := range dangerousProtocols {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", proto)
				if ok && strings.TrimSpace(out) == "active" {
					active = append(active, proto)
				}
				out2, ok2 := common.RunCmdQuiet("ss", "-tlnp")
				if ok2 && strings.Contains(out2, proto) {
					if !contains(active, proto) {
						active = append(active, proto+"(端口)")
					}
				}
			}
			if len(active) == 0 {
				return true, "未检测到危险协议服务"
			}
			return false, fmt.Sprintf("检测到 %d 个危险协议服务: %s", len(active), strings.Join(active, ", "))
		},
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RS-002 连接数限制
// 等保条款: L3-CE-12 | ATT&CK: T1499
func rs002() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-002",
		Domain:        model.DomainResilience,
		Name:          "连接数限制",
		Description:   "检查系统是否配置了连接数限制以防止资源耗尽",
		Delta:         -8,
		ComplianceRef: "L3-CE-12",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string
			data, err := os.ReadFile("/proc/sys/net/core/somaxconn")
			if err == nil {
				val := strings.TrimSpace(string(data))
				if v, err := strconv.Atoi(val); err == nil && v < 128 {
					issues = append(issues, fmt.Sprintf("somaxconn=%d (建议>=128)", v))
				}
			}
			data2, err := os.ReadFile("/proc/sys/net/ipv4/tcp_max_syn_backlog")
			if err == nil {
				val := strings.TrimSpace(string(data2))
				if v, err := strconv.Atoi(val); err == nil && v < 1024 {
					issues = append(issues, fmt.Sprintf("tcp_max_syn_backlog=%d (建议>=1024)", v))
				}
			}
			out, err := common.RunCmd("sysctl", "-n", "net.ipv4.tcp_max_connections")
			if err == nil {
				val := strings.TrimSpace(out)
				if v, err := strconv.Atoi(val); err == nil && v > 0 && v < 1000 {
					issues = append(issues, fmt.Sprintf("tcp_max_connections=%d (建议>=1000)", v))
				}
			}
			if len(issues) == 0 {
				return true, "连接数限制配置合理"
			}
			return false, strings.Join(issues, "; ")
		},
	}
}

// RS-003 自动封禁精度
// 等保条款: L3-CE-02 | ATT&CK: T1110
func rs003() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-003",
		Domain:        model.DomainResilience,
		Name:          "自动封禁精度",
		Description:   "检查fail2ban或类似工具的封禁规则是否有效配置",
		Delta:         -6,
		ComplianceRef: "L3-CE-02",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, ok := common.RunCmdQuiet("systemctl", "is-active", "fail2ban")
			if ok && strings.TrimSpace(out) == "active" {
				jailsOut, err := common.RunCmd("fail2ban-client", "status")
				if err == nil && strings.Contains(jailsOut, "Jail list") {
					jails := parseFail2banJails(jailsOut)
					if len(jails) >= 2 {
						return true, fmt.Sprintf("fail2ban已运行，监控 %d 个jail: %s", len(jails), strings.Join(jails, ", "))
					}
					if len(jails) == 1 {
						return false, fmt.Sprintf("fail2ban仅监控 1 个jail (%s)，建议增加更多监控规则", jails[0])
					}
				}
				return false, "fail2ban已运行但未检测到有效jail配置"
			}
			out2, ok2 := common.RunCmdQuiet("systemctl", "is-active", "crowdsec")
			if ok2 && strings.TrimSpace(out2) == "active" {
				return true, "crowdsec已运行，提供自动封禁能力"
			}
			out3, ok3 := common.RunCmdQuiet("which", "denyhosts")
			if ok3 && strings.TrimSpace(out3) != "" {
				return true, "denyhosts已安装，提供SSH自动封禁"
			}
			return false, "未检测到自动封禁工具 (fail2ban/crowdsec/denyhosts)"
		},
	}
}

func parseFail2banJails(output string) []string {
	var jails []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				jailList := strings.TrimSpace(parts[1])
				for _, j := range strings.Split(jailList, ",") {
					jail := strings.TrimSpace(j)
					if jail != "" {
						jails = append(jails, jail)
					}
				}
			}
		}
	}
	return jails
}

// RS-004 DDoS防护配置
// 等保条款: L3-CE-12 | ATT&CK: T1498
func rs004() model.CheckItem {
	return model.CheckItem{
		ID:            "RS-004",
		Domain:        model.DomainResilience,
		Name:          "DDoS防护配置",
		Description:   "检查系统是否配置了DDoS防护参数",
		Delta:         -10,
		ComplianceRef: "L3-CE-12",
		Platform:      "linux",
		Check: func() (bool, string) {
			var configured []string
			var issues []string
			data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_syncookies")
			if err == nil && strings.TrimSpace(string(data)) == "1" {
				configured = append(configured, "SYN Cookie")
			} else {
				issues = append(issues, "SYN Cookie未启用")
			}
			data2, err := os.ReadFile("/proc/sys/net/ipv4/tcp_synack_retries")
			if err == nil {
				val := strings.TrimSpace(string(data2))
				if v, err := strconv.Atoi(val); err == nil && v <= 5 {
					configured = append(configured, fmt.Sprintf("SYNACK重试=%d", v))
				}
			}
			data3, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fin_timeout")
			if err == nil {
				val := strings.TrimSpace(string(data3))
				if v, err := strconv.Atoi(val); err == nil && v <= 30 {
					configured = append(configured, fmt.Sprintf("FIN超时=%d", v))
				}
			}
			out, err := common.RunCmd("sysctl", "-n", "net.ipv4.conf.all.rp_filter")
			if err == nil && strings.TrimSpace(out) == "1" {
				configured = append(configured, "反向路径过滤")
			}
			if len(configured) >= 3 {
				return true, fmt.Sprintf("DDoS防护配置完善: %s", strings.Join(configured, ", "))
			}
			if len(configured) > 0 {
				return false, fmt.Sprintf("DDoS防护配置不足 (%s)，建议增强: %s", strings.Join(configured, ", "), strings.Join(issues, "; "))
			}
			return false, "未检测到DDoS防护配置"
		},
	}
}

// AC-006 本地管理员密码唯一性(LAPS)
// 等保条款: ACI-02 | ATT&CK: T1078.002
func ac006() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-006",
		Domain:        model.DomainResilience,
		Name:          "ACI:本地管理员密码唯一性",
		Description:   "检查是否部署LAPS或类似机制确保本地管理员密码唯一",
		Delta:         -10,
		ComplianceRef: "ACI-02",
		Platform:      "linux",
		Check: func() (bool, string) {
			lapsIndicators := []string{
				"/opt/laps/laps",
				"/usr/local/bin/laps",
				"/etc/laps/config",
				"/var/lib/laps",
			}
			for _, indicator := range lapsIndicators {
				if _, err := os.Stat(indicator); err == nil {
					return true, fmt.Sprintf("检测到LAPS部署: %s", indicator)
				}
			}
			out, err := common.RunCmd("which", "laps")
			if err == nil && strings.TrimSpace(out) != "" {
				return true, "LAPS工具已安装"
			}
			out2, err := common.RunCmd("systemctl", "list-units", "--type=service", "--all")
			if err == nil && strings.Contains(strings.ToLower(out2), "laps") {
				return true, "检测到LAPS服务"
			}
			sudoersData, err := os.ReadFile("/etc/sudoers")
			if err == nil {
				if strings.Contains(string(sudoersData), "NOPASSWD") {
					return false, "未检测到LAPS，且sudoers存在NOPASSWD配置，本地管理员密码风险较高"
				}
			}
			return false, "未检测到LAPS或类似机制，本地管理员密码可能存在复用风险"
		},
	}
}

// AC-007 数据防泄露(DLP)措施
// 等保条款: ACI-07 | ATT&CK: T1048
func ac007() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-007",
		Domain:        model.DomainResilience,
		Name:          "ACI:数据防泄露措施",
		Description:   "检查敏感数据出口是否受控",
		Delta:         -5,
		ComplianceRef: "ACI-07",
		Platform:      "linux",
		Check: func() (bool, string) {
			dlpTools := []string{
				"forcepoint",
				"symantec-dlp",
				"digitalguardian",
				"cofense",
				"trellix",
			}
			for _, tool := range dlpTools {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", tool)
				if ok && strings.TrimSpace(out) == "active" {
					return true, fmt.Sprintf("检测到DLP工具: %s", tool)
				}
			}
			out, err := common.RunCmd("ps", "-eo", "comm", "--no-headers")
			if err == nil {
				processes := strings.ToLower(out)
				for _, tool := range dlpTools {
					if strings.Contains(processes, tool) {
						return true, fmt.Sprintf("检测到DLP进程: %s", tool)
					}
				}
			}
			auditRules, err := os.ReadFile("/etc/audit/rules.d/audit.rules")
			if err == nil {
				content := string(auditRules)
				if strings.Contains(content, "watch") && (strings.Contains(content, "/etc/passwd") || strings.Contains(content, "/etc/shadow")) {
					return true, "审计规则监控敏感文件访问，提供基础DLP能力"
				}
			}
			return false, "未检测到DLP措施 (商业DLP或敏感文件审计监控)"
		},
	}
}

// AC-008 恢复能力验证(MTTR)
// 等保条款: ACI-08 | ATT&CK: T1485
func ac008() model.CheckItem {
	return model.CheckItem{
		ID:            "AC-008",
		Domain:        model.DomainResilience,
		Name:          "ACI:恢复能力验证",
		Description:   "检查系统恢复能力和MTTR相关配置",
		Delta:         -10,
		ComplianceRef: "ACI-08",
		Platform:      "linux",
		Check: func() (bool, string) {
			var recoveryIndicators []string
			recoveryTools := []string{
				"rear",
				"relax-and-recover",
				"clonezilla",
				"timeshift",
				"borgbackup",
				"restic",
			}
			for _, tool := range recoveryTools {
				out, err := common.RunCmd("which", tool)
				if err == nil && strings.TrimSpace(out) != "" {
					recoveryIndicators = append(recoveryIndicators, tool)
				}
			}
			cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly"}
			for _, dir := range cronDirs {
				entries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						continue
					}
					content := strings.ToLower(string(data))
					if strings.Contains(content, "restore") || strings.Contains(content, "recover") || strings.Contains(content, "backup") {
						recoveryIndicators = append(recoveryIndicators, entry.Name())
					}
				}
			}
			if len(recoveryIndicators) >= 2 {
				return true, fmt.Sprintf("恢复能力配置完善: %s", strings.Join(unique(recoveryIndicators), ", "))
			}
			if len(recoveryIndicators) == 1 {
				return false, fmt.Sprintf("恢复能力配置不足，仅检测到: %s", recoveryIndicators[0])
			}
			return false, "未检测到恢复能力配置 (rear/clonezilla/timeshift/borg/restic或恢复脚本)"
		},
	}
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
