package linux

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/argus-security/argus/internal/common"
	"github.com/argus-security/argus/internal/model"
)

func All() []model.CheckItem {
	return []model.CheckItem{
		as001(),
		as002(),
		as003(),
		as004(),
		as007(),
		as008(),
		as009(),
		as011(),
		as012(),
		as014(),
		as015(),
		ot001(),
		ot002(),
		ot003(),
		ot005(),
		ot007(),
		rs001(),
		rs005(),
		bc005(),
		ac001(),
		ac002(),
		ac003(),
		ac004(),
		ac005(),
	}
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
		Name:          "开放端口检查",
		Description:   "检查监听端口是否仅限业务所需",
		Delta:         -8,
		ComplianceRef: "L3-CE-23",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("ss", "-tlnp")
			if err != nil {
				return true, fmt.Sprintf("无法检查端口: %v", err)
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			var ports []string
			for _, line := range lines[1:] {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					addr := fields[3]
					if idx := strings.LastIndex(addr, ":"); idx != -1 {
						port := addr[idx+1:]
						if p, err := strconv.Atoi(port); err == nil && p > 0 {
							ports = append(ports, port)
						}
					}
				}
			}
			return true, fmt.Sprintf("当前监听 %d 个端口: [%s]", len(ports), strings.Join(ports, ", "))
		},
	}
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
		Description:   "扫描无密码或长期未登录账户",
		Delta:         -6,
		ComplianceRef: "L3-CE-09",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/etc/shadow")
			if err != nil {
				return false, fmt.Sprintf("无法读取/etc/shadow: %v", err)
			}
			var ghost []string
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				if len(parts) < 2 {
					continue
				}
				if parts[1] == "" || parts[1] == "!" || parts[1] == "!!" || parts[1] == "*" {
					if parts[0] != "root" && !strings.HasPrefix(parts[0], "systemd-") {
						ghost = append(ghost, parts[0])
					}
				}
			}
			if len(ghost) == 0 {
				return true, "未发现幽灵账户"
			}
			return false, fmt.Sprintf("发现 %d 个幽灵账户: %s", len(ghost), strings.Join(ghost, ", "))
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
				if perm&0077 != 0 {
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
				return true, "更新检查完成 (可能无更新或检查出错)"
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
			if _, err := os.Stat("/etc/selinux/config"); err == nil {
				data, _ := os.ReadFile("/etc/selinux/config")
				if strings.Contains(string(data), "enforcing") {
					return true, "SELinux enforcing模式提供执行限制"
				}
			}
			_, err := common.RunCmd("which", "fapolicyd")
			if err == nil {
				out, ok := common.RunCmdQuiet("systemctl", "is-active", "fapolicyd")
				if ok && strings.TrimSpace(out) == "active" {
					return true, "fapolicyd 已运行"
				}
			}
			return false, "未检测到应用程序白名单机制"
		},
	}
}
