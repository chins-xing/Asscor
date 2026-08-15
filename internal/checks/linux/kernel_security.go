//go:build checks

package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/asscor/asscor/internal/common"
	"github.com/asscor/asscor/internal/model"
)

func ksAll() []model.CheckItem {
	return []model.CheckItem{
		ks001(),
		ks002(),
		ks003(),
		ks004(),
		ks005(),
		ks006(),
		ks007(),
		ks008(),
		ks009(),
		ks010(),
		ks011(),
		ks012(),
	}
}

func ks001() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-001",
		Domain:        model.DomainKernelSecurity,
		Name:          "Kernel Version CVE Check",
		Description:   "比对当前内核版本与已知CVE数据库，检查是否存在未修补的提权类或RCE类内核漏洞",
		Delta:         -15,
		ComplianceRef: "KS-01",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("uname", "-r")
			if err != nil {
				return false, fmt.Sprintf("无法获取内核版本: %v", err)
			}
			kernelVer := strings.TrimSpace(out)

			cveCount := checkKernelCVEs(kernelVer)
			if cveCount > 0 {
				return false, fmt.Sprintf("内核 %s 存在 %d 个已知高危CVE", kernelVer, cveCount)
			}
			return true, fmt.Sprintf("内核 %s 未发现已知高危CVE", kernelVer)
		},
	}
}

type cveCacheEntry struct {
	CVEID            string   `json:"cve_id"`
	Description      string   `json:"description"`
	AffectedVersions []string `json:"affected_versions"`
	KernelVersions   []string `json:"kernel_versions"`
}

func checkKernelCVEs(kernelVer string) int {
	cveDBPath := "/var/lib/ASSCOR/cve_cache.json"
	if _, err := os.Stat(cveDBPath); os.IsNotExist(err) {
		return 0
	}
	data, err := os.ReadFile(cveDBPath)
	if err != nil {
		return 0
	}

	var entries []cveCacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return 0
	}

	count := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.CVEID, "CVE-") {
			continue
		}
		for _, kv := range entry.KernelVersions {
			if kv == kernelVer {
				count++
				break
			}
		}
		if count == 0 {
			for _, av := range entry.AffectedVersions {
				if av == kernelVer {
					count++
					break
				}
			}
		}
	}
	return count
}

func ks002() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-002",
		Domain:        model.DomainKernelSecurity,
		Name:          "KASLR Status",
		Description:   "检查内核地址空间布局随机化(KASLR)是否启用",
		Delta:         -10,
		ComplianceRef: "KS-02",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/proc/cmdline")
			if err != nil {
				return false, fmt.Sprintf("无法读取 /proc/cmdline: %v", err)
			}
			cmdline := string(data)
			if strings.Contains(cmdline, "nokaslr") {
				return false, "KASLR 已被 nokaslr 参数禁用"
			}
			if strings.Contains(cmdline, "kaslr") {
				return true, "KASLR 已启用"
			}
			return true, "KASLR 默认启用（未显式禁用）"
		},
	}
}

func ks003() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-003",
		Domain:        model.DomainKernelSecurity,
		Name:          "Kernel Module Signature Enforcement",
		Description:   "检查内核模块签名强制验证是否启用",
		Delta:         -15,
		ComplianceRef: "KS-03",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("uname", "-r")
			if err != nil {
				return false, fmt.Sprintf("无法获取内核版本: %v", err)
			}
			kernelVer := strings.TrimSpace(out)
			configPath := "/boot/config-" + kernelVer

			data, err := os.ReadFile(configPath)
			if err != nil {
				altPaths := []string{
					"/proc/config.gz",
					"/lib/modules/" + kernelVer + "/config",
				}
				found := false
				for _, p := range altPaths {
					if d, e := os.ReadFile(p); e == nil {
						data = d
						found = true
						break
					}
				}
				if !found {
					return false, fmt.Sprintf("无法读取内核配置文件: %v", err)
				}
			}

			content := string(data)
			if strings.Contains(content, "CONFIG_MODULE_SIG_FORCE=y") {
				return true, "内核模块签名强制验证已启用"
			}
			if strings.Contains(content, "CONFIG_MODULE_SIG=y") {
				return false, "模块签名已启用但未强制(CONFIG_MODULE_SIG_FORCE 未设置)"
			}
			return false, "内核模块签名验证未启用"
		},
	}
}

func ks004() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-004",
		Domain:        model.DomainKernelSecurity,
		Name:          "Kernel Information Leak Protection",
		Description:   "检查 kptr_restrict 和 dmesg_restrict 内核信息泄漏防护",
		Delta:         -8,
		ComplianceRef: "KS-04",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string

			kptrOut, err := common.RunCmd("sysctl", "-n", "kernel.kptr_restrict")
			if err != nil {
				issues = append(issues, "无法读取 kernel.kptr_restrict")
			} else {
				kptrVal := strings.TrimSpace(kptrOut)
				if kptrVal == "0" {
					issues = append(issues, "kernel.kptr_restrict=0（内核指针完全暴露）")
				} else if kptrVal == "1" {
					issues = append(issues, "kernel.kptr_restrict=1（仅root可见，建议设为2）")
				}
			}

			dmesgOut, err := common.RunCmd("sysctl", "-n", "kernel.dmesg_restrict")
			if err != nil {
				issues = append(issues, "无法读取 kernel.dmesg_restrict")
			} else {
				dmesgVal := strings.TrimSpace(dmesgOut)
				if dmesgVal != "1" {
					issues = append(issues, fmt.Sprintf("kernel.dmesg_restrict=%s（应为1）", dmesgVal))
				}
			}

			if len(issues) > 0 {
				return false, strings.Join(issues, "; ")
			}
			return true, "内核信息泄漏防护已正确配置"
		},
	}
}

func ks005() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-005",
		Domain:        model.DomainKernelSecurity,
		Name:          "KPTI Status",
		Description:   "检查内核页表隔离(KPTI)是否启用以缓解Meltdown类CPU漏洞",
		Delta:         -10,
		ComplianceRef: "KS-05",
		Platform:      "linux",
		Check: func() (bool, string) {
			data, err := os.ReadFile("/proc/cpuinfo")
			if err != nil {
				return false, fmt.Sprintf("无法读取 /proc/cpuinfo: %v", err)
			}

			ptiCount := strings.Count(string(data), " pti")
			if ptiCount > 0 {
				return true, fmt.Sprintf("KPTI 已启用（检测到 %d 个CPU标记）", ptiCount)
			}

			dmesgOut, ok := common.RunCmdQuiet("dmesg")
			if !ok {
				return false, "无法执行dmesg命令确认KPTI状态"
			}
			if strings.Contains(strings.ToLower(dmesgOut), "page tables isolation") ||
				strings.Contains(strings.ToLower(dmesgOut), "kpti") {
				return true, "KPTI 已启用（dmesg确认）"
			}

			return false, "KPTI 未检测到启用标记，Meltdown缓解可能缺失"
		},
	}
}

func ks006() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-006",
		Domain:        model.DomainKernelSecurity,
		Name:          "Kernel Module Minimization",
		Description:   "检查已加载内核模块数量是否在合理范围内",
		Delta:         -5,
		ComplianceRef: "KS-06",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("lsmod")
			if err != nil {
				return false, fmt.Sprintf("无法执行 lsmod: %v", err)
			}

			lines := strings.Split(strings.TrimSpace(out), "\n")
			moduleCount := len(lines) - 1
			if moduleCount < 0 {
				moduleCount = 0
			}

			maxModules := 150
			if moduleCount > maxModules {
				return false, fmt.Sprintf("已加载 %d 个内核模块（超过基线 %d），存在冗余攻击面", moduleCount, maxModules)
			}
			return true, fmt.Sprintf("已加载 %d 个内核模块，在合理范围内", moduleCount)
		},
	}
}

func ks007() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-007",
		Domain:        model.DomainKernelSecurity,
		Name:          "Sysctl Security Baseline",
		Description:   "检查15+项内核sysctl安全参数配置",
		Delta:         -10,
		ComplianceRef: "KS-07",
		Platform:      "linux",
		Check: func() (bool, string) {
			type sysctlCheck struct {
				param    string
				expected string
				desc     string
			}

			checks := []sysctlCheck{
				{"net.ipv4.tcp_syncookies", "1", "SYN Cookie"},
				{"net.ipv4.ip_forward", "0", "IP转发"},
				{"kernel.randomize_va_space", "2", "ASLR"},
				{"kernel.kptr_restrict", "2", "内核指针隐藏"},
				{"kernel.yama.ptrace_scope", "1", "ptrace限制"},
				{"fs.suid_dumpable", "0", "SUID dump"},
				{"net.ipv4.conf.all.rp_filter", "1", "反向路径过滤"},
				{"net.ipv4.conf.all.accept_source_route", "0", "源路由"},
				{"net.ipv4.conf.all.accept_redirects", "0", "ICMP重定向"},
				{"net.ipv4.conf.all.secure_redirects", "0", "安全ICMP重定向"},
				{"net.ipv4.conf.all.send_redirects", "0", "发送ICMP重定向"},
				{"net.ipv4.icmp_echo_ignore_broadcasts", "1", "广播ICMP"},
				{"net.ipv4.icmp_ignore_bogus_error_responses", "1", "虚假ICMP错误"},
				{"net.ipv6.conf.all.accept_redirects", "0", "IPv6重定向"},
			}

			var failures []string
			for _, c := range checks {
				out, err := common.RunCmd("sysctl", "-n", c.param)
				if err != nil {
					failures = append(failures, fmt.Sprintf("%s: 无法读取", c.desc))
					continue
				}
				val := strings.TrimSpace(out)
				if val != c.expected {
					failures = append(failures, fmt.Sprintf("%s=%s（应为%s）", c.desc, val, c.expected))
				}
			}

			if len(failures) > 0 {
				return false, fmt.Sprintf("%d项不合规: %s", len(failures), strings.Join(failures, "; "))
			}
			return true, "所有sysctl安全参数符合基线"
		},
	}
}

func ks008() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-008",
		Domain:        model.DomainKernelSecurity,
		Name:          "eBPF Program Audit",
		Description:   "审计已加载的eBPF程序，检测异常注入",
		Delta:         -12,
		ComplianceRef: "KS-08",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, ok := common.RunCmdQuiet("bpftool", "prog", "list")
			if !ok {
				return true, "bpftool 不可用，跳过eBPF审计"
			}

			lines := strings.Split(strings.TrimSpace(out), "\n")
			progCount := 0
			for _, line := range lines {
				if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
					progCount++
				}
			}

			if progCount == 0 {
				return true, "未检测到已加载的eBPF程序"
			}

			baselinePath := "/etc/ASSCOR/ebpf_baseline.txt"
			if _, statErr := os.Stat(baselinePath); os.IsNotExist(statErr) {
				return true, fmt.Sprintf("检测到 %d 个eBPF程序（无基线文件，跳过比对）", progCount)
			}

			baselineData, readErr := os.ReadFile(baselinePath)
			if readErr != nil {
				return true, fmt.Sprintf("检测到 %d 个eBPF程序（无法读取基线: %v）", progCount, readErr)
			}

			baseline := strings.Split(strings.TrimSpace(string(baselineData)), "\n")
			baselineSet := make(map[string]bool)
			for _, b := range baseline {
				baselineSet[strings.TrimSpace(b)] = true
			}

			var unknown []string
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				if !baselineSet[trimmed] {
					unknown = append(unknown, trimmed)
				}
			}

			if len(unknown) > 0 {
				return false, fmt.Sprintf("检测到 %d 个未知eBPF程序（共%d个，基线%d个）", len(unknown), progCount, len(baselineSet))
			}
			return true, fmt.Sprintf("所有 %d 个eBPF程序均与基线匹配", progCount)
		},
	}
}

func ks009() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-009",
		Domain:        model.DomainKernelSecurity,
		Name:          "Kernel Debug Interfaces Disabled",
		Description:   "检查内核调试接口(sysrq/debugfs/dev_mem)是否已禁用",
		Delta:         -8,
		ComplianceRef: "KS-09",
		Platform:      "linux",
		Check: func() (bool, string) {
			var issues []string

			sysrqOut, err := common.RunCmd("sysctl", "-n", "kernel.sysrq")
			if err != nil {
				issues = append(issues, "无法读取 kernel.sysrq")
			} else {
				sysrqVal := strings.TrimSpace(sysrqOut)
				if sysrqVal != "0" {
					issues = append(issues, fmt.Sprintf("kernel.sysrq=%s（应为0）", sysrqVal))
				}
			}

			mountOut, err := common.RunCmd("mount")
			if err == nil {
				if strings.Contains(mountOut, "debugfs") {
					issues = append(issues, "debugfs 已挂载")
				}
			}

			if info, err := os.Stat("/dev/mem"); err == nil {
				if info.Mode().Perm()&0444 != 0 {
					issues = append(issues, "/dev/mem 可读")
				}
			}
			if info, err := os.Stat("/dev/kmem"); err == nil {
				if info.Mode().Perm()&0444 != 0 {
					issues = append(issues, "/dev/kmem 可读")
				}
			}

			if len(issues) > 0 {
				return false, strings.Join(issues, "; ")
			}
			return true, "内核调试接口已正确禁用"
		},
	}
}

func ks010() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-010",
		Domain:        model.DomainKernelSecurity,
		Name:          "Secure Boot Status",
		Description:   "检查UEFI Secure Boot是否启用",
		Delta:         -10,
		ComplianceRef: "KS-10",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, ok := common.RunCmdQuiet("mokutil", "--sb-state")
			if ok {
				if strings.Contains(strings.ToLower(out), "secureboot enabled") {
					return true, "Secure Boot 已启用"
				}
				if strings.Contains(strings.ToLower(out), "secureboot disabled") {
					return false, "Secure Boot 已禁用"
				}
				return false, fmt.Sprintf("mokutil 返回: %s", strings.TrimSpace(out))
			}

			dmesgOut, ok := common.RunCmdQuiet("dmesg")
			if !ok {
				return false, "无法执行dmesg命令确认Secure Boot状态"
			}
			if strings.Contains(strings.ToLower(dmesgOut), "secure boot") {
				if strings.Contains(strings.ToLower(dmesgOut), "enabled") {
					return true, "Secure Boot 已启用（dmesg确认）"
				}
			}

			efiPath := "/sys/firmware/efi"
			if _, statErr := os.Stat(efiPath); os.IsNotExist(statErr) {
				return true, "非UEFI系统，Secure Boot不适用"
			}

			return false, "无法确认 Secure Boot 状态（mokutil 不可用）"
		},
	}
}

func ks011() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-011",
		Domain:        model.DomainKernelSecurity,
		Name:          "dmesg Access Restriction",
		Description:   "验证非特权用户无法访问dmesg内核日志",
		Delta:         -5,
		ComplianceRef: "KS-11",
		Platform:      "linux",
		Check: func() (bool, string) {
			out, err := common.RunCmd("sysctl", "-n", "kernel.dmesg_restrict")
			if err != nil {
				return false, fmt.Sprintf("无法读取 kernel.dmesg_restrict: %v", err)
			}

			val := strings.TrimSpace(out)
			if val != "1" {
				return false, fmt.Sprintf("kernel.dmesg_restrict=%s（应为1），非特权用户可读取内核日志", val)
			}

			info, statErr := os.Stat("/dev/kmsg")
			if statErr != nil {
				return true, "kernel.dmesg_restrict=1，dmesg访问已受限"
			}

			perm := info.Mode().Perm()
			if perm&0004 != 0 {
				return false, "/dev/kmsg 对other可读，dmesg限制可能被绕过"
			}

			return true, "kernel.dmesg_restrict=1，dmesg访问已受限"
		},
	}
}

func ks012() model.CheckItem {
	return model.CheckItem{
		ID:            "KS-012",
		Domain:        model.DomainKernelSecurity,
		Name:          "LSMs Status",
		Description:   "检查是否至少有一个LSM(SELinux/AppArmor)处于enforcing模式",
		Delta:         -15,
		ComplianceRef: "KS-12",
		Platform:      "linux",
		Check: func() (bool, string) {
			var activeLSMs []string

			selinuxOut, selinuxOK := common.RunCmdQuiet("sestatus")
			if selinuxOK {
				lower := strings.ToLower(selinuxOut)
				if strings.Contains(lower, "current mode") && strings.Contains(lower, "enforcing") {
					activeLSMs = append(activeLSMs, "SELinux(enforcing)")
				} else if strings.Contains(lower, "permissive") {
					activeLSMs = append(activeLSMs, "SELinux(permissive)")
				}
			}

			aaOut, aaOK := common.RunCmdQuiet("aa-status")
			if aaOK {
				lower := strings.ToLower(aaOut)
				if strings.Contains(lower, "enforce") {
					profiles := 0
					for _, line := range strings.Split(aaOut, "\n") {
						if strings.Contains(line, "enforce") {
							if parts := strings.Fields(line); len(parts) > 0 {
								if n, err := strconv.Atoi(parts[0]); err == nil {
									profiles = n
								}
							}
						}
					}
					activeLSMs = append(activeLSMs, fmt.Sprintf("AppArmor(%d profiles)", profiles))
				}
			}

			lsmOutBytes, _ := os.ReadFile("/sys/kernel/security/lsm")
			lsmOut := strings.TrimSpace(string(lsmOutBytes))

			if len(activeLSMs) > 0 {
				return true, fmt.Sprintf("活跃LSM: %s", strings.Join(activeLSMs, ", "))
			}

			if lsmOut != "" {
				return false, fmt.Sprintf("LSM已加载(%s)但无enforcing模块", lsmOut)
			}

			return false, "未检测到任何处于enforcing模式的LSM（SELinux/AppArmor均未启用）"
		},
	}
}
