# ASSCOR 扩展白皮书：内核安全域

**版本**：v1.3\
**日期**：2026-06-28
**状态**：发布\
**配套文档**：SSAM 2.0 白皮书（第一至第四篇章）、APT 攻击分析与检测增强白皮书

***

## 摘要

ASSCOR 在等保三级 53 项检查基础上，向安全纵深领域扩展。本白皮书以**内核安全**为扩展域，系统定义 12 项内核层检查指标，覆盖内核漏洞管理、内存防护、模块签名强制、eBPF 审计、LSM 状态等关键攻击面。内核作为系统最高权限层，是 Rootkit、权限提升、进程隐藏等高级威胁的主战场——传统合规评估对此几乎完全空白。通过将这些内核级检查纳入 ASSCOR 评估体系，模型覆盖范围从应用层延伸至 ring 0，为安全可接受性评估提供更完整的纵深防御视角。

***

## 1. 为什么需要内核安全扩展

### 1.1 合规评估的盲区

等保 2.0（GB/T 22239-2019）对安全计算环境的控制点集中在身份鉴别、访问控制、安全审计、入侵防范等层面。这些检查项覆盖了操作系统配置、服务管理、用户权限等“用户态”安全——但**对内核层的安全状态几乎没有触及**。

攻击者的现实路径是：

```
Web 漏洞 → 低权 shell → 内核提权 → 加载 Rootkit → 持久化 → 横向移动
```

在这条杀伤链中，**内核提权是攻击者从“普通用户”变成“完全控制”的关键一跃**。如果评估体系只看到 Web 漏洞而看不到内核防护，就好比给房子装了防盗门但忘了锁地下室入口。

### 1.2 内核攻击面的特殊性

内核层攻击面具有三个特征，使传统检测手段难以覆盖：

| 特征        | 说明                           | 传统手段的不足                               |
| :-------- | :--------------------------- | :------------------------------------ |
| **最高权限**  | 内核运行在 ring 0，可绕过所有用户态防护      | HIDS/EDR 运行在 ring 3，对内核级 Rootkit 可能失明 |
| **隐蔽性强**  | eBPF、LKM 等合法机制可被武器化          | 传统签名检查无法区分合法 eBPF 程序和恶意植入             |
| **持久化深度** | Bootkit、initramfs 篡改可存活至系统重装 | 用户态持久化检测无法触及启动链                       |

### 1.3 内核安全域的定位

内核安全域（Kernel Security, KS）检查项关注以下核心问题：

> **系统的内核层是否具备抵抗高级威胁的能力？是否配置了基本的纵深防护？**

与韧性域（Resilience）的区别：韧性域关注“被攻破后能否控制损害”，内核安全域关注“攻破内核本身的门槛有多高”。两者互补，共同构成纵深防御的内外环。

***

## 2. 内核安全域检查项

内核安全域共 **12 项**检查，覆盖内核漏洞管理、内存防护、模块完整性、eBPF 审计、调试接口安全、强制访问控制等维度。

### 2.1 检查项总览

| ID     | 检查项         | 检查方法                                | 默认影响 |
| :----- | :---------- | :---------------------------------- | :--: |
| KS-001 | 内核版本已知漏洞    | 比对 `uname -r` 与 CVE 数据库             |  -15 |
| KS-002 | KASLR 状态    | 检查 `/proc/cmdline` 中 `kaslr` 参数     |  -10 |
| KS-003 | 内核模块签名强制    | 检查 `CONFIG_MODULE_SIG_FORCE` 与模块签名  |  -15 |
| KS-004 | 内核信息泄漏防护    | 检查 `kptr_restrict`、`dmesg_restrict` |  -8  |
| KS-005 | KPTI 状态     | 检查 `/proc/cpuinfo` 中 `pti` 标记       |  -10 |
| KS-006 | 内核模块最小化     | 通过 `lsmod` 统计加载模块数                  |  -5  |
| KS-007 | Sysctl 安全基线 | 检查 15+ 项内核参数                        |  -10 |
| KS-008 | eBPF 程序审计   | `bpftool prog list` 与已知基线比对         |  -12 |
| KS-009 | 内核调试接口禁用    | 检查 sysrq、debugfs、/dev/mem           |  -8  |
| KS-010 | Secure Boot | 检查 `mokutil --sb-state`             |  -10 |
| KS-011 | dmesg 权限    | 检查 `dmesg_restrict`                 |  -5  |
| KS-012 | LSMs 启用状态   | 至少一个 LSM 处于 enforcing               |  -15 |

### 2.2 与现有检查项的去重声明

以下内核检查项与已有检查项存在检测目标的相近性，已做去重处理：

| 内核检查项                         | 已有检查项                   | 处理方式                                  |
| :---------------------------- | :---------------------- | :------------------------------------ |
| KS-007 中 `tcp_syncookies`     | RS-005 SYN Cookie 防护    | KS-007 改为引用 RS-005 结果，不重复扣分           |
| KS-007 中 `randomize_va_space` | ED-012 内存保护             | KS-007 改为引用 ED-012 结果                 |
| KS-010 Secure Boot            | ED-008 安全启动             | KS-010 聚焦内核验证链，ED-008 聚焦终端引导，两者保留     |
| KS-012 LSM 状态                 | OT-005 SELinux/AppArmor | KS-012 检查所有 LSM，OT-005 仅查 SELinux，不冲突 |

***

## 3. 检查项详细定义

### KS-001：内核版本已知漏洞

**检查逻辑**：

获取当前运行内核版本，与本地 CVE 数据库缓存进行版本号匹配，检查是否存在未修补的提权类或 RCE 类内核漏洞。

```bash
uname -r  # 获取当前内核版本
# 与本地 CVE 缓存比对，查找该版本的已知漏洞
```

**安全意义**：这是内核安全最基础的检查。内核 CVE 通常伴随“本地提权”能力，能让 WebShell 直接跃迁至 ring 0。未修补内核漏洞意味着系统承受着一条通往完全控制权的公开通道。

***

### KS-002：KASLR（内核地址空间布局随机化）

**检查逻辑**：

```bash
# 应包含 kaslr，不应包含 nokaslr
cat /proc/cmdline | grep -o 'kaslr\|nokaslr'
```

**安全意义**：KASLR 是内核漏洞利用的第一道阻碍。没有 KASLR，攻击者可以硬编码内核地址，将漏洞利用的可靠性提升至接近 100%。`nokaslr` 通常出现在某些硬件兼容性问题或调试场景中，不应在线上环境出现。

***

### KS-003：内核模块签名强制

**检查逻辑**：

```bash
# 检查内核是否强制模块签名验证
grep CONFIG_MODULE_SIG_FORCE /boot/config-$(uname -r)
# 检查已加载模块的签名情况
cat /sys/module/*/signature 2>/dev/null
```

**安全意义**：恶意内核模块（LKM Rootkit）是最经典的持久化手段。签名强制确保只有经过签名的模块才能插入内核。在 UEFI + Secure Boot 环境下，这形成了从固件到内核模块的完整信任链。若此项未通过，攻击者只需编译一个简单的 `hello world` 模块即可获得 ring 0 权限。

***

### KS-004：内核信息泄漏防护

**检查逻辑**：

```bash
sysctl kernel.kptr_restrict   # 应为 2（完全隐藏）或 1（仅 root）
sysctl kernel.dmesg_restrict  # 应为 1
```

**安全意义**：`kptr_restrict` 控制 `/proc/kallsyms` 中内核函数地址的可见性。若设为 0，任何用户都可以直接读取内核函数地址，从而绕过 KASLR。`dmesg_restrict` 则限制只有特权用户才能访问内核日志缓冲区——攻击者常从 dmesg 中提取驱动版本、内存布局等关键侦察信息。

***

### KS-005：KPTI（内核页表隔离）

**检查逻辑**：

```bash
# 检查 CPU 漏洞缓解是否启用
grep -c pti /proc/cpuinfo
dmesg | grep -i "page tables isolation"
```

**安全意义**：KPTI（原名 KAISER）是 Meltdown 类 CPU 漏洞的核心缓解措施。它将内核页表和用户页表分离，使攻击者无法通过侧信道读取内核内存。没有 KPTI，Meltdown 可被用来从用户态直接窃取内核中的任意数据。

***

### KS-006：内核模块最小化

**检查逻辑**：

```bash
lsmod | wc -l  # 与运维团队设定的基线对比
# 检查是否有已知的可疑内核模块（黑名单机制）
```

**安全意义**：每个内核模块都是潜在的攻击面。过多未使用的模块增加了可被利用的代码量。运维团队应根据服务器角色设定内核模块基线（如 Web 服务器 vs 数据库服务器），ASSCOR 据此判断是否存在冗余或可疑模块。

***

### KS-007：Sysctl 安全基线

**检查逻辑**：一次性采集 15+ 项内核参数，逐一与安全基线比对。

**检查参数表**：

| 参数                                           | 安全值            | 说明                      |
| :------------------------------------------- | :------------- | :---------------------- |
| `net.ipv4.tcp_syncookies`                    | 1              | SYN Flood 防护（引用 RS-005） |
| `net.ipv4.ip_forward`                        | 0              | 禁止非路由器转发                |
| `kernel.randomize_va_space`                  | 2              | 完整 ASLR（引用 ED-012）      |
| `kernel.kptr_restrict`                       | 2              | 内核指针完全隐藏                |
| `kernel.yama.ptrace_scope`                   | 1              | 限制 ptrace               |
| `kernel.core_pattern`                        | `\|/bin/false` | 禁止 core dump            |
| `fs.suid_dumpable`                           | 0              | 禁止 suid 程序 dump         |
| `net.ipv4.conf.all.rp_filter`                | 1              | 反向路径过滤                  |
| `net.ipv4.conf.all.accept_source_route`      | 0              | 禁止源路由                   |
| `net.ipv4.conf.all.accept_redirects`         | 0              | 禁止 ICMP 重定向             |
| `net.ipv4.conf.all.secure_redirects`         | 0              | 禁止安全 ICMP 重定向           |
| `net.ipv4.conf.all.send_redirects`           | 0              | 不发送 ICMP 重定向            |
| `net.ipv4.icmp_echo_ignore_broadcasts`       | 1              | 忽略广播 ICMP               |
| `net.ipv4.icmp_ignore_bogus_error_responses` | 1              | 忽略虚假 ICMP 错误            |
| `net.ipv6.conf.all.accept_redirects`         | 0              | IPv6 禁止重定向              |

**安全意义**：Sysctl 参数是 Linux 内核安全配置的核心。这些参数控制了网络栈行为、内存保护、进程限制等关键安全机制。错误配置可能直接打开信息泄漏、拒绝服务、权限提升等攻击路径。一次扫描即可覆盖多个安全基线。

***

### KS-008：eBPF 程序审计

**检查逻辑**：

```bash
# 列出所有已加载的 eBPF 程序
bpftool prog list 2>/dev/null
# 与运维团队维护的合法 eBPF 基线比对
```

**安全意义**：eBPF 是近年来最活跃的攻击向量。攻击者可以将恶意 eBPF 程序注入内核，实现流量劫持、数据窃取、进程隐藏等操作，且传统 HIDS 对这些行为几乎不可见。此项检查要求运维团队维护一份合法 eBPF 基线，ASSCOR 据此判断是否存在异常注入。

***

### KS-009：内核调试接口

**检查逻辑**：

```bash
sysctl kernel.sysrq           # 应为 0
mount | grep -c debugfs       # 应不挂载
ls -la /dev/mem /dev/kmem     # 应不可读写
```

**安全意义**：`/sys/kernel/debug`（debugfs）暴露大量内核内部数据结构，是攻击者信息收集的金矿。`/dev/mem` 和 `/dev/kmem` 可直接读写物理内存和内核虚拟内存，一旦被利用即可绕过所有访问控制。线上环境应关闭所有调试接口。

***

### KS-010：Secure Boot

**检查逻辑**：

```bash
mokutil --sb-state 2>/dev/null
dmesg | grep -i secureboot
```

**安全意义**：Secure Boot 是固件层的安全基石，确保只有经过签名的引导程序和内核能被加载。它与 KS-003（内核模块签名强制）共同构成从固件到内核模块的完整信任链。没有 Secure Boot，攻击者可以通过物理访问或远程管理接口植入 Bootkit，这种恶意软件在操作系统重装后仍然存活。

***

### KS-011：dmesg 权限

**检查逻辑**：

```bash
sysctl kernel.dmesg_restrict  # 应为 1
```

**安全意义**：与 KS-004 互补——KS-004 检查 `dmesg_restrict` 参数值，KS-011 进一步验证非特权用户尝试访问 dmesg 时的实际行为。默认情况下，`dmesg` 包含大量系统启动信息、硬件固件版本、驱动加载日志等关键侦察数据。

***

### KS-012：LSMs 状态

**检查逻辑**：

```bash
# 检查是否至少有一个 LSM 处于 enforcing
sestatus 2>/dev/null | grep -i "current mode.*enforcing"
aa-status 2>/dev/null | grep -i "profiles.*enforce\|apparmor.*enforce"
```

**安全意义**：LSMs（Linux Security Modules）是强制访问控制的框架层。SELinux、AppArmor、TOMOYO、SMACK 中至少一个应处于 enforcing 模式。没有任何 LSM 执行强制访问控制，意味着进程权限在内核层几乎不受约束——攻击者一旦获得 shell，可以访问系统上几乎所有资源。

***

## 4. 与 SSAM 评估体系的集成

### 4.1 扩展域与核心域的关系

内核安全域并非与等保四核心域并列，而是作为**附加评估层**运行：

| 层       | 内容                   | 作用          |
| :------ | :------------------- | :---------- |
| **核心层** | 攻击面管理、业务连续性、操作可信度、韧性 | 等保合规基础评估    |
| **扩展层** | 内核安全                 | 纵深防御与高级威胁覆盖 |

### 4.2 配置方式

管理员可在 `config.ini` 中灵活启用内核安全扩展：

```ini
[extensions]
kernel_security = on

[extension_weights]
kernel_security = 10
```

内核安全域得分独立计算，作为**附加参考分数**展示在评估报告中，不影响等保合规的核心判定，但可提供更全面的安全可见性。

### 4.3 评估报告输出示例

```
[ Core Domain Scores ]
---------------------------------------------------------------
  Attack Surface      : [====================] 63/100
  Business Continuity : [============        ] 60/100
  Operation Trust     : [=====               ] 24/100
  Resilience          : [                    ] 0/100

[ Extension Domain Scores ]
---------------------------------------------------------------
  Kernel Security     : [========            ] 40/100  (5 of 12 checks passed)

[ Kernel Security Details ]
---------------------------------------------------------------
  [PASS] KS-002 : KASLR Status
  [PASS] KS-005 : KPTI Status
  [FAIL] KS-003 : Kernel Module Signature Enforcement
  [FAIL] KS-008 : eBPF Program Audit
  [FAIL] KS-012 : LSMs Status
  ...
```

***

## 5. 实现路线图

| 阶段          | 内容                  | 状态       |
| :---------- | :------------------ | :------- |
| **Phase 1** | 内核安全域检查项定义（12 项）    | ✅ 本白皮书完成 |
| **Phase 2** | KS-001\~012 检查函数实现  | ✅ 已完成（`internal/checks/linux/kernel_security.go`） |
| **Phase 3** | 内核安全域集成到 ASSCOR 评估引擎 | ✅ 已完成（通过 `All()` 函数注册，Delta 在 `config.ini` 配置） |
| **Phase 4** | 内核安全域 Agent 插件发布    | 📋 待开发   |

***

## 6. 总结

ASSCOR 内核安全域将安全评估的触角从用户态伸入 ring 0，覆盖 Rootkit、eBPF 后门、内核提权等高级威胁的主战场。12 项检查指标从内核漏洞管理、内存防护、模块完整性、运行时审计、调试接口安全到强制访问控制，形成了一个完整的内核安全评估闭环。

**在真实的 APT 攻击中，内核是攻击者必须征服的最后一个堡垒。ASSCOR 的内核安全域，就是为这个堡垒配备的防护检测仪。**

***

**版本历史**\
v1.0 — 2026-05-14，内核安全域完整定义，作为 ASSCOR 首个扩展域白皮书独立发布。\
v1.1 — 2026-05-20，配套文档版本号更新至 SSAM 2.0；Phase 2 状态更新为开发中；补充与核心域检查项（RS-005 SYN Cookie、RS-002 Fail2ban 自动封禁、RS-003 连接数限制）的交互说明。
v1.2 — 2026-05-26，Phase 2/3 状态更新为已完成；KS-001~012 已在 `kernel_security.go` 中实现并通过 `All()` 注册集成到评估引擎。
