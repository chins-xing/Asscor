# ASSCOR ʹ���ֲ�

> �汾��v0.2.3 | SSAM 2.0 | �����£�2026-08-12

> ?? ASSCOR ����ķ�����һ��**��ѧģ�͵ļ����������Ǿ��Եİ�ȫ��ֵ��**
> �뽫������Ϊ���߲ο����Ǿ��������ģ���ܲ�����֪�Ŀ�����ά�ȣ�����ȫ��
> ����ͼ��Զ���κι�ʽ�ĸ��Ƿ�Χ��

---

## Ŀ¼

1. [����](#1-����)
2. [���ٿ�ʼ](#2-���ٿ�ʼ)
3. [����ܹ�](#3-����ܹ�)
4. [Kernel ����](#4-kernel-����)
5. [Agent ����](#5-agent-����)
6. [TLS ֤�����](#6-tls-֤�����)
7. [�����ļ����](#7-�����ļ����)
8. [SPC ��ȫ̬��ģ��](#8-spc-��ȫ̬��ģ��)
9. [�ȱ�ӳ����������ֵ](#9-�ȱ�ӳ����������ֵ)
10. [ATT&CK V19 ��в����ģ��](#10-attck-v19-��в����ģ��)
11. [��־����](#11-��־����)
12. [�ػ�����ģʽ](#12-�ػ�����ģʽ)
13. [��������ģʽ](#13-��������ģʽ)
14. [���������ο�](#14-���������ο�)
15. [�����Ų�](#15-�����Ų�)

---

## 1. ����

ASSCOR ��һ����Դ�ķֲ�ʽ��ȫ�ɽ���������ϵͳ��ʵ����ϵͳ��ȫ�ɽ�����ģ�ͣ�SSAM��2.0��ϵͳͨ���ĸ��������������������ȫ״̬�������� MITRE ATT&CK V19 ��в������ܣ��ṩ�Ӱ�ȫ��������в��⵽ APT ����������������������

SSAM V2.0 ������������ģ�ͣ����� Intrinsic / ��¶ Exposure / ��в Threat�����������������ղ��Ȩƽ��ȡ���ɰ� ThreatCoeff/SPCScore ˫�ط��ֻ��ƣ��������ֵĿɽ������빫���ԡ������㷨���Ѷ���Ϊ [github.com/chins-xing/ssam](https://github.com/chins-xing/ssam)��`ssam-lib/`�������ⲿ������������ʽ��ơ�ASSCOR ƽ̨ͨ�� `internal/ssam/` �������ί�е��á�

| ������ | Ȩ�� | �������� |
|--------|------|----------|
| ��������� | 35% | ���÷��񡢿��Ŷ˿ڡ�ǿ��֤��SSH ���� |
| ҵ�������� | 25% | �ؼ��������С����ݻ��ơ���Դ��ԣ�� |
| �������Ŷ� | 25% | �ļ�Ȩ�ޡ������־��������ʷ���۸ġ���Ӧ�������ԡ�SELinux/AppArmor |
| ���� | 15% | �Զ�������ȡ�SYN Cookie���������ơ��ɽ�������ָ�꣨ACI�� |

**����ģ��**��

| ģ�� | ���� |
|------|------|
| ATT&CK V19 | MITRE ATT&CK ��ܼ��ɣ�����������в�鱨�����ַ��桢�������̡�APT ��������������ǿ |
| SPC | ��ȫ̬�Ƽ��㣬NVD/EPSS/CISA KEV/CNNVD/CNVD ��Դ©���鱨�뱾���ʲ��ȶ� |
| CTI | ������в�鱨�������̬��вϵ�� �� ���� |

**���ֹ�ʽ**��

```
SSAM_final = (��(S_i �� W_i) / ��W_i) �� ��M_j �� �� �� P_score
```

- `S_i`�������������0�C100��
- `W_i`��������Ȩ�أ��ܺ� 100��
- `M_j`����Ե���ӳ��������� Active �� Factor �� (0,1) ������ִ�����ˣ�
- `��`����вϵ����Ĭ�� 1.0���� CTI ģ�鶯̬������
- `P_score`��SPC �������ӣ�0.60�C1.00������ CVE ƥ�������㣩

---

## 2. ���ٿ�ʼ

### 2.1 ǰ������

- Ŀ��������Linux��֧�� x86_64 / ARM64 / i386��
- Kernel �� Agent ������ɴ�
- ���Ƽ���NVD API Key���� https://nvd.nist.gov/developers/request-an-api-key ��ȡ

### 2.2 ��С�����������Ƽ���

```bash
# 1. ��װ����� Kernel��һ��������� systemd + FHS + PATH��
sudo ./ASSCOR-kernel-linux --install
sudo systemctl start asscor-kernel

# 2. ��װ����� Agent��Ŀ��������
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent

# 3. ���� CLI ����
asscor-cli               # status / plugins / history / exit
```

### 2.3 �������������� Kernel/Agent��

```bash
# ����ģʽ��ֱ���ڱ���ִ�������������ӡ���ն�
./ASSCOR-linux --config=/etc/asscor/config.ini          # �ı�����
./ASSCOR-linux --config=/etc/asscor/config.ini -json    # JSON ����
```

---

## 3. ����ܹ�

```
������������������������������������������������������������������������������������������������������
��                  ASSCOR Kernel                    ��
��  ���������������� ���������������� ���������������� ���������������� ���������������� ��
��  ��Assess�� ��Policy�� �� SPC  �� �� CTI  �� ��Cmdr  �� ��
��  �������Щ������� �������Щ������� �������Щ������� �������Щ������� �������Щ������� ��
��  ����������������                                      ��
��  ��ATT&CK��  MITRE ATT&CK V19 ��в����           ��
��  �������Щ�������  ���/�鱨/����/����/APT��ǿ          ��
��     ��        ��        ��        ��        ��      ��
��  �������ة����������������ة����������������ة����������������ة����������������ة�����   ��
��  ��         ��Kernel Plugin Bus              ��   ��
��  �����������������������������������Щ�����������������������������������������������   ��
��                   �� gRPC + mTLS                ��
�����������������������������������������੤������������������������������������������������������
                    ��
        �������������������������੤����������������������
        ��           ��           ��
   �����������ة��������� �����������ة��������� �����������ة���������
   �� Agent A �� �� Agent B �� �� Agent C ��
   ��(host-01)�� ��(host-02)�� ��(host-03)��
   ���������������������� ���������������������� ����������������������
```

**���˵��**��

| ��� | ְ�� |
|------|------|
| Kernel | ΢�ںˣ��������������ڡ�gRPC ����CLI ���� |
| Agent | �����ڱ������������ռ���������ݲ��ϱ� |
| CLI | Kernel ���ý���ʽ�նˣ��ṩ�����й������� |

---

## 4. Kernel ����

### 4.1 �����в���

```
ASSCOR-kernel [ѡ��]
```

| ���� | Ĭ��ֵ | ˵�� |
|------|--------|------|
| `--config` | `config.ini` | �����ļ�·�� |
| `--listen` | `:50051` | gRPC ������ַ |
| `--webui-port` | `8087` | Web �Ǳ��̶˿ڣ�0 ���ã� |
| `--no-mtls` | `false` | ���� mTLS��**���޿�������**�� |
| `--cert-dir` | `certs` | TLS ֤��Ŀ¼ |
| `--verify-certs` | `false` | ��֤֤����һ���Ժ��˳� |
| `--force-regen-certs` | `false` | ǿ�������������� TLS ֤�� |
| `--daemon` | `false` | ���ػ�����ģʽ���� |
| `--pid-file` | `ASSCOR-kernel.pid` | PID �ļ�·�� |
| `--version` | �� | ��ʾ�汾���˳� |
| `--install` | �� | ��װΪ systemd ������ root�� |
| `--uninstall` | �� | ж�� systemd ������ root�� |
| `--upgrade` | �� | ԭ�������Ѱ�װ�汾���� root�� |
| `--check-install` | �� | У�鰲װ�����Ժ��˳� |
| `--cli <socket>` | �� | ���ӵ��������ں˵� CLI��Unix socket�� |
| `--log-format` | `json` | ��־��ʽ��`json`��`text` |
| `--log-level` | `info` | ��־����`debug`��`info`��`warn`��`error` |
| `--log-output` | `stderr` | ��־�����`stderr`��`stdout`�����ļ�·�� |

### 4.2 ��������systemd + FHS���Ƽ���

���������Դ���װ������һ��������� systemd ����ע�ᡢFHS Ŀ¼���֡�PATH �������ӡ��û�������

```bash
# ��װ���� root��
sudo ./ASSCOR-kernel-linux --install

# ��� + ��������
sudo systemctl start asscor-kernel
sudo systemctl enable asscor-kernel

# ��װ Agent��ͬһ����������������
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent
```

**FHS �ļ�ϵͳ����**��

```
/etc/asscor/config.ini              # �ں�����
/etc/asscor/agent.ini               # Agent ����
/etc/asscor/config/                 # 6 ��ҵģ��
/opt/asscor/ASSCOR-kernel           # �ں˶�����
/opt/asscor/agent/ASSCOR-agent      # Agent ������
/opt/asscor/asscor-cli.sock         # CLI Unix socket
/var/lib/asscor/                    # ���ݣ�CVE ���桢������¼�����ݣ�
/var/lib/asscor/latest-assessment.json      # ������������
/var/lib/asscor/assessments-<date>.jsonl     # ��ʷ������¼
/var/log/asscor/kernel.log          # �ں���־
/usr/bin/asscor                     # ȫ������������ӣ�
/usr/bin/asscor-cli                 # CLI ��ݰ�װ�ű�
```

��װ�� `asscor` �� `asscor-cli` ������·������ `sudo`�����á�

### 4.3 systemctl �ܿ�

| ���� | Ч�� |
|------|------|
| `systemctl start asscor-kernel` | ������� |
| `systemctl stop asscor-kernel` | ֹͣ��SIGTERM �� ���Źرգ����� CVE ���棩 |
| `systemctl reload asscor-kernel` | SIGHUP �� ������ config.ini��Ȩ��/��ֵ/Prism/��Ե���ӣ� |
| `systemctl status asscor-kernel` | �鿴״̬ |
| `journalctl -u asscor-kernel -f` | ʵʱ������־ |

### 4.4 �汾����

```bash
# ԭ���������Զ�ֹͣ�����ݡ��滻�������ʧ���Զ��ع���
sudo ./ASSCOR-kernel-v0.2.3-linux-amd64 --upgrade
asscor --version         # ȷ�ϰ汾
```

�������Զ����� PATH �������Ӳ�����ɶ������� `.bak`��

### 4.5 Զ�� CLI

�ں��� systemd ��������ʱ���޽����նˣ���ͨ�� Unix socket ���� CLI��

```bash
asscor-cli               # ��ݷ�ʽ���Զ����� socket��
# ��
asscor --cli /opt/asscor/asscor-cli.sock

asscor> status           # �鿴�ں�״̬
asscor> plugins          # ����б�
asscor> exit             # �Ͽ����ں˼������У�
```

> `exit`/`quit` ���Ͽ���ǰ CLI �Ự���ں˳������С�ֻ�� `systemctl stop` �Ż������˳��ںˡ�

### 4.6 �����в������ֶ����У�

```bash
ASSCOR-kernel [ѡ��]
```

### 4.7 ���ʾ��

```bash
# ��׼�����mTLS ���ã�
./ASSCOR-kernel-linux --config=/etc/asscor/config.ini --listen=:50051

# ����ģʽ���� mTLS��
./ASSCOR-kernel-linux --no-mtls --log-level=debug --log-format=text

# �ػ�����ģʽ
./ASSCOR-kernel-linux --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# ��֤֤��
./ASSCOR-kernel-linux --verify-certs --cert-dir=/etc/asscor/certs

# ��������֤��
./ASSCOR-kernel-linux --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 4.3 ������

Kernel �������ʾ����״̬��

```
ASSCOR ��Kernel
  Framework: v0.2.3   SSAM: 2.0

  Listen:   :50051 (mTLS: true)
  Log:      json (info) -> stderr
  Plugins:  17 loaded
    {heartbeat} v1.0.0 �� Agent heartbeat tracking
    {spc} v1.0.0 �� Security Posture Calculator
    {cti} v1.0.0 �� Cyber Threat Intelligence
    {assessor} v1.0.0 �� SSAM security assessment engine
    {policy} v1.0.0 �� Policy enforcement and compliance
    {commander} v1.0.0 �� Agent command dispatch
    {log_collector} v1.0.0 �� Agent log collection
    {persistence} v1.0.0 �� Data persistence layer
    {concurrency} v1.0.0 �� Concurrency control
    {attck} v1.0.0 �� MITRE ATT&CK V19 threat analysis
    {config_watcher} v1.0.0 �� Configuration hot-reload
    {adapter_integration} v1.0.0 �� External adapter integration
    {source_manager} v1.0.0 �� External source management
    {cli} v1.0.0 �� Command-line interface
```

---

## 5. Agent ����

### 5.1 �����в���

```
ASSCOR-agent [ѡ��]
```

| ���� | Ĭ��ֵ | ˵�� |
|------|--------|------|
| `--config` | `agent.ini` | Agent �����ļ�·�� |
| `--kernel` | `127.0.0.1:50051` | Kernel ��ַ��host:port�� |
| `--host-id` | ������ | Agent ������ʶ�� |
| `--tls` | `false` | ���� mTLS ���� |
| `--tls-skip-verify` | `false` | ���� TLS ֤����֤��**���޿�������**�� |
| `--cert-dir` | `certs` | TLS ֤��Ŀ¼ |
| `--install` | �� | ��װΪ systemd ������ root�� |
| `--uninstall` | �� | ж�� systemd ������ root�� |
| `--upgrade` | �� | ԭ���������� root�� |
| `--version` | �� | ��ʾ�汾���˳� |
| `--log-format` | `json` | ��־��ʽ |
| `--log-level` | `info` | ��־���� |
| `--log-output` | `stderr` | ��־��� |

### 5.2 ����ʾ��

```bash
# ������װ��systemd��
sudo ./ASSCOR-agent-linux --install
sudo systemctl start asscor-agent

# �ֶ����У�����Զ�� Kernel��mTLS��
./ASSCOR-agent-linux --kernel=192.168.1.10:50051 --tls --cert-dir=/etc/asscor/certs

# ָ������ ID
./ASSCOR-agent-linux --kernel=10.0.0.5:50051 --tls --host-id=web-server-01

# ����ģʽ
./ASSCOR-agent-linux --kernel=localhost:50051 --tls-skip-verify --log-level=debug
```

> Agent �� root ������ִ��ϵͳ����飨��ȡ `/etc/shadow`��`iptables` �ȣ����� root ����ʱ��Ҫ root Ȩ�޵ļ�����Զ���������ǡ�

### 5.3 Agent �����ļ�

Agent ֧�ֶ����� INI �����ļ���Ĭ�� `agent.ini`������ʽ���£�

```ini
[agent]
kernel_addr = 192.168.1.10:50051
host_id = web-server-01
tls_enabled = true
cert_dir = /etc/ASSCOR/certs

[logging]
format = json
level = info
output = /var/log/ASSCOR-agent.log
```

�����в������ȼ����������ļ���

---

## 6. TLS ֤�����

ASSCOR ʹ�� mTLS��˫�� TLS������ Kernel �� Agent ���ͨ�Ű�ȫ��

### 6.1 �Զ�֤������

�״����ʱ��Kernel �Զ���֤��Ŀ¼���������ļ���

```
certs/
������ ca.crt        # CA ֤��
������ ca.key        # CA ˽Կ
������ server.crt    # Kernel �����֤��
������ server.key    # Kernel �����˽Կ
������ agent.crt     # Agent �ͻ���֤��
������ agent.key     # Agent �ͻ���˽Կ
```

### 6.2 ֤�����

```bash
# ��֤֤����һ����
./ASSCOR-kernel-linux --verify-certs --cert-dir=/etc/asscor/certs

# ǿ��������������֤�飨��֤�齫��ɾ����
./ASSCOR-kernel-linux --force-regen-certs --cert-dir=/etc/asscor/certs
```

### 6.3 ֤��ַ�

�� `ca.crt`��`agent.crt`��`agent.key` �ַ���ÿ̨ Agent ������֤��Ŀ¼��

> **��ȫ��ʾ**��˽Կ�ļ���`.key`��Ȩ��Ӧ��Ϊ 0600������ root �û���ȡ��

---

## 7. �����ļ����

�����ļ����� INI ��ʽ��Ĭ��·�� `config.ini`��

### 7.1 Ȩ������

```ini
[weights]
attack_surface = 35        # ���������Ȩ��
business_continuity = 25   # ҵ��������Ȩ��
operation_trust = 25       # �������Ŷ�Ȩ��
resilience = 15            # ����Ȩ��
```

> ����Ȩ���ܺͱ���Ϊ 100��

### 7.2 �ɽ�������ֵ

```ini
[acceptability]
threshold = 80.0                       # SSAM ������ֵ
compliance_framework = GB/T 22239-2019 Level 3  # �Ϲ���
```

��ֵ��ȱ��ȼ�������

| �ȱ��ȼ� | SSAM ��ֵ |
|----------|-----------|
| ���� | �� 65 |
| ������Ĭ�ϣ� | �� 80 |
| �ļ� | �� 90 |

### 7.3 ��Ե����

```ini
[edge_factors]
two_factor_failure = 0.85    # ˫������֤ȱʧʱ����

[edge_factors.level4_override]
two_factor_failure = 0.70    # �ȱ��ļ���������֤ȱʧʱ����
```

��Ե���ӽ��ڶ�Ӧ��������ʱ�������ˣ�ȡֵ��Χ (0, 1)��

### 7.4 ��в����

```ini
[threat]
coefficient = 1.0     # ��вϵ�� �̣�Ĭ�� 1.0���� CTI ģ�鶯̬������
spc_enabled = true    # �Ƿ����� SPC ����
```

### 7.5 ����� Delta ֵ

```ini
[check_deltas]
AS-001 = -8      # ����������
OT-001 = -10     # �������Ŷȼ����
RS-001 = -10     # ���Լ����
BC-005 = -10     # ҵ�������Լ����
AC-001 = -15     # �ȱ��ļ���ǿ�����
EF-001 = 0       # ��Ե���Ӽ����
```

Delta ֵΪ������ʾ���δͨ��ʱ�Ŀ۷֣�������ʾ�����ӷ֡�ÿ������� ID ��ѭ `XX-NNN` �����ϵ��

- `AS`�������棨Attack Surface��
- `OT`���������Ŷȣ�Operation Trust��
- `RS`�����ԣ�Resilience��
- `BC`��ҵ�������ԣ�Business Continuity��
- `AC`���ȱ��ļ���ǿ��Additional Control��
- `EF`����Ե���ӣ�Edge Factor��
- `KS`���ں˰�ȫ��չ��Kernel Security��

### 7.6 ��չ����

```ini
[extensions]
kernel_security = on        # �����ں˰�ȫ��չ��

[extension_weights]
kernel_security = 10        # �ں˰�ȫ��չȨ��
```

---

## 8. SPC ��ȫ̬��ģ��

SPC ģ��ͨ�� NVD/EPSS/CISA KEV/CNNVD/CNVD ���ⲿ©������Դ�뱾���ʲ��ȶԣ�������廯�������� P_score��0.60�C1.00����

> ?? **����������������֪�����ԣ�**��SPC ����֤�߼����� CPE �ַ���ƥ�䡪�����Ѱ�װ���������/�汾�� CVE ���ݿ��е���Ӱ���Ʒ�汾���н���ȶԡ���**��ִ��**©��������֤������ʱ�ɴ��Է����������Ʒ���������������ʩ��֤��ƥ�������ܲ��������ԣ���ͨ�� WAF/���ⲹ�����⵫δ���°汾�ŵ�©�����ͼ����ԣ��汾��ƥ�䵫���ڶ��Ʊ��֣���SPC ��λΪ"©���鱨�ۺ���汾�ȶ�����"������"©��������֤��"��Ŀǰ���޼ƻ����������֤������

### 8.1 ��������

```ini
[spc]
enabled = true              # �Ƿ�����
min_pscore = 0.60           # P_score ����
cache_retention_days = 365  # CVE ���汣������
fetch_interval_h = 1        # �Զ�ˢ�¼���Сʱ��
```

### 8.2 NVD ����Դ

```ini
[spc.nvd]
base_url = https://services.nvd.nist.gov/rest/json/cves/2.0
api_key =                   # �����ӻ������� NVD_API_KEY ��ȡ
sync_interval_h = 6         # ͬ�����
use_last_mod = true         # ����ͬ��ģʽ
no_rejected = true          # �����Ѿܾ��� CVE
```

**API Key ˵��**��

- �� Key�������������� 5 ��/30�룬ϵͳ�Զ����� 4 ������Ƭ����
- �� Key�������������� 50 ��/30�룬ϵͳ�Զ����� 2 ������Ƭ����
- ��ȡ��ַ��https://nvd.nist.gov/developers/request-an-api-key

### 8.3 EPSS ����Դ

```ini
[spc.epss]
enabled = true
data_url = https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
sync_interval_h = 24
```

### 8.4 CISA KEV ����Դ

```ini
[spc.cisa_kev]
enabled = true
catalog_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
sync_interval_h = 24
```

### 8.5 CNNVD ����Դ

```ini
[spc.cnnvd]
enabled = false
base_url = https://www.cnnvd.org.cn/home/data
api_key =                   # �����ӻ������� CNNVD_API_KEY ��ȡ
sync_interval_h = 24
```

### 8.6 CNVD ����Դ

```ini
[spc.cnvd]
enabled = false
base_url = https://www.cnvd.org.cn/shareData
sync_interval_h = 24
```

### 8.7 MISP ����Դ

```ini
[spc.misp]
base_url =                  # MISP ��������ַ
api_key =                   # �����ӻ������� MISP_API_KEY ��ȡ
verify_tls = true
sync_interval_h = 1
tlp_filter = white          # TLP ��ǩ����
```

### 8.8 OSCAL ����

```ini
[spc.oscal]
enabled = false
input_format = json         # json / yaml / xml
results_path = ./oscal_results/
plan_path = ./oscal_plan/
```

### 8.9 CPE ƥ�����

Agent �Զ����Ѱ�װ�����ת��Ϊ CPE 2.3 ��ʽ��`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`����SPC ģ�鰴�������ȼ�ƥ�䣺

1. **��ȷ�汾ƥ��**��MatchExactVersion����vendor��product��version ��ȫһ��
2. **�汾��Χƥ��**��MatchVersionRange����vendor��product һ�£�version ����Ӱ�췶Χ��
3. **��Ʒƥ��**��MatchProduct����vendor��product һ�£��ް汾��Ϣ
4. **����ƥ��**��MatchVendor������ vendor һ��
5. **����ƥ��**��MatchDescription�������������� CVE ������

---

## 9. �ȱ�ӳ����������ֵ

### 9.1 ������

| �ȱ��ȼ� | �Զ���������� |
|----------|----------------|
| ���� | 53 �� |
| �ļ� | 53 + 9 = 62 �� |

### 9.2 ����������ֲ�

| ������ | �����ǰ׺ | ������������ |
|--------|------------|--------------|
| ��������� | AS-001 ~ AS-017 | 17 |
| �������Ŷ� | OT-001 ~ OT-022 | 22 |
| ���� | RS-001 ~ RS-012 | 12 |
| ҵ�������� | BC-005 ~ BC-007 | 3 |
| �ȱ��ļ���ǿ | AC-001 ~ AC-008 | 8�����ļ��� |
| ��Ե���� | EF-001 ~ EF-002 | 2 |

### 9.3 ������ֵ����

�޸� `[acceptability] threshold` ֵ�����л��ȱ��ȼ���Ӧ����ֵ��

```ini
# �ȱ�����
threshold = 65.0

# �ȱ�������Ĭ�ϣ�
threshold = 80.0

# �ȱ��ļ�
threshold = 90.0
```

---

## 10. ATT&CK V19 ��в����ģ��

ASSCOR v0.2.3 ���� MITRE ATT&CK V19 ��ܣ���Ϊ ��Kernel �����`attck`�����ȼ� 21���汾 1.0.0�����С�ģ���ṩ�Ӽ�⡢�鱨�����浽������������в���������������ڴ˻�������չ APT ��������������ǿ��ģ�顣

### 10.1 �Ĵ������ģ��

| ��ģ�� | �������� |
|--------|----------|
| **��������** | ���������棨ע��/����/ɾ�������쳣�¼���¼���ѯ���澯�������������ժҪͳ�� |
| **��в�鱨** | IOC �������ɾ����/�������������в��Ϊ�廭��TTP ׷�١��澯�鱨���� |
| **���ַ�������** | ���泡��������� APT ��֯�Զ����ɳ�������ȫģʽ����ִ�С���������¼ |
| **�����빤��** | �����������������ʣ�����ȫ����ӳ�䡢���⽨�����ɡ������Ľ�׷�� |

### 10.2 APT ��������������ǿ

���Ĵ���ģ������ϣ�APT ��ǿ���ṩ�߼���в����������

| ���� | ���� |
|------|------|
| **�������ع�** | ���ڸ澯���쳣��IOC ��Դ֤�ݣ��� ATT&CK ս��˳���Զ��ع���׶ι����� |
| **��Ϊ���** | ��Ϊָ��ע����������������Ϊ���߹����C2 �ű��⣨������������ |
| **APT ��������** | ��Դ֤���ںϣ�TTP �ص� 60% + IOC ƥ�� 40%����APT ��֯ƥ�����Ŷ����� |
| **��в���Կ��** | ���Լ��� CRUD�����ڹ���ת�ƾ����Զ����ɼ��衢����ִ����ȷ�� |

### 10.3 �� SSAM ������ϵ��Эͬ

ATT&CK ģ���� SSAM ������ϵ�γ�˫����ǿ�ջ���

- **��������ǿ**��APT �����������ͨ���¼�����ע����Թ�������Ӱ��������ȫ״̬�ж�
- **SPC ����**��APT ���������������в��Ϊ����Ϣ���� SPC ©���鱨������֤����̬���� P_score
- **CTI Эͬ**��CTI ģ�����вϵ�� �� �� ATT&CK ��в�鱨��ģ�鹲������Դ
- **��������**��APT ���澯�������Թ������Զ���Ӧ����

### 10.4 ATT&CK ����

```ini
[attck]
enabled = true                  # �Ƿ����� ATT&CK ģ��
version = v19                   # ATT&CK ��ܰ汾
auto_hunt = false               # �Ƿ��Զ��������Լ���
beacon_threshold = 0.7          # �ű���������ֵ
attribution_threshold = 0.6     # APT �������Ŷ���ֵ
safe_emulation = true           # �����Ƿ�Ĭ�ϰ�ȫģʽ
```

### 10.5 CLI ����

ͨ�� Kernel ����ʽ CLI �ɲ��� ATT&CK ģ�飺

```
# �鿴���ժҪ
ASSCOR> attck summary

# ע�������
ASSCOR> attck rule add --name "suspicious_powershell" --technique T1059 --severity high

# �鿴 IOC �б�
ASSCOR> attck ioc list --type ip

# ִ�в�����
ASSCOR> attck gap --host=web-server-01

# �ع�������
ASSCOR> attck chain --host=web-server-01

# ִ�� APT ����
ASSCOR> attck attribute --chain=<chainID>

# �������Լ���
ASSCOR> attck hunt generate --host=web-server-01

# ִ�ж��ַ���
ASSCOR> attck emulate --scenario=<scenarioID> --host=web-server-01 --safe
```

---

## 11. ��־����

### 11.1 ��־����

```bash
# JSON ��ʽ��Ĭ�ϣ��ʺ���־�ɼ�ϵͳ��
-log-format json -log-level info -log-output /var/log/ASSCOR-kernel.log

# �ı���ʽ���ʺ��˹��Ķ���
-log-format text -log-level debug -log-output stderr
```

### 11.2 ��־����

| ���� | ��; |
|------|------|
| `debug` | ��ϸ������Ϣ����������/��Ӧϸ�� |
| `info` | ����������Ϣ���Ƽ����������� |
| `warn` | ������Ϣ��������ȱʧ���������� |
| `error` | ������Ϣ����Ҫ��ע���� |

### 11.3 ��־���ǰ׺

ÿ����־�������ǰ׺�����ڹ��ˣ�

```
{"time":"...","level":"info","component":"spc","msg":"CVE cache loaded","count":1234}
{"time":"...","level":"warn","component":"kernel","msg":"NVD API key not configured"}
```

�������ǰ׺��`kernel`��`spc`��`cti`��`assessor`��`policy`��`commander`��`heartbeat`��`cli`��`tls`

---

## 12. �ػ�����ģʽ

```bash
# ����ػ�����
./ASSCOR-kernel-linux --daemon --pid-file=/var/run/ASSCOR-kernel.pid

# ֹͣ�ػ�����
kill $(cat /var/run/ASSCOR-kernel.pid)
```

�ػ�����ģʽ�£���־�Զ��ض��� `ASSCOR-kernel.log`��

---

## 13. ��������ģʽ

`ASSCOR` �����ṩ�����������������貿�� Kernel �� Agent����ʱ������նˣ�

```bash
# �ı����棨ֱ�Ӵ�ӡ���նˣ�
./ASSCOR-linux --config=/etc/asscor/config.ini

# JSON ���棨���ض����ļ���
./ASSCOR-linux --config=/etc/asscor/config.ini -json > report.json
```

| ���� | Ĭ��ֵ | ˵�� |
|------|--------|------|
| `--config` | `config.ini` | �����ļ�·�� |
| `--json` | `false` | �� JSON ��ʽ��� |

����ģʽ������������

- **���ļ��**��80 ��ذ�ȫ��飨�� KS �ں˰�ȫ��
- **SPC ̬�Ƽ���**��������������Դ���Զ���ȡ NVD/EPSS/KEV ������
- **ATT&CK ����**�����Ƕȡ�Kill Chain��APT ���򡢷���Ԥ��
- **�ⲿ����������**��config.ini `[adapters]` �����õĹ��ߣ�Trivy/Lynis/Suricata/ClamAV/AIDE �ȣ��Զ�ִ�в����������ɵ���Ӧ�����
- **SRD/Prism �������**��Core����̬���֣��� Semantic��ģ��״̬���� Inference������Ԥ�⣩

> **����λ��˵��**������ģʽ�ı���**��������ն�/stdout**����д����̡�����־û���ʷ���棬��ʹ�� Kernel + Agent ģʽ�������Զ�д�� `/var/lib/asscor/`���� ��4.2����

### 13.1 ����λ�ö���

| ģʽ | ����λ�� |
|------|----------|
| ���� `ASSCOR` | �ն� stdout��`-json > file` �ɱ��棩 |
| Kernel ����ģʽ | `/var/lib/asscor/latest-assessment.json`�����£�<br>`/var/lib/asscor/assessments-<date>.jsonl`����ʷ��<br>WebUI `http://<host>:8087` |

---

## 14. ���������ο�

| �������� | ��; | ���ȼ� |
|----------|------|--------|
| `NVD_API_KEY` | NVD API ��Կ | ���� config.ini �е� `api_key` |
| `MISP_API_KEY` | MISP API ��Կ | ���� config.ini �е� `api_key` |
| `CNNVD_API_KEY` | CNNVD API ��Կ | ���� config.ini �е� `api_key` |

> **��ȫ��ʾ**��API Key Ӧͨ�������������ݣ���ֹӲ���뵽�����ļ��������в����С�

---

## 15. �����Ų�

### 15.1 Kernel ���ʧ��

| ֢״ | ����ԭ�� | ������� |
|------|----------|----------|
| `FATAL: kernel bootstrap failed` | �����ʼ��ʧ�� | �����־�����ȷ�������ļ���ʽ��ȷ |
| `WARN: server start failed` | �˿ڱ�ռ�� | ���� `-listen` ��ַ���ͷŶ˿� |
| ֤����� | ֤���ļ��𻵻�ƥ�� | ʹ�� `-force-regen-certs` �������� |

### 15.2 Agent ����ʧ��

| ֢״ | ����ԭ�� | ������� |
|------|----------|----------|
| `connection refused` | Kernel δ������ַ���� | ȷ�� Kernel ��ַ�Ͷ˿� |
| `certificate verify failed` | ֤�鲻ƥ�� | ���·ַ�֤�飬ȷ�� `cert_dir` ·�� |
| `agent: fatal` | ���ô��� | ʹ�� `-log-level debug` �鿴��ϸ���� |

### 15.3 SPC ����ͬ������

| ֢״ | ����ԭ�� | ������� |
|------|----------|----------|
| `CVE cache is empty` | �״�ͬ��δ��� | �ȴ���̨ͬ����ɣ�Լ 1�C5 ���ӣ� |
| `NVD API rate limited` | �� API Key �������Ƶ | ���� `NVD_API_KEY` �������� |
| `SPC cannot calculate risk` | ����Ϊ�� | ����������ӣ�ȷ������Դ�ɷ��� |

### 15.4 �����쳣

| ֢״ | ����ԭ�� | ������� |
|------|----------|----------|
| ����ʼ��Ϊ 100 | ���м����ͨ�� | �������󣬱�ʾϵͳ��ȫ״̬���� |
| �����쳣ƫ�� | ����� Delta ֵ���� | ��� `[check_deltas]` �����Ƿ���� |
| P_score Ϊ 0.60 | ���ڸ�Σ CVE ƥ�� | ʹ�� `spc cve` ����鿴ƥ��� CVE ���� |

---

## 16. CLI ����ο�

### 16.1 CLI ����

ASSCOR Kernel ���ý���ʽ CLI �նˣ�Kernel ������Զ����롣CLI �ṩ����ע�ᡢ�Զ���ȫ����ʷ��¼�Ͳ����չ������

**���� CLI**��Kernel �������־�Զ��ض��� `ASSCOR-kernel.log`���ն˽��뽻��ģʽ��

```
ASSCOR ��Kernel
  Framework: v0.2.3   SSAM: 2.0
  Listen:   :50051 (mTLS: true)
  CLI active: logs redirected to ASSCOR-kernel.log

ASSCOR>
```

**�����﷨**��`command <subcommand|param> [options]`��ѡ��ʹ�� `--name=value` �� `--name value` ��ʽ������ѡ��ʹ�� `--flag` ��������� `Ctrl+D` �� `Ctrl+C` �˳���

### 16.2 ͨ��ѡ��

| ѡ�� | ��ѡ�� | ˵�� |
|------|--------|------|
| `--verbose` | `-v` | ��ʾ��ϸ��� |
| `--json` | `-j` | �� JSON ��ʽ��� |
| `--quiet` | `-q` | ���ƷǱ�Ҫ��� |
| `--help` | `-h` | ��ʾ������� |

### 16.3 ��������

**help** �� ��ʾ����������г����п������`help [command]`

**version** �� ��ʾ ASSCOR ��ܰ汾�� SSAM ģ�Ͱ汾��`version`

**status** �� ��ʾ��ǰ Kernel ״̬���������״̬������ʱ�����Դʹ�ã�`status [--format=json]`

### 16.4 ��������

**assess** �� ������ָ�������İ�ȫ�ɽ�����������

```
�÷���assess [host] [options]
������host �� Ŀ������ ID��Ĭ�� local��
ѡ�--format=json, --domain=attack_surface|business_continuity|operation_trust|resilience
```

### 16.5 SPC ����

**spc** �� ��ѯ SPC ģ��� CVE ���桢P-score��KEV �������������ݡ�

```
�÷���spc <summary|cve|kev|score|fetch> [options]
ѡ�--limit=N��Ĭ��20��, --cvss-min=N, --kev-only, --host=HOST
ʾ����
  ASSCOR> spc summary
  ASSCOR> spc cve --cvss-min=9.0 --kev-only
  ASSCOR> spc score --host=web-server-01
  ASSCOR> spc fetch
```

### 16.6 Agent ��������

**agent** �� ������ע��� Agent��

```
�÷���agent <list|status|start|stop|restart|config|command> [options]
ѡ�--host=HOST, --all, --filter=key=value, --limit=N��Ĭ��50��, --watch
ʾ����
  ASSCOR> agent list --filter=active=true
  ASSCOR> agent status --host=web-server-01
  ASSCOR> agent stop --host=db-master-01
  ASSCOR> agent command --host=web-01 --action=scan
```

**log** �� �鿴�����˺͵��� Agent ������־��

```
�÷���log <show|export> [options]
ѡ�--host=HOST, --level=debug|info|warn|error, --limit=N��Ĭ��50��, --format=json|csv, --output=PATH
```

### 16.7 ATT&CK ����

**attck** �� ��ѯ MITRE ATT&CK V19 ģ��ķ�������������ʡ�ɱ������APT ƥ�䡢��������в�鱨��

```
�÷���attck <summary|coverage|killchain|apt|detect|ti>
ѡ�--host=HOST, --limit=N��Ĭ��20��, --json
```

���������

```
ASSCOR> attck summary                                      # ģ�������������/�澯/IOC �ȹؼ�ָ��
ASSCOR> attck coverage --host=web01                         # 14 ս����⸲����
ASSCOR> attck killchain --host=web01                        # 9 �׶�ɱ��������
ASSCOR> attck apt --host=web01                              # APT ��֯ƥ����
ASSCOR> attck detect                                        # ������͸澯ժҪ
ASSCOR> attck ti                                            # ��в�鱨��IOC/��Ϊ�壩ժҪ
```

### 16.8 �������

**diag** �� ��ʾ�ں�����ʱ�����Ϣ���¼�����ָ�ꡢWorker Pool ״̬����

```
�÷���diag [--json]
ʾ����
  ASSCOR> diag              # �ն˸�ʽ���
  ASSCOR> diag --json       # JSON ��ʽ���
```

### 16.9 ��������

**policy** �� �鿴��ǰ�������ú�״̬���ա�

```
�÷���policy
˵������ʾ������ֵ����ǰ����״̬�ֲ���������Զ�����¼
```

### 16.10 �����������

**plugin** �� �г����鿴�͹��� Kernel �����

```
�÷���plugin <list|info|health> [name]
ʾ����
  ASSCOR> plugin list
  ASSCOR> plugin info spc
  ASSCOR> plugin health
```

### 16.9 �ⲿԴ��������

**source** �� �������á���ͣ������ⲿ����Դ��

```
�÷���source <list|info|deploy|enable|disable|update|uninstall|run|config|audit> [name] [options]
ѡ�--category=scanner|management, --version=VERSION, --force, --limit=N��Ĭ��50��
```

### 16.10 ϵͳ����

**config** �� �鿴��ǰ Kernel ���ã�`config [key] [--format=json]`

**health** �� ������ Kernel ���ִ�н�����飺`health [--json]`

### 16.11 ��������

**history** �� �鿴����ִ����ʷ��¼��`history [count] [--failed] [--clear]`

### 16.12 ����ʽ�ն˹���

- **�Զ���ȫ**����������� `Tab` ���������������������ѡ����ɲ�ȫ��
- **������ʷ**��ʹ�� `��`/`��` ��ͷ�������ʷ����
- **�ű�����**����������֧�� `--json` ѡ������ṹ�� JSON��`echo "spc summary --json" | asscor-cli`
- **�˳���**��0=�ɹ���1=ִ�д���2=�÷�����130=�û�ȡ��

### 16.13 ���ע���Զ�������

```go
cliPlugin, ok := k.Container().Resolve((*cli.CLIInterface)(nil))
if ok {
    cliMod := cliPlugin.(cli.CLIInterface)
    cliMod.RegisterCommand(cli.NewBaseCommand(
        cli.CommandInfo{
            Name: "mycmd", Short: "My custom command",
            Usage: "mycmd [args]", Category: cli.CategoryPlugin,
        },
        func(ctx *cli.CommandContext) *cli.CommandResult {
            return &cli.CommandResult{ExitCode: cli.ExitOK, Output: "Custom command executed\n"}
        },
    ))
}

---

## 15. �Զ�����չ�������д Go ���룩

ASSCOR ֧�����������д Go �������չ��ʽ�������ż���רҵ�����𼶵ݽ���

### 15.1 �����ļ��������� (`[user_check]`)

�� `config.ini` ��ֱ����Ӱ�ȫ��飬�����κα�̣�

```ini
# �����飺ִ�� shell ���exit 0 �����ƥ���ַ��� = ͨ��
[user_check.nginx]
id = CU-001
domain = attack_surface
name = Nginx service status
description = Check if nginx is running
command = systemctl is-active nginx
delta = -8
output_match = active

# �ļ����ݼ�飺����ļ��Ƿ���ڡ������Ƿ�ƥ������
[user_check.auditd]
id = CU-002
domain = operation_trust
name = Auditd rules
description = Verify auditd has shadow watch rules
file_path = /etc/audit/audit.rules
file_regex = -w /etc/shadow -p wa
delta = -10
```

֧�ֵ��ֶΣ�

| �ֶ� | ���� | ˵�� |
|------|------|------|
| `id` | ? | Ψһ��� ID���� `CU-001` |
| `domain` | ? | ������attack_surface / business_continuity / operation_trust / resilience / kernel_security�� |
| `name` | ? | ������� |
| `command` | * | shell ���exit 0 = ͨ���� |
| `output_match` | �� | ����г��ִ��ַ��� = ͨ�� |
| `file_path` | * | Ҫ�����ļ�·�� |
| `file_regex` | �� | �ļ�����ƥ������� = ͨ�� |
| `delta` | �� | ʧ�ܿ۷֣�Ĭ�� -10�� |

> *: `command` �� `file_path` �����ṩһ�����޸ĺ�ִ�� `systemctl reload asscor-kernel` ������Ч��

### 15.2 �ⲿ�ű������� (`[adapter_script]`)

�����κ����Ա�д�Ľű���Bash/Python/�κΣ����� JSON stdout �Զ���Ϊ���������֣�

```ini
[adapter_script.my-monitor]
path = /opt/asscor/scripts/my-monitor.sh
```

�ű� stdout ��ʽ��JSON ���飩��

```json
[
  {
    "id": "MON-001",
    "title": "Disk usage warning",
    "severity": "high",
    "detail": "/dev/sda1 is 95% full",
    "domain": "business_continuity",
    "finding_type": "alert"
  }
]
```

**��ȫ����**:
- �ű�·�������� `/opt/asscor/scripts/` `/etc/asscor/scripts/` `/var/lib/asscor/scripts/`
- �ű����� root:root �ҷ� world-writable
- �ܾ���������
- 30 ��ִ�г�ʱ
- 1MB �������

### 15.3 Plugin SDK������ Go ģ�飬רҵ������

`pluginsdk/` �ṩ���� Go ģ��ģ�壬���ͨ�� JSON-RPC (stdin/stdout) ���ں�ͨ�ţ�**�� ASSCOR Դ������**��

```
pluginsdk/
������ go.mod           # ����ģ�鶨��
������ sdk.go           # Plugin �ӿ� + JSON-RPC ѭ��
������ cmd/myplugin/    # ����ʾ�����
��   ������ main.go
��   ������ extension.json
������ README.md
```

�������̣�����ģ�� �� ʵ�� `HandleRequest()` �� `go build` �� `asscor> source deploy`��

---

## 16. �㷨�������� (`[integrity]`)

���� ASSCOR �� SSAM/Prism �����㷨�������Ա�����

```ini
[integrity]
sign_assessment = true    # �������� HMAC-SHA256 ǩ������α�챨�棩
verify_algo = true        # ���ʱУ�� SSAM/Prism ����������
anti_debug = false        # Linux �����Լ�⣨����ʽ�����
```

| ģʽ | ���� |
|------|------|
| `sign=false, verify=false` | ���������������� |
| `sign=true, verify=true` | ������������α�� + �㷨У�飨�Ƽ��� |
| `anti_debug=true` | ��л������ӷ����� |

---

## �汾��ʷ

| �汾 | ���� | ��Ҫ��� |
|------|------|----------|
| v0.2.3 | 2026-08-12 | ����ծ���峥80��(87��7, 92%): P0ȫ����(19/19)���ں�17�ӿ�/�����ļ���֡�25�����ļ�/222����/5Benchmark�����湳�Ӂ6�2��չ���Ž�(8�׶�)��SemVerͳһ��extmgr�Ž�(9����)��������������λ��ATT&CK build-tag���롢10+nil-guard�޸���TLS���ء�ϵͳd���ء�pkgmgr�ںϡ����㷨���ſ�ѡ������չ��������ϵ(package.json+pkgmgr+SCHEMA) |
| v0.2.1 | 2026-07-17 | ��չ��ϵ65��չ��ȫ�������ڸ���(̽�����Ӧ��������޸�����֤���鵵)��isPermDeniedȨ�޼����ǿ(EACCES/EPERM/����)��CLI�ն�-�ﾳ�˳�+done�ź�+goDecoder�޸���CLI��־�ָ�������+socketȨ���ս�0660������ģ���ع�(helpers��ȡ/��������/systemdͬ��+waitForServiceHealthy)��verify.status_changed����չ�㼤�asscor-cli͸��ASSCOR_CLI_SOCKET�����㷨���ſ�ѡģ��(multi-algo-orchestrator, extension-point��������)����չ��������(pkgmgr, package.json��������, git�ⲿ�ֿ�����)��optional/�ⲿ��չĿ¼(algorithms/adapters/checks/platform) |
| v0.2.0 | 2026-07-07 | �������ư�װ(--install/--uninstall/--upgrade/--version)��FHS����(/etc/asscor,/var/lib/asscor,/var/log/asscor)��systemctl�ܿ�+SIGHUP�����أ�Զ��CLI(Unix socket, asscor-cli)��PATH��������(/usr/bin/asscor)������ģʽ֧������������+SRD���������SSAM V2��Ȩƽ�����֣�persistence·���޸���agent����Ƶ���Ż���config��������([user_check])���ⲿ�ű�������([adapter_script])��Plugin SDK(pluginsdk/)���㷨��������([integrity])��CLI diag/policy��ά���� |
| v0.2.0 | 2026-06-28 | CLI spc������(score/kev/fetch)ʵ�֣�kernel����̨��������(config.ini console_report)��agent��־��ʽ������(agent.ini log_format)��source deploy���ATT&CK�汾/���ȼ�������config������Ĭ�Ͽ��������������Parse������ϵͳd service + Dockerfile |
| v0.1.4-mvp | 2026-06-09 | SSAM V2.0��������ģ�ͣ�ATT&CK V19ģ�飻SPC������Դ(CNNVD/CNVD/MISP)����չ��������Prism SRD���� |
| v0.1.3-mvp | 2026-05-25 | gRPC/JSONRPC˫Э��ջ��Ȩ���ȼ��أ�SPC���̳־û�������������ģ�� |
| v0.1.2 | 2026-05-22 | HMACǩ���޸����ؼ���ϢPublishSync�����Թ���������switch��CTI���ؼ����Ȩ |
| v0.1.1 | 2026-05-16 | Agent�������ƣ��������ͳһbuild/Ŀ¼ |
| v0.1.0 | 2026-05-13 | ��ʼ���� |
```
