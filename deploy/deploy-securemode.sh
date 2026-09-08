#!/usr/bin/env bash
# =============================================================================
# deploy-securemode.sh — Secure Mode 集群一键部署 / 巡检 / 清理
#
# 背景：本脚本固化 Secure Mode 集群测试（A-1 18 节点模拟 / WSL2 Containerlab
# 14 节点真实拓扑）中验证过的部署流程，并把测试暴露的工程坑写成显式步骤：
#   * 证书签发 / 分发（CA 从 kernel 自动生成的目录导出，每 agent 独立证书）
#   * agent.ini 生成（[bootstrap] 明文引导段 + [agent] 受保护段；写入后回读
#     校验，杜绝 heredoc 转义导致的"写入静默失败 → agent 用默认 host_id"）
#   * 身份清理（`cert reset` 清 host↔证书指纹绑定，CA/证书轮换后让 agent
#     用新证书重新注册；对应 audit §3 证书身份冲突残留）
#   * OSPF redistribute connected（clab 扩展子网注入，host13/14 类节点可达）
#   * 资源边界（ssh 后端并发 ≤ AGENT_LIMIT，防压垮 sshd）
#
# 三个 executor（后端）统一子命令：
#   clab  —— containerlab 真实容器拓扑（docker exec/cp），默认
#   ssh   —— 远程多进程模拟（如 A-1：kernel + N×agent 进程）
#   local —— 本机多进程模拟（同一台 Linux 上跑 kernel + N×agent，开发用）
#
# 用法：
#   deploy/deploy-securemode.sh build [--executor=...] [--out=...]
#   deploy/deploy-securemode.sh deploy-kernel [--executor=...] [--kernel-host=...] [--listen=...]
#   deploy/deploy-securemode.sh deploy-agent  [--executor=...] [--agents="a b c"] [--start=N]
#   deploy/deploy-securemode.sh reset-identity [--executor=...]
#   deploy/deploy-securemode.sh verify [--executor=...] [--agents="a b c"]
#   deploy/deploy-securemode.sh ospf [--executor=clab] [--router=r2]
#
# 环境变量（全部可选，均有默认）：
#   KERNEL_BIN / AGENT_BIN  已构建二进制路径（缺省走 build 输出目录）
#   CA_DIR                  证书工作目录（缺省 /tmp/asscor-ca）
#   DIST_DIR                构建输出目录（缺省 ./build）
#   KERNEL_ADDR             agent 连接的 kernel 地址 host:port
#   REMOTE_USER / REMOTE_HOST   ssh 后端目标
#   DATA_DIR / CONFIG_DIR   远端安装路径（默认 /var/lib/asscor 与 /etc/asscor）
#
# 提示：build 子命令在部署机执行 go build，需该机已有 Go 模块缓存或可达
#   GOPROXY（离线机可设 GOPROXY=https://goproxy.cn,direct 或先在有网机预取）。
#   Go 构建相关环境变量（GOPROXY/GOFLAGS 等）原样透传。
# =============================================================================
set -euo pipefail

# --- 解析公共参数 -------------------------------------------------------------
EXECUTOR="${EXECUTOR:-clab}"
OUT_BIN="${DIST_DIR:-build}"
CA_DIR="${CA_DIR:-/tmp/asscor-ca}"
KERNEL_ADDR="${KERNEL_ADDR:-10.10.0.10:50051}"
REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-}"
DATA_DIR="${DATA_DIR:-/var/lib/asscor}"
CONFIG_DIR="${CONFIG_DIR:-/etc/asscor}"
CERT_DIR="${CERT_DIR:-$CONFIG_DIR/certs}"
AGENT_LIMIT="${AGENT_LIMIT:-12}"     # ssh 后端并发 agent 上限（A-1 2 核 3.4GB 实测 ~14）
CERT_RESET="${CERT_RESET:-1}"        # reset-identity 是否调用 cert reset（1=用，0=仅提示）

for arg in "$@"; do
  case "$arg" in
    --executor=*) EXECUTOR="${arg#*=}" ;;
    --kernel-host=*) KERNEL_HOST="${arg#*=}" ;;
    --agents=*) AGENTS="${arg#*=}" ;;
    --start=*) START_IDX="${arg#*=}" ;;
    --out=*) OUT_BIN="${arg#*=}" ;;
    --listen=*) LISTEN_ADDR="${arg#*=}" ;;
    --router=*) ROUTER="${arg#*=}" ;;
  esac
done

KERNEL_HOST="${KERNEL_HOST:-${REMOTE_HOST:-edge0}}" # clab: 容器名; ssh: 远程主机; local: 忽略
AGENTS="${AGENTS:-}"                                 # 空格分隔的 agent 标识
START_IDX="${START_IDX:-1}"
LISTEN_ADDR="${LISTEN_ADDR:-:50051}"
ROUTER="${ROUTER:-r2}"

# CLI socket 默认 /opt/asscor/asscor-cli.sock; 本脚本的测试实例一律用
# $DATA_DIR/asscor-cli.sock (ASSCOR_CLI_SOCKET 覆盖), 避免与已安装的
# systemd kernel 实例抢同一个 socket (A-1 实测 "Unknown command: mode" 根因)。
CLI_SOCK="${CLI_SOCK:-$DATA_DIR/asscor-cli.sock}"

# 拼出 kernel 启动命令（ASSCOR_CLI_SOCKET 注入 + setsid 脱离会话）。
# $1=二进制路径。返回的字符串在远端/本地经 eval 语义执行。
kernel_cmd() { # $1=bin
  echo "ASSCOR_CLI_SOCKET=$CLI_SOCK setsid nohup $1 --config=$CONFIG_DIR/config.ini --listen=$LISTEN_ADDR --cert-dir=$CERT_DIR --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 < /dev/null &"
}

# --- 工具函数 -----------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

if [ "$EXECUTOR" = "ssh" ] && { [ -z "$REMOTE_HOST" ] && [ -z "$KERNEL_HOST" ] || [ "$KERNEL_HOST" = "edge0" ]; }; then
  die "ssh executor needs a target host: --kernel-host=<host> or REMOTE_HOST env"
fi

# --- 构建 tag（与实测构建矩阵一致：kernel 需 comms/heartbeat 等，agent 需 checks）--
KERNEL_TAGS="securemode,heartbeat,commander,policy,cti,assessor,attck_ext,spc,collector,sourcemanager,persistence,srdwrapper,integrity,resilience,comms,checks,adapter,engine"
AGENT_TAGS="securemode,checks"

# 生成 openssl 证书（每 agent 独立 key/crt，EKU clientAuth，与实测 issue_certs.sh 一致）
issue_cert() { # $1=host_id  $2=ca_dir
  local host="$1" ca="$2"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$ca/$host.key" -out "$ca/$host.csr" \
    -subj "/CN=$host" 2>/dev/null
  printf "extendedKeyUsage = clientAuth\n" > "$ca/ext-$host.cnf"
  openssl x509 -req -in "$ca/$host.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" \
    -CAcreateserial -out "$ca/$host.crt" -days 365 -extfile "$ca/ext-$host.cnf" 2>/dev/null
  echo "$host: $(openssl x509 -in "$ca/$host.crt" -noout -fingerprint -sha256)"
}

# 向远端复制本地文件: copy_in <local> <remote_path>
copy_in() {
  local local_path="$1" remote_path="$2"
  case "$EXECUTOR" in
    clab)  docker cp "$local_path" "asc-asscor-$KERNEL_HOST:$remote_path" ;;
    ssh)   scp -q "$local_path" "$REMOTE_USER@$KERNEL_HOST:$remote_path" ;;
    local) cp -f "$local_path" "$remote_path" ;;
  esac
}

# 从远端取回文件: copy_out <remote_path> <local_path>
copy_out() {
  local remote_path="$1" local_path="$2"
  case "$EXECUTOR" in
    clab)  docker cp "asc-asscor-$KERNEL_HOST:$remote_path" "$local_path" ;;
    ssh)   scp -q "$REMOTE_USER@$KERNEL_HOST:$remote_path" "$local_path" ;;
    local) cp -f "$remote_path" "$local_path" ;;
  esac
}

# 在远端执行命令（单字符串命令，正确转义）
remote_exec() {
  local cmd="$1"
  case "$EXECUTOR" in
    clab)  docker exec "asc-asscor-$KERNEL_HOST" bash -lc "$cmd" ;;
    # ssh: 直接整串传给远端默认 shell 执行——不要再包 bash -lc '...'，
    # 否则命令内的单引号会截断外层引号（A-1 实测坑）。
    ssh)   ssh -o BatchMode=yes "$REMOTE_USER@$KERNEL_HOST" "$cmd" ;;
    local) bash -lc "$cmd" ;;
  esac
}

# clab 后端: 展开 agent 标识 -> 容器名
agent_container() { echo "asc-asscor-host$1"; }

# 从 CA_DIR 读取 kernel 证书指纹(CA 自签指纹), 供 reset-identity 对照
ca_fingerprint() {
  openssl x509 -in "$CA_DIR/ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':'
}

# ----------------------------------------------------------------------------
# 子命令: build —— 交叉编译 securemode kernel/agent
# ----------------------------------------------------------------------------
# 生成最小 kernel config.ini（首次部署无现成配置时用；含 [bootstrap] 段）
make_kernel_config() {
  local out="$1"
  cat > "$out" <<EOF
[bootstrap]
listen_addr = $LISTEN_ADDR

[weights]
attack_surface = 35
business_continuity = 25
operation_trust = 25
resilience = 15
EOF
}

cmd_build() {
  info "building kernel (tags: $KERNEL_TAGS)"
  mkdir -p "$OUT_BIN"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "$KERNEL_TAGS" \
    -trimpath -o "$OUT_BIN/ASSCOR-kernel-secure" ./cmd/kernel/
  info "building agent (tags: $AGENT_TAGS)"
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags "$AGENT_TAGS" \
    -trimpath -o "$OUT_BIN/ASSCOR-agent-secure" ./cmd/agent/
  ls -lh "$OUT_BIN/ASSCOR-kernel-secure" "$OUT_BIN/ASSCOR-agent-secure"
  echo "kernel 二进制: $OUT_BIN/ASSCOR-kernel-secure"
  echo "agent  二进制: $OUT_BIN/ASSCOR-agent-secure"
}

# ----------------------------------------------------------------------------
# 子命令: deploy-kernel —— 部署并启动 kernel（首启自动生成 CA/证书）
# ----------------------------------------------------------------------------
cmd_deploy_kernel() {
  local kern_bin="${KERNEL_BIN:-$OUT_BIN/ASSCOR-kernel-secure}"
  [ -f "$kern_bin" ] || die "kernel binary not found: $kern_bin (run 'build' first or set KERNEL_BIN)"

  info "deploying kernel to $EXECUTOR/$KERNEL_HOST"
  local tmpcfg; tmpcfg=$(mktemp)
  make_kernel_config "$tmpcfg"
  case "$EXECUTOR" in
    clab)
      docker exec "asc-asscor-$KERNEL_HOST" bash -lc "mkdir -p $CONFIG_DIR $DATA_DIR $CERT_DIR /var/log/asscor"
      docker cp "$kern_bin" "asc-asscor-$KERNEL_HOST:/usr/local/bin/ASSCOR-kernel-secure"
      # config.ini: 若容器里已有则不动；否则用最小模板
      if ! docker exec "asc-asscor-$KERNEL_HOST" test -f "$CONFIG_DIR/config.ini"; then
        docker cp "$tmpcfg" "asc-asscor-$KERNEL_HOST:$CONFIG_DIR/config.ini"
      fi
      # 若已有一个 kernel 实例在跑(旧 systemd/手动), 先停掉避免 CLI socket 冲突
      docker exec "asc-asscor-$KERNEL_HOST" bash -lc \
        "pkill -x ASSCOR-kernel-secure 2>/dev/null || true; rm -f $CLI_SOCK 2>/dev/null || true; true"
      docker exec -d "asc-asscor-$KERNEL_HOST" bash -lc "cd $DATA_DIR && $(kernel_cmd /usr/local/bin/ASSCOR-kernel-secure)"
      ;;
    ssh)
      remote_exec "mkdir -p $CONFIG_DIR $DATA_DIR $CERT_DIR /var/log/asscor"
      copy_in "$kern_bin" "/usr/local/bin/ASSCOR-kernel-secure"
      if ! remote_exec "test -f $CONFIG_DIR/config.ini"; then
        copy_in "$tmpcfg" "$CONFIG_DIR/config.ini"
      fi
      # 旧实例清理: 只 kill 二进制名完全匹配的进程, 防误杀 sshd (pkill -x)
      remote_exec "pkill -x ASSCOR-kernel-secure 2>/dev/null || true; rm -f $CLI_SOCK; true"
      remote_exec "$(kernel_cmd /usr/local/bin/ASSCOR-kernel-secure)"
      ;;
    local)
      local rundir="$DATA_DIR"; mkdir -p "$rundir" "$CONFIG_DIR" "$CERT_DIR"
      [ -f "$CONFIG_DIR/config.ini" ] || cp -f "$tmpcfg" "$CONFIG_DIR/config.ini"
      pkill -x ASSCOR-kernel-secure 2>/dev/null || true
      rm -f "$CLI_SOCK"
      (cd "$rundir" && eval "$(kernel_cmd "$kern_bin")")
      ;;
  esac
  rm -f "$tmpcfg"

  sleep 6
  info "waiting for kernel bootstrap (CA generation)"
  # kernel 首启自动生成 ca/server/agent 证书; 稍候确认进程存活
  case "$EXECUTOR" in
    clab)  docker exec "asc-asscor-$KERNEL_HOST" pgrep -x ASSCOR-kernel-secure >/dev/null || die "kernel not running" ;;
    ssh)   remote_exec "pgrep -x ASSCOR-kernel-secure >/dev/null" || die "kernel not running" ;;
    local) pgrep -x ASSCOR-kernel-secure >/dev/null || die "kernel not running" ;;
  esac
  info "kernel started (executor=$EXECUTOR host=$KERNEL_HOST listen=$LISTEN_ADDR)"

  # 导出 CA 供 agent 证书签发
  info "exporting CA from kernel"
  mkdir -p "$CA_DIR"
  case "$EXECUTOR" in
    clab)  docker cp "asc-asscor-$KERNEL_HOST:$CERT_DIR/ca.crt" "$CA_DIR/ca.crt"; docker cp "asc-asscor-$KERNEL_HOST:$CERT_DIR/ca.key" "$CA_DIR/ca.key" ;;
    ssh)   copy_out "$CERT_DIR/ca.crt" "$CA_DIR/ca.crt"; copy_out "$CERT_DIR/ca.key" "$CA_DIR/ca.key" ;;
    local) cp -f "$CERT_DIR/ca.crt" "$CA_DIR/ca.crt"; cp -f "$CERT_DIR/ca.key" "$CA_DIR/ca.key" ;;
  esac
  chmod 600 "$CA_DIR/ca.key"
  echo "CA: $CA_DIR/ca.crt (指纹 $(ca_fingerprint))"
}

# ----------------------------------------------------------------------------
# 子命令: deploy-agent —— 签发证书、生成 agent.ini、分发并启动 N 个 agent
# ----------------------------------------------------------------------------
cmd_deploy_agent() {
  local agent_bin="${AGENT_BIN:-$OUT_BIN/ASSCOR-agent-secure}"
  [ -f "$agent_bin" ] || die "agent binary not found: $agent_bin (run 'build' first or set AGENT_BIN)"
  [ -f "$CA_DIR/ca.crt" ] || die "CA not found in $CA_DIR — run 'deploy-kernel' first"
  [ -n "$AGENTS" ] || die "--agents='a b c' required (or AGENTS= env)"

  # 1. 为每个 agent 签发独立证书
  info "issuing per-agent certificates"
  for h in $AGENTS; do
    [ -f "$CA_DIR/$h.crt" ] || issue_cert "$h" "$CA_DIR"
  done

  # 2. 部署与启动
  local n=0
  for h in $AGENTS; do
    n=$((n+1))
    # 资源边界：ssh 后端并发进程上限（A-1 实测 ~14，默认 12 留余量）
    if [ "$EXECUTOR" = "ssh" ] && [ "$n" -gt "$AGENT_LIMIT" ]; then
      warn "ssh agent limit $AGENT_LIMIT reached — skipping ${h} (AGENT_LIMIT 可调)"
      continue
    fi

    # agent.ini: 用 base64 传输避免 heredoc 转义坑（A-1 实测 printf/heredoc 会静默失败）
    # [bootstrap] 明文段保留 kernel 地址与 TLS 连接必需项; [agent] 段受保护
    local ini; ini=$(mktemp)
    cat > "$ini" <<EOF
[bootstrap]
kernel_addr = $KERNEL_ADDR
cert_dir = $CERT_DIR
tls_enabled = true
tls_skip_verify = false

[agent]
host_id = $h
hostname = $h
version = v0.2.3
heartbeat_sec = 30
check_interval_sec = 300
check_timeout_sec = 10
max_retries = 3
reconnect_sec = 5
hmac_key =
log_format = text
log_level = info
log_output = stderr
EOF

    # A-1 实测坑: heredoc/printf 转义曾静默写出空文件 → agent 用默认 host_id
    # (主机名) 注册导致证书身份冲突。写入后回读校验: 非空 + host_id 正确。
    local ini_ok=0
    if [ -s "$ini" ] && grep -q "host_id = $h" "$ini"; then
      ini_ok=1
    fi
    [ "$ini_ok" = "1" ] || die "agent.ini for $h failed local write validation"

    case "$EXECUTOR" in
      clab)
        local cid; cid=$(agent_container "$h")
        docker exec "$cid" bash -lc "mkdir -p $CERT_DIR /var/log/asscor"
        docker cp "$agent_bin" "$cid:/usr/local/bin/ASSCOR-agent-secure"
        docker cp "$ini" "$cid:$CONFIG_DIR/agent.ini"
        docker cp "$CA_DIR/ca.crt" "$cid:$CERT_DIR/ca.crt"
        docker cp "$CA_DIR/$h.crt" "$cid:$CERT_DIR/agent.crt"
        docker cp "$CA_DIR/$h.key" "$cid:$CERT_DIR/agent.key"
        docker exec "$cid" bash -lc "chmod 755 /usr/local/bin/ASSCOR-agent-secure; chmod 600 $CERT_DIR/agent.key"
        # 旧实例清理(pkill -x 防误杀); 已加密残留(agent.ini.enc)保留——重启后走锁定+自恢复路径
        docker exec "$cid" bash -lc "pkill -x ASSCOR-agent-secure 2>/dev/null || true; true"
        docker exec -d "$cid" bash -lc \
          "setsid nohup /usr/local/bin/ASSCOR-agent-secure --config=$CONFIG_DIR/agent.ini --kernel=$KERNEL_ADDR --cert-dir=$CERT_DIR --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 < /dev/null &"
        ;;
      ssh)
        # ssh 后端 = A-1 式同机多进程模拟: kernel 与全部 agent 都在 KERNEL_HOST
        # 上, 每 agent 独立工作目录 $DATA_DIR/agent-<id>（配置/证书/日志互不覆盖）
        local rh; rh="${REMOTE_USER}@${KERNEL_HOST}"
        remote_exec "mkdir -p $DATA_DIR/agent-$h/$CERT_DIR"
        # 二进制放共享路径一次即可（cp 幂等）
        copy_in "$agent_bin" "/usr/local/bin/ASSCOR-agent-secure"
        # agent.ini 生成在本地临时文件后经 sed 改 cert_dir 指向该 agent 目录
        sed "s|^cert_dir = .*|cert_dir = $DATA_DIR/agent-$h/$CERT_DIR|" "$ini" > "$ini.$h"
        ssh -o BatchMode=yes "$rh" "cat > $DATA_DIR/agent-$h/agent.ini" < "$ini.$h"
        ssh -o BatchMode=yes "$rh" "cat > $DATA_DIR/agent-$h/$CERT_DIR/ca.crt" < "$CA_DIR/ca.crt"
        ssh -o BatchMode=yes "$rh" "cat > $DATA_DIR/agent-$h/$CERT_DIR/agent.crt" < "$CA_DIR/$h.crt"
        ssh -o BatchMode=yes "$rh" "cat > $DATA_DIR/agent-$h/$CERT_DIR/agent.key" < "$CA_DIR/$h.key"
        remote_exec "chmod 755 /usr/local/bin/ASSCOR-agent-secure 2>/dev/null || true; chmod 600 $DATA_DIR/agent-$h/$CERT_DIR/agent.key; pkill -f 'ASSCOR-agent-secure.*agent-$h' 2>/dev/null || true; true"
        # setsid + </dev/null 使进程脱离 ssh 会话（docker exec -d 的同步进程会随会话死掉 — 同源坑）
        remote_exec "setsid nohup /usr/local/bin/ASSCOR-agent-secure --config=$DATA_DIR/agent-$h/agent.ini --kernel=$KERNEL_ADDR --cert-dir=$DATA_DIR/agent-$h/$CERT_DIR --log-output=$DATA_DIR/agent-$h/agent.log >/tmp/agent-$h.out 2>&1 < /dev/null &"
        rm -f "$ini.$h"
        ;;
      local)
        local wd="$DATA_DIR/agent-$h"; mkdir -p "$wd/$CERT_DIR"
        cp -f "$agent_bin" "$wd/ASSCOR-agent-secure"
        sed "s|^cert_dir = .*|cert_dir = $wd/$CERT_DIR|" "$ini" > "$wd/agent.ini"
        cp -f "$CA_DIR/ca.crt" "$wd/$CERT_DIR/ca.crt"
        cp -f "$CA_DIR/$h.crt" "$wd/$CERT_DIR/agent.crt"
        cp -f "$CA_DIR/$h.key" "$wd/$CERT_DIR/agent.key"
        chmod 600 "$wd/$CERT_DIR/agent.key"
        pkill -f "ASSCOR-agent-secure.*agent-$h" 2>/dev/null || true
        (cd "$wd" && nohup ./ASSCOR-agent-secure --config="$wd/agent.ini" --kernel="$KERNEL_ADDR" \
          --cert-dir="$wd/$CERT_DIR" --log-output="$wd/agent.log" >"/tmp/agent-$h.out" 2>&1 &)
        ;;
    esac
    rm -f "$ini"
    echo "agent $h deployed (${n})"
    # 逐台短延,避免瞬时连接风暴
    sleep 1
  done

  info "all agents deployed; waiting for first heartbeat (bootstrap encryption + registration)"
  sleep $((15 + n/4))
  info "done — run 'verify' to confirm .enc encryption and registration"
}

# ----------------------------------------------------------------------------
# 子命令: reset-identity —— 身份绑定清理（CA/证书轮换后让 agent 重新注册）
# ----------------------------------------------------------------------------
cmd_reset_identity() {
  info "reset-identity: clearing host↔certificate bindings on kernel ($EXECUTOR/$KERNEL_HOST)"

  # 方式 A: 经 CLI socket 调 `cert reset --yes`（Fix 4 新命令, heartbeat 模块提供）
  if [ "$CERT_RESET" = "1" ]; then
    local sock="$CLI_SOCK"
    local out
    case "$EXECUTOR" in
      clab)
        if docker exec "asc-asscor-$KERNEL_HOST" test -S "$sock" 2>/dev/null; then
          out=$(docker exec "asc-asscor-$KERNEL_HOST" bash -lc "echo 'cert reset --yes' | /usr/local/bin/ASSCOR-kernel-secure --cli $sock 2>&1" || true)
          echo "$out"
          echo "$out" | grep -q "Cleared" && echo "  -> identity bindings cleared via cert reset"
        else
          warn "CLI socket $sock not present — falling back to file cleanup"
          CERT_RESET=0
        fi
        ;;
      ssh)
        if remote_exec "test -S $sock" 2>/dev/null; then
          out=$(remote_exec "echo 'cert reset --yes' | /usr/local/bin/ASSCOR-kernel-secure --cli $sock 2>&1" || true)
          echo "$out"
          echo "$out" | grep -q "Cleared" && echo "  -> identity bindings cleared via cert reset"
        else
          warn "CLI socket $sock not present — falling back to file cleanup"
          CERT_RESET=0
        fi
        ;;
      local)
        if [ -S "$sock" ]; then
          out=$(echo 'cert reset --yes' | "$OUT_BIN/ASSCOR-kernel-secure" --cli "$sock" 2>&1 || true)
          echo "$out"
          echo "$out" | grep -q "Cleared" && echo "  -> identity bindings cleared via cert reset"
        else
          warn "CLI socket $sock not present — falling back to file cleanup"
          CERT_RESET=0
        fi
        ;;
    esac
  fi

  # 方式 B（CERT_RESET=0 或 socket 不可用）: 停 kernel → 删绑定文件 → 重启
  # heartbeat_identity.json 是 host↔指纹锚; 删除后所有 agent 下次注册按 first-contact 重绑
  if [ "$CERT_RESET" != "1" ]; then
    warn "manual cleanup path: stop kernel, remove identity file, restart"
    case "$EXECUTOR" in
      clab)
        docker exec "asc-asscor-$KERNEL_HOST" bash -lc \
          "pkill -x ASSCOR-kernel-secure; rm -f $DATA_DIR/heartbeat_identity.json; true"
        docker exec -d "asc-asscor-$KERNEL_HOST" bash -lc "cd $DATA_DIR && $(kernel_cmd /usr/local/bin/ASSCOR-kernel-secure)"
        ;;
      ssh)
        remote_exec "pkill -x ASSCOR-kernel-secure; rm -f $DATA_DIR/heartbeat_identity.json; true"
        remote_exec "$(kernel_cmd /usr/local/bin/ASSCOR-kernel-secure)"
        ;;
      local)
        pkill -x ASSCOR-kernel-secure
        rm -f "$DATA_DIR/heartbeat_identity.json"
        (cd "$DATA_DIR" && eval "$(kernel_cmd "$OUT_BIN/ASSCOR-kernel-secure")")
        ;;
    esac
    echo "  -> identity bindings file removed; agents re-register on next heartbeat"
  fi

  # agent 侧: 清除可能残留的旧 .asscor-mode / socket（证书轮换后旧状态无意义）
  info "agent-side cleanup (residual sockets / mode markers) is per-agent: stop agent, rm socket, restart"
}

# ----------------------------------------------------------------------------
# 子命令: verify —— 检查 .enc 加密、进程存活、登记表与心跳
# ----------------------------------------------------------------------------
cmd_verify() {
  info "verify (executor=$EXECUTOR)"

  case "$EXECUTOR" in
    clab)
      # kernel 存活 + 登记表(经 mode status)
      docker exec "asc-asscor-$KERNEL_HOST" pgrep -x ASSCOR-kernel-secure >/dev/null || die "kernel not running"
      echo "--- kernel mode status ---"
      docker exec "asc-asscor-$KERNEL_HOST" bash -lc \
        "echo 'mode status' | /usr/local/bin/ASSCOR-kernel-secure --cli $CLI_SOCK 2>&1 | head -40 || true"
      # agent .enc 加密 + 存活
      if [ -n "$AGENTS" ]; then
        for h in $AGENTS; do
          local cid; cid=$(agent_container "$h")
          local enc_st
          enc_st=$(docker exec "$cid" bash -lc "ls $CONFIG_DIR/agent.ini.enc 2>/dev/null && echo ENC || echo NOENC")
          local alive; alive=$(docker exec "$cid" pgrep -x ASSCOR-agent-secure >/dev/null && echo ALIVE || echo DEAD)
          echo "agent $h: $alive $enc_st"
        done
      else
        warn "--agents not given; skipping per-agent .enc check"
      fi
      ;;
    ssh)
      remote_exec "pgrep -x ASSCOR-kernel-secure >/dev/null" || die "kernel not running"
      echo "--- kernel mode status ---"
      remote_exec "echo 'mode status' | /usr/local/bin/ASSCOR-kernel-secure --cli $CLI_SOCK 2>&1 | head -40 || true"
      if [ -n "$AGENTS" ]; then
        for h in $AGENTS; do
          local enc2 alive2
          enc2=$(remote_exec "ls $DATA_DIR/agent-$h/agent.ini.enc 2>/dev/null && echo ENC || echo NOENC" 2>/dev/null || echo "UNREACHABLE")
          alive2=$(remote_exec "pgrep -f 'ASSCOR-agent-secure.*agent-$h' >/dev/null && echo ALIVE || echo DEAD" 2>/dev/null || echo "UNREACHABLE")
          echo "agent $h: $alive2 $enc2"
        done
      fi
      ;;
    local)
      pgrep -x ASSCOR-kernel-secure >/dev/null || die "kernel not running"
      if [ -n "$AGENTS" ]; then
        for h in $AGENTS; do
          local enc2 alive2
          enc2=$(ls "$DATA_DIR/agent-$h/agent.ini.enc" 2>/dev/null && echo ENC || echo NOENC)
          alive2=$(pgrep -f "ASSCOR-agent-secure.*agent-$h" >/dev/null && echo ALIVE || echo DEAD)
          echo "agent $h: $alive2 $enc2"
        done
      fi
      ;;
  esac
}

# ----------------------------------------------------------------------------
# 子命令: ospf —— clab 专用: FRR redistribute connected（扩展子网可达）
# ----------------------------------------------------------------------------
cmd_ospf() {
  [ "$EXECUTOR" = "clab" ] || die "ospf only applies to clab executor"
  local router="${ROUTER:-r2}"
  info "configuring OSPF redistribute connected on $router"
  docker exec "asc-asscor-$router" vtysh -c "configure terminal" \
    -c "router ospf" -c "redistribute connected" 2>/dev/null || \
    docker exec "asc-asscor-$router" bash -lc "vtysh -c 'configure terminal' -c 'router ospf' -c 'redistribute connected'" 
  echo "done — check with: docker exec asc-asscor-$router vtysh -c 'show ip ospf'"
}

# --- 主调度 -------------------------------------------------------------------
SUB="help"
for a in "$@"; do
  case "$a" in
    --*) : ;;
    *) SUB="$a"; break ;;
  esac
done
case "$SUB" in
  build)          cmd_build ;;
  deploy-kernel)  cmd_deploy_kernel ;;
  deploy-agent)   cmd_deploy_agent ;;
  reset-identity) cmd_reset_identity ;;
  verify)         cmd_verify ;;
  ospf)           cmd_ospf ;;
  help|-h|--help)
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    echo
    echo "executor: $EXECUTOR | kernel-host: ${KERNEL_HOST:-edge0} | agents: ${AGENTS:-(未指定)}"
    ;;
  *) die "unknown subcommand: $SUB (see help)" ;;
esac
