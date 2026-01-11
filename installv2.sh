#!/usr/bin/env bash
set -euo pipefail

# InstallNET-dd-fixed.sh
# Fokus: mode -dd (Windows image) + inject NIC mapping fix (MAC-based) via SetupComplete.
# Argumen dibuat mirip gaya teddysun: -dd URL, -port, -rdp, --ip-addr/mask/gate/dns, -i interface.

ipAddr=""
ipMask=""
ipGate=""
ipDNS="8.8.8.8"
sshPORT="22"
setRDP="0"
WinRemote=""
interfaceSelect=""
ddURL=""
INC_DISK=""

# -------- arg parsing (subset yang relevan untuk -dd) --------
while [[ $# -ge 1 ]]; do
  case "$1" in
    -dd|--image)
      shift
      ddURL="${1:-}"
      shift
      ;;
    -i|--interface)
      shift
      interfaceSelect="${1:-}"
      shift
      ;;
    --ip-addr) shift; ipAddr="${1:-}"; shift ;;
    --ip-mask) shift; ipMask="${1:-}"; shift ;;
    --ip-gate) shift; ipGate="${1:-}"; shift ;;
    --ip-dns)  shift; ipDNS="${1:-}"; shift ;;
    -port) shift; sshPORT="${1:-22}"; shift ;;
    -rdp) shift; setRDP="1"; WinRemote="${1:-}"; shift ;;
    *)
      # biar kompatibel, abaikan arg lain (teddysun banyak arg)
      shift
      ;;
  esac
done

[[ "${EUID}" -ne 0 ]] && echo "Run as root." && exit 1
[[ -z "$ddURL" ]] && echo "Usage: bash InstallNET.sh -dd \"DD download URL\"" && exit 1

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

depend(){
  local missing=0
  for c in "$@"; do
    if ! have_cmd "$c"; then
      echo "Missing: $c"
      missing=1
    fi
  done
  [[ $missing -eq 0 ]] || exit 1
}

primary_iface(){
  local iface=""
  iface="$(ip route get 1.1.1.1 2>/dev/null | awk '/ dev /{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  [[ -n "$iface" ]] && { echo "$iface"; return; }
  iface="$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  echo "$iface"
}

detect_ipv4_cidr(){
  local iface="$1"
  ip -o -4 addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | head -n1
}

cidr_to_mask(){
  local cidr="${1##*/}"
  local b="" m="" i s
  for ((i=0;i<32;i++)); do
    [[ $i -lt $cidr ]] && b+="1" || b+="0"
  done
  for ((i=0;i<4;i++)); do
    s="$(echo "$b" | cut -c$((i*8+1))-$(((i+1)*8)))"
    [[ -z "$m" ]] && m="$((2#${s}))" || m="${m}.$((2#${s}))"
  done
  echo "$m"
}

detect_gateway(){
  local iface="$1"
  local gw=""
  # 1) best: route get
  gw="$(ip route get 1.1.1.1 2>/dev/null | awk '/ via /{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true)"
  [[ -n "$gw" ]] && { echo "$gw"; return; }

  # 2) default route via
  gw="$(ip route show default dev "$iface" 2>/dev/null | awk '{print $3}' | head -n1 || true)"
  [[ -n "$gw" ]] && { echo "$gw"; return; }

  # 3) p2p/default without via (gateway "aneh"): set 0.0.0.0 (akan ditangani di Windows fallback)
  echo "0.0.0.0"
}

detect_dns(){
  awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | head -n3 | xargs || true
}

detect_disk(){
  # pilih disk pertama non-removable yang bukan sr/fd
  local d
  d="$(lsblk -dn -o NAME,TYPE | awk '$2=="disk"{print $1}' | grep -vE '^fd|^sr' | head -n1 || true)"
  [[ -z "$d" ]] && return 1
  echo "/dev/$d"
}

# -------- UFW preflight (port tetap ada) --------
ensure_ufw(){
  have_cmd ufw && return 0
  echo "Installing ufw..."
  if have_cmd apt-get; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y ufw >/dev/null 2>&1 || true
  elif have_cmd yum; then
    yum install -y ufw >/dev/null 2>&1 || true
  fi
  have_cmd ufw || return 1
}

ufw_allow_ports(){
  local ports_csv="$1" proto="${2:-tcp}"
  ensure_ufw || { echo "Skip UFW (not available)."; return 0; }
  IFS=',' read -ra P <<< "$ports_csv"
  for p in "${P[@]}"; do
    p="$(echo "$p" | xargs)"
    [[ -z "$p" ]] && continue
    ufw allow "${p}/${proto}" >/dev/null 2>&1 || true
    echo "UFW allow ${p}/${proto}"
  done
  ufw status | grep -qi "Status: active" || ufw --force enable >/dev/null 2>&1 || true
  ufw status verbose || true
}

# -------- dd image helpers --------
download_and_dd(){
  local url="$1" disk="$2"
  echo "Writing image to $disk from: $url"

  if echo "$url" | grep -qiE '\.gz($|\?)'; then
    depend wget gunzip
    wget -qO- "$url" | gunzip -dc | dd of="$disk" bs=64M status=progress conv=fsync
  elif echo "$url" | grep -qiE '\.xz($|\?)'; then
    depend wget xz
    wget -qO- "$url" | xz -dc | dd of="$disk" bs=64M status=progress conv=fsync
  else
    echo "URL harus .gz atau .xz"
    exit 1
  fi

  sync
  partprobe "$disk" >/dev/null 2>&1 || true
}

# -------- inject Windows SetupComplete (NIC mapping fix) --------
inject_windows_fix(){
  local disk="$1" ip="$2" mask="$3" gw="$4" dns="$5" mac="$6"
  depend lsblk mount umount mkdir grep awk sed

  # Cari partisi NTFS terbesar (biasanya C:)
  local ntfs_part=""
  ntfs_part="$(lsblk -pn -o NAME,FSTYPE,SIZE "$disk" | awk '$2=="ntfs"{print $1, $3}' | sort -k2 -hr | head -n1 | awk '{print $1}' || true)"
  if [[ -z "$ntfs_part" ]]; then
    echo "Tidak menemukan partisi NTFS untuk injeksi SetupComplete. Skip."
    return 0
  fi

  # Pastikan ntfs-3g tersedia untuk RW mount
  if ! have_cmd ntfs-3g; then
    echo "Installing ntfs-3g..."
    if have_cmd apt-get; then
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y ntfs-3g >/dev/null 2>&1 || true
    elif have_cmd yum; then
      yum install -y ntfs-3g >/dev/null 2>&1 || true
    fi
  fi
  have_cmd ntfs-3g || { echo "ntfs-3g tidak tersedia. Skip inject."; return 0; }

  local mnt="/mnt/win"
  mkdir -p "$mnt"
  mount -t ntfs-3g -o rw "$ntfs_part" "$mnt" || { echo "Gagal mount NTFS $ntfs_part. Skip inject."; return 0; }

  # Lokasi SetupComplete
  local scripts_dir="$mnt/Windows/Setup/Scripts"
  mkdir -p "$scripts_dir"

  # PowerShell script: pilih NIC by MAC, fallback link up
  cat >"$scripts_dir/FixNet.ps1" <<'PS1'
param(
  [string]$TargetMac,
  [string]$IPv4,
  [string]$Mask,
  [string]$Gateway,
  [string]$DNS
)

function Normalize-Mac([string]$m){
  if([string]::IsNullOrWhiteSpace($m)){ return "" }
  return ($m -replace '[-:\.]','').ToUpperInvariant()
}

$target = Normalize-Mac $TargetMac

# Get adapters (prefer modern cmdlets, fallback to WMI)
$adapters = @()
try {
  $adapters = Get-NetAdapter -Physical -ErrorAction Stop
} catch {
  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -and $_.IPEnabled -ne $null } | ForEach-Object {
    [pscustomobject]@{
      Name = $_.Description
      MacAddress = $_.MACAddress
      Status = "Unknown"
      LinkSpeed = 0
      InterfaceIndex = $_.InterfaceIndex
    }
  }
}

# Pick by MAC
$chosen = $null
if($adapters -and $target){
  foreach($a in $adapters){
    $mac = Normalize-Mac ($a.MacAddress.ToString())
    if($mac -eq $target){
      $chosen = $a
      break
    }
  }
}

# Fallback: adapter that is Up / has link
if(-not $chosen -and $adapters){
  try {
    $up = $adapters | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if($up){ $chosen = $up }
  } catch {}
}

# Last fallback: first adapter
if(-not $chosen -and $adapters){
  $chosen = $adapters | Select-Object -First 1
}

if(-not $chosen){
  exit 0
}

# Determine interface name/index
$ifName = $chosen.Name
$ifIndex = $null
try { $ifIndex = (Get-NetAdapter -Name $ifName -ErrorAction Stop).ifIndex } catch { $ifIndex = $chosen.InterfaceIndex }

# Clean old IPs on that adapter (best-effort)
try {
  Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

# Set static IP
try {
  if($Gateway -and $Gateway -ne "0.0.0.0"){
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $IPv4 -PrefixLength ([int]([IPAddress]$Mask).GetAddressBytes() | %{$_.ToString("X2")} | %{
      # not used
    }) | Out-Null
  }
} catch {
  # Fallback to netsh (compatible)
}

# netsh compatible path (works on most Windows images)
# Convert mask -> prefix if possible; else just use netsh with mask
try {
  & netsh interface ipv4 set address name="$ifName" static $IPv4 $Mask $Gateway 1 | Out-Null
  if($DNS -and $DNS.Trim().Length -gt 0){
    $dnsList = $DNS.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
    if($dnsList.Count -ge 1){
      & netsh interface ipv4 set dns name="$ifName" static $dnsList[0] | Out-Null
      for($i=1; $i -lt $dnsList.Count; $i++){
        & netsh interface ipv4 add dns name="$ifName" $dnsList[$i] index=($i+1) | Out-Null
      }
    }
  }
} catch {}

exit 0
PS1

  # SetupComplete.cmd will run at end of setup (SYSTEM)
  cat >"$scripts_dir/SetupComplete.cmd" <<CMD
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%WINDIR%\\Setup\\Scripts\\FixNet.ps1" -TargetMac "$mac" -IPv4 "$ip" -Mask "$mask" -Gateway "$gw" -DNS "$dns"
exit /b 0
CMD

  umount "$mnt" || true
  echo "Injected Windows NIC-fix into: $ntfs_part (SetupComplete)"
}

# -------- main flow --------
depend ip lsblk dd

# choose interface
iface="${interfaceSelect:-}"
if [[ -z "$iface" || "$iface" == "auto" ]]; then
  iface="$(primary_iface)"
fi
[[ -z "$iface" ]] && { echo "Gagal deteksi interface."; exit 1; }

# detect network if not provided
if [[ -z "$ipAddr" || -z "$ipMask" || -z "$ipGate" ]]; then
  cidr="$(detect_ipv4_cidr "$iface" || true)"
  [[ -z "$cidr" ]] && { echo "Gagal deteksi IPv4 pada $iface"; exit 1; }
  ipAddr="${ipAddr:-${cidr%%/*}}"
  ipMask="${ipMask:-$(cidr_to_mask "$cidr")}"
  ipGate="${ipGate:-$(detect_gateway "$iface")}"
fi
dns_auto="$(detect_dns)"
if [[ -z "$ipDNS" || "$ipDNS" == "8.8.8.8" ]]; then
  [[ -n "$dns_auto" ]] && ipDNS="$dns_auto"
fi

# mac of chosen iface
mac="$(cat /sys/class/net/"$iface"/address 2>/dev/null | tr '[:lower:]' '[:upper:]' || true)"
[[ -z "$mac" ]] && mac=""

echo "---- Network (Linux) ----"
echo "IFACE : $iface"
echo "MAC   : $mac"
echo "IP    : $ipAddr"
echo "MASK  : $ipMask"
echo "GW    : $ipGate"
echo "DNS   : $ipDNS"
echo "-------------------------"

# UFW preflight (port arg tetap)
defaultPorts="$sshPORT"
if [[ "$setRDP" == "1" && -n "$WinRemote" ]]; then
  defaultPorts="$defaultPorts,$WinRemote"
fi
echo
echo "Firewall preflight (UFW). Default ports: $defaultPorts"
read -r -p "Ports to allow (comma) [ENTER=default]: " inPorts
portsToAllow="${inPorts:-$defaultPorts}"
read -r -p "Protocol (tcp/udp) [tcp]: " inProto
protoToAllow="${inProto:-tcp}"
ufw_allow_ports "$portsToAllow" "$protoToAllow"

# select disk
INC_DISK="$(detect_disk || true)"
[[ -z "$INC_DISK" ]] && { echo "Gagal deteksi disk target."; exit 1; }
echo
echo "Target disk: $INC_DISK"
read -r -p "LANJUT dd ke $INC_DISK? (YES untuk lanjut): " confirm
[[ "$confirm" == "YES" ]] || { echo "Batal."; exit 0; }

download_and_dd "$ddURL" "$INC_DISK"

# inject fix into windows partition
inject_windows_fix "$INC_DISK" "$ipAddr" "$ipMask" "$ipGate" "$ipDNS" "$mac"

echo
echo "Done. Reboot sekarang."
