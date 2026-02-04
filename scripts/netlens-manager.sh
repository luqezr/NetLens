#!/bin/bash

# NetLens Manager (TUI)
# - Shows service/process status
# - Runs API health checks
# - Starts/stops/enable/disables systemd units
# - Kills leftover NetLens processes (dev + installed paths)

set -euo pipefail

ASCII_BANNER='    _   __     __  __                   
   / | / /__  / /_/ /   ___  ____  _____
  /  |/ / _ \/ __/ /   / _ \/ __ \/ ___/
 / /|  /  __/ /_/ /___/  __/ / / (__  ) 
/_/ |_/\___/\__/_____/\___/_/ /_/____/  '

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

detect_mongo_service() {
  if systemctl list-unit-files --no-pager 2>/dev/null | grep -qE '^mongod\.service\s'; then
    echo "mongod"
    return 0
  fi
  if systemctl list-unit-files --no-pager 2>/dev/null | grep -qE '^mongodb\.service\s'; then
    echo "mongodb"
    return 0
  fi
  return 1
}

read_env_value() {
  local file="$1"
  local key="$2"
  local default_value="${3:-}"
  if [[ ! -f "$file" ]]; then
    echo "$default_value"
    return 0
  fi

  # Reads the last matching KEY=... line; strips surrounding quotes.
  local value
  value=$(grep -E "^[[:space:]]*${key}=" "$file" | tail -n 1 | sed -E "s/^[[:space:]]*${key}=//")
  value="${value%\r}"
  value="${value%\n}"
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"

  if [[ -z "$value" ]]; then
    echo "$default_value"
  else
    echo "$value"
  fi
}

unit_state_line() {
  local unit="$1"
  local active enabled

  if ! systemctl list-unit-files --no-pager 2>/dev/null | grep -qE "^${unit}[[:space:]]"; then
    echo "- ${unit}: not installed"
    return 0
  fi

  active=$(systemctl is-active "$unit" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)

  printf -- "- %s: %s (%s)\n" "$unit" "$active" "$enabled"
}

count_matching_procs() {
  local pattern="$1"
  local count
  count=$(pgrep -f "$pattern" 2>/dev/null | wc -l | tr -d ' ' || true)
  echo "${count:-0}"
}

proc_summary_lines() {
  local installed_node dev_node installed_scanner dev_scanner
  installed_node=$(count_matching_procs "/opt/netlens/server.js")
  dev_node=$(count_matching_procs "${REPO_ROOT}/server.js")
  installed_scanner=$(count_matching_procs "/opt/netlens/scanner_service.py")
  dev_scanner=$(count_matching_procs "${REPO_ROOT}/scanner_service.py")

  echo "- node server.js (installed): ${installed_node}"
  echo "- node server.js (dev):       ${dev_node}"
  echo "- scanner_service.py (inst):  ${installed_scanner}"
  echo "- scanner_service.py (dev):   ${dev_scanner}"
}

get_api_url() {
  local env_file="/opt/netlens/config.env"
  if [[ ! -f "$env_file" && -f "${REPO_ROOT}/config.env" ]]; then
    env_file="${REPO_ROOT}/config.env"
  fi
  local port https_port enable_https
  port=$(read_env_value "$env_file" "PORT" "5000")
  https_port=$(read_env_value "$env_file" "HTTPS_PORT" "5443")
  enable_https=$(read_env_value "$env_file" "ENABLE_HTTPS" "false")
  enable_https=$(echo "$enable_https" | tr '[:upper:]' '[:lower:]')

  if [[ "$enable_https" == "true" ]]; then
    echo "https://localhost:${https_port}"
  else
    echo "http://localhost:${port}"
  fi
}

api_healthcheck() {
  local url="$(get_api_url)/health"
  local curl_args=(--silent --show-error --max-time 4)
  
  if [[ "$url" == https* ]]; then
    curl_args+=(--insecure)
  fi

  if ! have_cmd curl; then
    echo "Health: ERROR (curl not installed)"
    return 0
  fi

  local http_code
  http_code=$(curl "${curl_args[@]}" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
  if [[ "$http_code" == "200" ]]; then
    echo "Health: OK (${url} -> 200)"
  elif [[ -z "$http_code" || "$http_code" == "000" ]]; then
    echo "Health: FAIL (${url} -> no response)"
  else
    echo "Health: WARN (${url} -> ${http_code})"
  fi
}

get_cookie_file() {
  echo "/tmp/netlens-manager-cookies.txt"
}

api_login() {
  local env_file="/opt/netlens/config.env"
  if [[ ! -f "$env_file" && -f "${REPO_ROOT}/config.env" ]]; then
    env_file="${REPO_ROOT}/config.env"
  fi
  
  local username password
  username=$(read_env_value "$env_file" "DEFAULT_ADMIN_USERNAME" "admin")
  password=$(read_env_value "$env_file" "DEFAULT_ADMIN_PASSWORD" "")
  
  if [[ -z "$password" ]]; then
    return 1
  fi
  
  local url="$(get_api_url)/api/auth/login"
  local cookie_file="$(get_cookie_file)"
  local curl_args=(--silent --show-error --max-time 10 -X POST)
  
  if [[ "$url" == https* ]]; then
    curl_args+=(--insecure)
  fi
  
  curl_args+=(-H "Content-Type: application/json")
  curl_args+=(-d "{\"username\":\"${username}\",\"password\":\"${password}\"}")
  curl_args+=(-c "$cookie_file")
  
  local response
  response=$(curl "${curl_args[@]}" "$url" 2>&1)
  
  if echo "$response" | grep -q '"success":true'; then
    return 0
  else
    rm -f "$cookie_file"
    return 1
  fi
}

api_call() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"
  
  local url="$(get_api_url)${endpoint}"
  local cookie_file="$(get_cookie_file)"
  local curl_args=(--silent --show-error --max-time 10 -X "$method")
  
  if [[ "$url" == https* ]]; then
    curl_args+=(--insecure)
  fi
  
  # Try to use existing session first
  if [[ -f "$cookie_file" ]]; then
    curl_args+=(-b "$cookie_file")
  fi
  
  if [[ -n "$data" ]]; then
    curl_args+=(-H "Content-Type: application/json" -d "$data")
  fi
  
  local response
  response=$(curl "${curl_args[@]}" "$url" 2>&1)
  
  # If unauthorized, try to login and retry once
  if echo "$response" | grep -q '"Unauthorized"'; then
    if api_login; then
      curl_args=(--silent --show-error --max-time 10 -X "$method")
      if [[ "$url" == https* ]]; then
        curl_args+=(--insecure)
      fi
      curl_args+=(-b "$cookie_file")
      if [[ -n "$data" ]]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
      fi
      response=$(curl "${curl_args[@]}" "$url" 2>&1)
    fi
  fi
  
  echo "$response"
}

render_status() {
  local mongo_unit=""
  mongo_unit=$(detect_mongo_service 2>/dev/null || true)

  echo "$ASCII_BANNER"
  echo ""
  echo "Systemd units:"
  unit_state_line "netlensscan.service"
  unit_state_line "netlens.service"
  if [[ -n "$mongo_unit" ]]; then
    unit_state_line "${mongo_unit}.service"
  else
    echo "- mongodb: service name not detected"
  fi
  echo ""
  echo "Processes:"
  proc_summary_lines
  echo ""
  api_healthcheck
}

do_systemctl() {
  local action="$1"
  shift
  if ! is_root; then
    echo "ERROR: Need root for systemctl. Re-run with sudo." >&2
    return 1
  fi
  systemctl "$action" "$@"
}

stop_services() {
  do_systemctl stop netlensscan.service 2>/dev/null || true
  do_systemctl stop netlens.service 2>/dev/null || true
}

start_services() {
  local mongo_unit=""
  mongo_unit=$(detect_mongo_service 2>/dev/null || true)
  if [[ -n "$mongo_unit" ]]; then
    do_systemctl start "${mongo_unit}.service" 2>/dev/null || true
  fi
  do_systemctl start netlensscan.service 2>/dev/null || true
  do_systemctl start netlens.service 2>/dev/null || true
}

restart_services() {
  local mongo_unit=""
  mongo_unit=$(detect_mongo_service 2>/dev/null || true)
  if [[ -n "$mongo_unit" ]]; then
    do_systemctl restart "${mongo_unit}.service" 2>/dev/null || true
  fi
  do_systemctl restart netlensscan.service 2>/dev/null || true
  do_systemctl restart netlens.service 2>/dev/null || true
}

enable_services() {
  do_systemctl enable netlensscan.service 2>/dev/null || true
  do_systemctl enable netlens.service 2>/dev/null || true
}

disable_services() {
  do_systemctl disable netlensscan.service 2>/dev/null || true
  do_systemctl disable netlens.service 2>/dev/null || true
}

kill_leftovers() {
  if ! is_root; then
    echo "ERROR: Need root to reliably kill other users' processes. Re-run with sudo." >&2
    return 1
  fi

  pkill -f "/opt/netlens/server.js" 2>/dev/null || true
  pkill -f "/opt/netlens/scanner_service.py" 2>/dev/null || true

  # Dev paths (repo)
  pkill -f "${REPO_ROOT}/server.js" 2>/dev/null || true
  pkill -f "${REPO_ROOT}/scanner_service.py" 2>/dev/null || true
}

view_logs() {
  local unit="$1"
  if ! have_cmd journalctl; then
    echo "journalctl not available."
    read -r -p "Press Enter to continue..." _
    return 0
  fi
  journalctl -u "$unit" -n 200 --no-pager || true
  echo ""
  read -r -p "Press Enter to continue..." _
}

view_logs_whiptail() {
  local unit="$1"
  local title="$2"

  if ! have_cmd journalctl; then
    whiptail --title "${title}" --msgbox "journalctl not available." 8 50
    return 0
  fi

  local tmp
  tmp=$(mktemp -t netlens-logs.XXXXXX)
  journalctl -u "$unit" -n 200 --no-pager 2>/dev/null >"$tmp" || echo "No logs" >"$tmp"
  whiptail --title "${title}" --scrolltext --textbox "$tmp" 25 90
  rm -f "$tmp"
}

view_scan_status_whiptail() {
  if ! have_cmd curl; then
    whiptail --title "Scan Status" --msgbox "curl not installed." 8 50
    return 0
  fi

  local response
  response=$(api_call GET "/api/scans/status" 2>&1 || echo '{"error":"API call failed"}')
  
  local tmp
  tmp=$(mktemp -t netlens-scan-status.XXXXXX)
  
  # Pretty print JSON if jq is available, otherwise raw
  if have_cmd jq; then
    echo "$response" | jq '.' 2>/dev/null >"$tmp" || echo "$response" >"$tmp"
  else
    echo "$response" >"$tmp"
  fi
  
  whiptail --title "Current Scan Status" --scrolltext --textbox "$tmp" 30 100
  rm -f "$tmp"
}

trigger_manual_scan_whiptail() {
  if ! have_cmd curl; then
    whiptail --title "Manual Scan" --msgbox "curl not installed." 8 50
    return 0
  fi

  if ! whiptail --title "Manual Scan" --yesno "Trigger a new scan now?" 8 50; then
    return 0
  fi

  # Ensure we're logged in
  local cookie_file="$(get_cookie_file)"
  if [[ ! -f "$cookie_file" ]]; then
    # Try auto-login first
    if ! api_login 2>/dev/null; then
      # Prompt for credentials
      local username password
      username=$(whiptail --title "Login Required" --inputbox "Username:" 10 50 "admin" 3>&1 1>&2 2>&3 || true)
      if [[ -z "$username" ]]; then
        return 0
      fi
      password=$(whiptail --title "Login Required" --passwordbox "Password:" 10 50 3>&1 1>&2 2>&3 || true)
      if [[ -z "$password" ]]; then
        return 0
      fi
      
      # Manual login
      local url="$(get_api_url)/api/auth/login"
      local curl_args=(--silent --show-error --max-time 10 -X POST)
      if [[ "$url" == https* ]]; then
        curl_args+=(--insecure)
      fi
      curl_args+=(-H "Content-Type: application/json")
      curl_args+=(-d "{\"username\":\"${username}\",\"password\":\"${password}\"}")
      curl_args+=(-c "$cookie_file")
      
      local login_response
      login_response=$(curl "${curl_args[@]}" "$url" 2>&1)
      if ! echo "$login_response" | grep -q '"success":true'; then
        whiptail --title "Login Failed" --msgbox "Invalid credentials." 8 50
        return 0
      fi
    fi
  fi

  whiptail --title "Manual Scan" --infobox "Triggering scan..." 8 50
  local response
  response=$(api_call POST "/api/scans/run" '{}' 2>&1 || echo '{"error":"API call failed"}')
  
  if echo "$response" | grep -q '"success":true'; then
    whiptail --title "Manual Scan" --msgbox "Scan queued successfully!\\n\\nUse 'View current scan status' to monitor progress." 12 70
  else
    whiptail --title "Manual Scan" --msgbox "Failed to trigger scan:\\n\\n${response}" 15 80
  fi
}

force_stop_scan_whiptail() {
  if ! whiptail --title "Force Stop Scan" --yesno "WARNING: This will kill the scanner process.\\n\\nContinue?" 10 60; then
    return 0
  fi

  if ! is_root; then
    whiptail --title "Force Stop Scan" --msgbox "ERROR: Need root to kill scanner processes." 8 50
    return 0
  fi

  whiptail --title "Force Stop Scan" --infobox "Stopping scanner..." 8 50
  pkill -9 -f "scanner_service.py --run-once" 2>/dev/null || true
  sleep 1
  whiptail --title "Force Stop Scan" --msgbox "Scanner processes terminated." 8 50
}

edit_scan_config_whiptail() {
  local env_file="/opt/netlens/config.env"
  if [[ ! -f "$env_file" ]]; then
    if [[ -f "${REPO_ROOT}/config.env" ]]; then
      env_file="${REPO_ROOT}/config.env"
    else
      whiptail --title "Scan Config" --msgbox "config.env not found." 10 60
      return 0
    fi
  fi

  if ! is_root && [[ "$env_file" == "/opt/netlens/config.env" ]]; then
    whiptail --title "Scan Config" --msgbox "ERROR: Need root to edit /opt/netlens/config.env" 10 60
    return 0
  fi

  local current_ranges current_schedule
  current_ranges=$(read_env_value "$env_file" "NETWORK_RANGES" "192.168.1.0/24")
  current_schedule=$(read_env_value "$env_file" "SCAN_SCHEDULE" "disabled")

  local new_ranges new_schedule
  new_ranges=$(whiptail --title "Scan Config" --inputbox "Network ranges (comma-separated CIDR):" 12 80 "$current_ranges" 3>&1 1>&2 2>&3 || true)
  if [[ -z "$new_ranges" ]]; then
    return 0
  fi

  new_schedule=$(whiptail --title "Scan Config" --inputbox "Scan schedule (disabled, or interval minutes like 60):" 12 80 "$current_schedule" 3>&1 1>&2 2>&3 || true)
  if [[ -z "$new_schedule" ]]; then
    return 0
  fi

  # Update config.env
  sed -i "s|^NETWORK_RANGES=.*|NETWORK_RANGES=${new_ranges}|" "$env_file"
  sed -i "s|^SCAN_SCHEDULE=.*|SCAN_SCHEDULE=${new_schedule}|" "$env_file"

  # Restart service to apply changes
  if whiptail --title "Scan Config" --yesno "Config updated!\\n\\nRestart netlensscan.service to apply changes?" 12 70; then
    whiptail --title "Scan Config" --infobox "Restarting service..." 8 50
    do_systemctl restart netlensscan.service 2>&1
    sleep 2
    whiptail --title "Scan Config" --msgbox "Service restarted." 8 50
  fi
}

edit_config_env_whiptail() {
  local env_file="/opt/netlens/config.env"
  if [[ ! -f "$env_file" ]]; then
    if [[ -f "${REPO_ROOT}/config.env" ]]; then
      env_file="${REPO_ROOT}/config.env"
    else
      whiptail --title "Edit Config" --msgbox "config.env not found." 8 50
      return 0
    fi
  fi

  if ! is_root && [[ "$env_file" == "/opt/netlens/config.env" ]]; then
    whiptail --title "Edit Config" --msgbox "ERROR: Need root to edit /opt/netlens/config.env" 8 60
    return 0
  fi

  # Read current values
  local api_port=$(read_env_value "$env_file" "API_PORT" "5000")
  local cors_origin=$(read_env_value "$env_file" "CORS_ORIGIN" "http://localhost:3000")
  local network_ranges=$(read_env_value "$env_file" "NETWORK_RANGES" "192.168.1.0/24")
  local log_level=$(read_env_value "$env_file" "LOG_LEVEL" "INFO")
  
  # Show menu with options
  local choice
  choice=$(whiptail \
    --title "Config Editor" \
    --menu "Select setting to edit:" 20 80 10 \
    "api_port" "API Port: $api_port" \
    "cors_origin" "CORS Origin: $cors_origin" \
    "network_ranges" "Network Ranges: $network_ranges" \
    "log_level" "Log Level: $log_level" \
    "advanced" "Open in nano (advanced)" \
    "back" "Back to main menu" \
    3>&1 1>&2 2>&3) || return 0
  
  case "$choice" in
    api_port)
      local new_value
      new_value=$(whiptail --inputbox "Enter API Port:" 10 60 "$api_port" 3>&1 1>&2 2>&3) || return 0
      if [[ -n "$new_value" ]]; then
        sed -i "s|^API_PORT=.*|API_PORT=${new_value}|" "$env_file"
        whiptail --title "Success" --msgbox "API_PORT updated to: $new_value\n\nRestart services for changes to take effect." 10 70
      fi
      ;;
    cors_origin)
      local new_value
      new_value=$(whiptail --inputbox "Enter CORS Origin:" 10 60 "$cors_origin" 3>&1 1>&2 2>&3) || return 0
      if [[ -n "$new_value" ]]; then
        sed -i "s|^CORS_ORIGIN=.*|CORS_ORIGIN=${new_value}|" "$env_file"
        whiptail --title "Success" --msgbox "CORS_ORIGIN updated to: $new_value\n\nRestart services for changes to take effect." 10 70
      fi
      ;;
    network_ranges)
      local new_value
      new_value=$(whiptail --inputbox "Enter Network Ranges (comma-separated):" 10 60 "$network_ranges" 3>&1 1>&2 2>&3) || return 0
      if [[ -n "$new_value" ]]; then
        sed -i "s|^NETWORK_RANGES=.*|NETWORK_RANGES=${new_value}|" "$env_file"
        whiptail --title "Success" --msgbox "NETWORK_RANGES updated to: $new_value\n\nRestart services for changes to take effect." 10 70
      fi
      ;;
    log_level)
      local new_value
      new_value=$(whiptail \
        --title "Select Log Level" \
        --menu "Choose log level:" 15 60 5 \
        "DEBUG" "Debug (verbose)" \
        "INFO" "Info (normal)" \
        "WARNING" "Warning" \
        "ERROR" "Error" \
        "CRITICAL" "Critical" \
        3>&1 1>&2 2>&3) || return 0
      if [[ -n "$new_value" ]]; then
        sed -i "s|^LOG_LEVEL=.*|LOG_LEVEL=${new_value}|" "$env_file"
        whiptail --title "Success" --msgbox "LOG_LEVEL updated to: $new_value\n\nRestart services for changes to take effect." 10 70
      fi
      ;;
    advanced)
      if ! have_cmd nano; then
        whiptail --title "Edit Config" --msgbox "nano editor not installed." 8 50
        return 0
      fi
      nano "$env_file"
      whiptail --title "Edit Config" --msgbox "Config saved. Restart services for changes to take effect." 10 70
      ;;
    back)
      return 0
      ;;
  esac
}

plain_menu() {
  while true; do
    clear || true
    render_status
    echo ""
    echo "Actions:"
    echo "  1) Refresh"
    echo "  2) Start all (systemd)"
    echo "  3) Stop all (systemd)"
    echo "  4) Enable at boot (netlensscan+netlens)"
    echo "  5) Disable at boot (netlensscan+netlens)"
    echo "  6) Kill leftover NetLens processes"
    echo "  7) Stop everything (systemd + kill)"
    echo "  8) View logs: netlensscan.service"
    echo "  9) View logs: netlens.service"
    echo "  q) Quit"
    echo ""
    read -r -p "Select: " choice

    case "${choice,,}" in
      1) : ;;
      2) start_services; read -r -p "Done. Press Enter..." _ ;;
      3) stop_services; read -r -p "Done. Press Enter..." _ ;;
      4) enable_services; read -r -p "Done. Press Enter..." _ ;;
      5) disable_services; read -r -p "Done. Press Enter..." _ ;;
      6) kill_leftovers; read -r -p "Done. Press Enter..." _ ;;
      7) stop_services; kill_leftovers; read -r -p "Done. Press Enter..." _ ;;
      8) view_logs "netlensscan.service" ;;
      9) view_logs "netlens.service" ;;
      q) return 0 ;;
      *) echo "Invalid"; sleep 1 ;;
    esac
  done
}

change_admin_password_whiptail() {
  local username
  local new_password
  local confirm_password
  
  username=$(whiptail --inputbox "Enter admin username:" 10 60 "admin" 3>&1 1>&2 2>&3) || return 0
  [[ -z "$username" ]] && return 0
  
  new_password=$(whiptail --passwordbox "Enter new password (min 8 characters):" 10 60 3>&1 1>&2 2>&3) || return 0
  [[ -z "$new_password" ]] && return 0
  
  if [[ ${#new_password} -lt 8 ]]; then
    whiptail --title "Error" --msgbox "Password must be at least 8 characters long." 8 50
    return 0
  fi
  
  confirm_password=$(whiptail --passwordbox "Confirm new password:" 10 60 3>&1 1>&2 2>&3) || return 0
  
  if [[ "$new_password" != "$confirm_password" ]]; then
    whiptail --title "Error" --msgbox "Passwords do not match." 8 50
    return 0
  fi
  
  # Attempt to login first to get session
  if ! api_login; then
    whiptail --title "Error" --msgbox "Failed to authenticate. Check credentials." 8 50
    return 0
  fi
  
  # Get current password for change-password API
  local current_password
  current_password=$(whiptail --passwordbox "Enter current password for verification:" 10 60 3>&1 1>&2 2>&3) || return 0
  [[ -z "$current_password" ]] && return 0
  
  whiptail --title "NetLens" --infobox "Changing password..." 8 50
  
  local payload
  payload=$(cat <<EOF
{
  "current_password": "${current_password}",
  "new_password": "${new_password}"
}
EOF
)
  
  local response
  response=$(api_call POST "/api/auth/change-password" "$payload" 2>&1 || echo '{"error":"API call failed"}')
  
  if echo "$response" | grep -q '"success":true'; then
    whiptail --title "Success" --msgbox "Password changed successfully!" 8 50
  else
    local error_msg
    error_msg=$(echo "$response" | grep -oP '"error":"\K[^"]+' || echo "Unknown error")
    whiptail --title "Error" --msgbox "Failed to change password:\n\n${error_msg}" 12 70
  fi
}

whiptail_menu() {
  # Set purple/green color scheme for whiptail
  export NEWT_COLORS='
root=,magenta
window=,black
border=green,black
title=green,black
textbox=white,black
button=black,green
compactbutton=white,black
listbox=white,black
actlistbox=black,green
actsellistbox=black,green
checkbox=white,black
actcheckbox=black,green
'

  while true; do
    local status_text
    status_text=$(render_status)

    local choice
    choice=$(whiptail \
      --title "NetLens Manager" \
      --menu "$status_text\n\nChoose an action:" 40 130 22 \
      "refresh" "Refresh status" \
      "health" "Run API health check" \
      "scan_status" "View current scan status (live progress)" \
      "scan_run" "Trigger a manual scan now" \
      "scan_stop" "Force-stop running scan" \
      "scan_config" "Configure scan settings (schedule/ranges)" \
      "config_edit" "Edit config.env settings" \
      "change_password" "Change admin password" \
      "start" "Start all (systemd)" \
      "stop" "Stop all (systemd)" \
      "restart" "Restart all services" \
      "enable" "Enable at boot (netlensscan+netlens)" \
      "disable" "Disable at boot (netlensscan+netlens)" \
      "kill" "Kill leftover NetLens processes" \
      "stopall" "Stop everything (systemd + kill)" \
      "logs_api" "View logs: netlensscan.service" \
      "logs_scan" "View logs: netlens.service" \
      "quit" "Quit" \
      3>&1 1>&2 2>&3) || true

    case "$choice" in
      refresh) : ;;
      health)
        whiptail --title "API Health" --msgbox "$(api_healthcheck)" 10 80
        ;;
      scan_status)
        view_scan_status_whiptail
        ;;
      scan_run)
        trigger_manual_scan_whiptail
        ;;
      scan_stop)
        force_stop_scan_whiptail
        ;;
      scan_config)
        edit_scan_config_whiptail
        ;;
      config_edit)
        edit_config_env_whiptail
        ;;
      change_password)
        change_admin_password_whiptail
        ;;
      start)
        whiptail --title "NetLens" --infobox "Starting services..." 8 50
        if output=$(start_services 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      stop)
        whiptail --title "NetLens" --infobox "Stopping services..." 8 50
        if output=$(stop_services 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      restart)
        whiptail --title "NetLens" --infobox "Restarting services..." 8 50
        if output=$(restart_services 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      enable)
        whiptail --title "NetLens" --infobox "Enabling at boot..." 8 50
        if output=$(enable_services 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      disable)
        whiptail --title "NetLens" --infobox "Disabling at boot..." 8 50
        if output=$(disable_services 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      kill)
        whiptail --title "NetLens" --infobox "Killing leftover processes..." 8 55
        if output=$(kill_leftovers 2>&1); then
          whiptail --title "NetLens" --msgbox "Done.\n\n${output}" 20 90
        else
          whiptail --title "NetLens" --msgbox "Failed.\n\n${output}" 20 90
        fi
        ;;
      stopall)
        whiptail --title "NetLens" --infobox "Stopping services and killing leftovers..." 8 65
        out1=$(stop_services 2>&1 || true)
        out2=$(kill_leftovers 2>&1 || true)
        whiptail --title "NetLens" --msgbox "Done.\n\n${out1}\n${out2}" 22 90
        ;;
      logs_api)
        view_logs_whiptail "netlensscan.service" "netlensscan.service logs"
        ;;
      logs_scan)
        view_logs_whiptail "netlens.service" "netlens.service logs"
        ;;
      quit|"")
        return 0
        ;;
      *)
        return 0
        ;;
    esac
  done
}

main() {
  if have_cmd whiptail; then
    whiptail_menu
  else
    plain_menu
  fi
}

main "$@"
