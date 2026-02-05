
import os
import sys
import time
import uuid
from datetime import datetime, timezone
import threading
import subprocess
import json
import math
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from loguru import logger
import nmap
from pymongo import ReturnDocument

from database.mongo_manager import MongoDBManager


def _load_environment() -> None:
	env_file = os.getenv('ENV_FILE', '/opt/netlens/config.env')
	if os.path.exists(env_file):
		load_dotenv(env_file)


def _configure_logging() -> None:
	log_level = os.getenv('LOG_LEVEL', 'INFO')
	preferred = (os.getenv('LOG_FILE') or '').strip() or '/opt/netlens/logs/scanner.log'

	def _is_writable_file(path: str) -> bool:
		try:
			parent = os.path.dirname(path) or '.'
			if os.path.exists(path):
				return os.access(path, os.W_OK)
			return os.access(parent, os.W_OK)
		except Exception:
			return False

	def _pick_log_file() -> str | None:
		candidates = []
		if preferred:
			candidates.append(preferred)
		# Fallbacks that are often writable for a service user
		candidates.extend([
			'/var/log/netlens/scanner.log',
			'/tmp/netlens/scanner.log',
			os.path.join(os.getcwd(), 'scanner.log'),
		])
		for cand in candidates:
			try:
				os.makedirs(os.path.dirname(cand) or '.', exist_ok=True)
				if _is_writable_file(cand):
					return cand
			except Exception:
				continue
		return None

	logger.remove()
	logger.add(sys.stderr, level=log_level)
	log_file = _pick_log_file()
	if not log_file:
		logger.warning('File logging disabled: no writable LOG_FILE path found')
		return

	try:
		logger.add(log_file, rotation='10 MB', retention='14 days', level=log_level)
		logger.info('File logging enabled at {}', log_file)
	except Exception:
		# If file logging fails, keep stderr logging.
		logger.exception('Failed to configure file logging (LOG_FILE={})', log_file)


def _best_effort_reverse_dns(ip: str) -> str | None:
	try:
		import socket
		name, _, _ = socket.gethostbyaddr(ip)
		name = (name or '').strip()
		if not name or name == ip:
			return None
		return name
	except Exception:
		return None


def _best_effort_mac_from_neighbor_table(ip: str) -> str | None:
	"""Try to read MAC from the OS neighbor/ARP cache without raw sockets.

	This can work even when running scans as a non-root service user.
	"""
	# 1) iproute2 neighbor table
	try:
		p = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=2)
		out = (p.stdout or '').strip()
		# Example: "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
		for token in out.split():
			if token.count(':') == 5 and len(token) >= 17:
				return token.lower()
	except Exception:
		pass

	# 2) /proc/net/arp
	try:
		with open('/proc/net/arp', 'r', encoding='utf-8') as f:
			lines = f.read().splitlines()
		for line in lines[1:]:
			parts = line.split()
			if len(parts) >= 4 and parts[0] == ip:
				mac = parts[3]
				if mac and mac != '00:00:00:00:00:00':
					return mac.lower()
	except Exception:
		pass

	return None


def _infer_device_type(device: dict) -> str | None:
	"""Infer a friendly device type for UI grouping.

	Returns one of: router, switch, printer, windows_pc, linux_pc, mac, mobile, server, unknown
	"""
	hostname = (device.get('hostname') or '').strip().lower()
	vendor = (device.get('vendor') or '').strip().lower()
	os_name = ''
	os_obj = device.get('os')
	if isinstance(os_obj, dict):
		os_name = (os_obj.get('name') or os_obj.get('type') or '').strip().lower()
	elif isinstance(os_obj, str):
		os_name = os_obj.strip().lower()

	services = device.get('services') if isinstance(device.get('services'), list) else []
	open_ports: set[int] = set()
	for s in services:
		try:
			if str(s.get('state') or 'open').lower() != 'open':
				continue
			p = s.get('port')
			if isinstance(p, int):
				open_ports.add(p)
		except Exception:
			continue

	def has_any(substrings: tuple[str, ...], hay: str) -> bool:
		return any(ss in hay for ss in substrings)

	# Strong hints from hostname/vendor
	if has_any(('router', 'gateway', 'gw', 'mikrotik', 'openwrt', 'pfsense'), hostname) or has_any(('mikrotik', 'ubiquiti', 'netgear', 'tp-link', 'tplink', 'cisco', 'juniper'), vendor):
		return 'router'
	if has_any(('switch',), hostname):
		return 'switch'
	if has_any(('printer',), hostname) or 9100 in open_ports or 515 in open_ports or 631 in open_ports:
		return 'printer'
	if has_any(('iphone', 'ipad', 'android', 'pixel', 'samsung'), hostname) or has_any(('apple',), vendor) and 62078 in open_ports:
		return 'mobile'

	# OS hints
	if has_any(('windows',), os_name) or 3389 in open_ports or 445 in open_ports or 139 in open_ports:
		return 'windows_pc'
	if has_any(('mac os', 'os x', 'darwin'), os_name) or has_any(('apple',), vendor):
		return 'mac'
	if has_any(('linux', 'unix', 'freebsd', 'openbsd', 'netbsd'), os_name):
		return 'linux_pc'

	# Service-based hints
	if 53 in open_ports and (80 in open_ports or 443 in open_ports):
		return 'router'
	if 22 in open_ports and (80 in open_ports or 443 in open_ports or 5432 in open_ports or 3306 in open_ports):
		return 'server'
	if 80 in open_ports or 443 in open_ports:
		return 'server'

	return None


def _parse_network_ranges() -> list[str]:
	raw = os.getenv('NETWORK_RANGES', '').strip()
	return _parse_network_ranges_raw(raw)


def _parse_network_ranges_raw(raw: str | None) -> list[str]:
	if not raw:
		return []
	parts = [p.strip() for p in str(raw).strip().replace(';', ',').split(',')]
	return [p for p in parts if p]


def _sanitize_for_mongodb(obj):
	"""Recursively convert all dict keys to strings for MongoDB BSON compatibility."""
	if isinstance(obj, dict):
		return {str(k): _sanitize_for_mongodb(v) for k, v in obj.items()}
	elif isinstance(obj, list):
		return [_sanitize_for_mongodb(item) for item in obj]
	elif isinstance(obj, (int, float, str, bool, type(None))):
		return obj
	else:
		# For other types, convert to string
		return str(obj)


def _get_schedule_from_env():
	raw = (os.getenv('SCAN_SCHEDULE') or '').strip()
	if not raw:
		return IntervalTrigger(minutes=60)

	if raw.lower() in ('disabled', 'disable', 'off', 'false', 'none'):
		return 'disabled'

	# Cron format: "m h dom mon dow" (5 fields)
	fields = raw.split()
	if len(fields) == 5:
		try:
			return CronTrigger.from_crontab(raw)
		except Exception:
			logger.warning('Invalid SCAN_SCHEDULE cron expression: {}', raw)
			return IntervalTrigger(minutes=60)

	# Hour list: "0,1,2,..." -> run at minute 0
	if all(c.isdigit() or c == ',' for c in raw):
		hours = [h.strip() for h in raw.split(',') if h.strip()]
		if hours:
			return CronTrigger(minute=0, hour=','.join(hours))

	# Interval minutes: "60"
	try:
		minutes = int(raw)
		return IntervalTrigger(minutes=max(1, minutes))
	except Exception:
		logger.warning('Unrecognized SCAN_SCHEDULE value: {}', raw)
		return IntervalTrigger(minutes=60)


def _get_schedule_from_db(db):
	settings = db.get_collection('settings').find_one({'_id': 'scan_schedule'})
	if not settings:
		return None
	if not settings.get('enabled', True):
		return 'disabled'
	interval_minutes = settings.get('interval_minutes', 60)
	try:
		interval_minutes = int(interval_minutes)
	except Exception:
		interval_minutes = 60
	interval_minutes = max(1, min(1440, interval_minutes))
	return IntervalTrigger(minutes=interval_minutes)



def _discover_hosts(ranges: list[str]) -> list[str]:
	if not ranges:
		return []

	scanner = nmap.PortScanner()
	found: set[str] = set()

	is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
	if not is_root:
		logger.warning('Discovery running without root privileges; ARP/MAC discovery may be incomplete')

	discovery_timeout = (os.getenv('DISCOVERY_HOST_TIMEOUT') or '8s').strip() or '8s'
	discovery_retries = (os.getenv('DISCOVERY_MAX_RETRIES') or '2').strip() or '2'
	# Ports used for TCP ping discovery (works better than ICMP on some networks).
	tcp_ports = (os.getenv('DISCOVERY_TCP_PORTS') or '22,80,443,445,3389').strip() or '22,80,443,445,3389'

	# Optional fallback: if discovery returns too few hosts, assume all are up (may be slow).
	min_hosts_raw = (os.getenv('DISCOVERY_MIN_HOSTS') or '').strip()
	try:
		min_hosts = int(min_hosts_raw) if min_hosts_raw else 0
		min_hosts = max(0, min(4096, min_hosts))
	except Exception:
		min_hosts = 0
	allow_full_sweep = (os.getenv('DISCOVERY_FALLBACK_FULL_SWEEP', '0') or '').strip().lower() in ('1', 'true', 'yes', 'on')
	max_full_sweep_hosts_raw = (os.getenv('DISCOVERY_FALLBACK_MAX_HOSTS') or '256').strip()
	try:
		max_full_sweep_hosts = int(max_full_sweep_hosts_raw)
		max_full_sweep_hosts = max(1, min(65536, max_full_sweep_hosts))
	except Exception:
		max_full_sweep_hosts = 256

	def _ping_host(ip: str, timeout_s: int) -> bool:
		try:
			# Linux ping: -c 1 (one packet), -n (numeric), -W seconds (timeout)
			p = subprocess.run(
				['ping', '-n', '-c', '1', '-W', str(timeout_s), ip],
				stdout=subprocess.DEVNULL,
				stderr=subprocess.DEVNULL,
				timeout=max(2, timeout_s + 1),
			)
			return p.returncode == 0
		except Exception:
			return False

	def _ping_sweep(net: str) -> set[str]:
		# Default: enable ping sweep for better coverage (esp. devices that only answer ICMP).
		# Can be disabled via DISCOVERY_PING_SWEEP=false.
		mode = (os.getenv('DISCOVERY_PING_SWEEP', 'true') or '').strip().lower()
		if mode in ('0', 'false', 'no', 'off'):
			return set()
		if mode == 'auto' and is_root:
			# auto means "only when not root" (root can already do ICMP/ARP via nmap)
			return set()

		try:
			n = ipaddress.ip_network(net, strict=False)
		except Exception:
			logger.warning('Ping sweep skipped: invalid network {}', net)
			return set()

		max_hosts_raw = (os.getenv('DISCOVERY_PING_MAX_HOSTS') or '2048').strip()
		try:
			max_hosts = int(max_hosts_raw)
			max_hosts = max(1, min(65536, max_hosts))
		except Exception:
			max_hosts = 2048

		hosts = list(n.hosts())
		if len(hosts) > max_hosts:
			logger.warning('Ping sweep skipped for {}: {} hosts > DISCOVERY_PING_MAX_HOSTS={}', net, len(hosts), max_hosts)
			return set()

		timeout_ms_raw = (os.getenv('DISCOVERY_PING_TIMEOUT_MS') or '1000').strip()
		try:
			timeout_ms = int(timeout_ms_raw)
			timeout_ms = max(200, min(5000, timeout_ms))
		except Exception:
			timeout_ms = 1000
		timeout_s = max(1, int(math.ceil(timeout_ms / 1000.0)))

		conc_raw = (os.getenv('DISCOVERY_PING_CONCURRENCY') or '128').strip()
		try:
			conc = int(conc_raw)
			conc = max(8, min(1024, conc))
		except Exception:
			conc = 128

		logger.info('Ping sweep {} (hosts={}, timeout={}ms, concurrency={})', net, len(hosts), timeout_ms, conc)
		up: set[str] = set()
		with ThreadPoolExecutor(max_workers=conc) as ex:
			futs = {ex.submit(_ping_host, str(ip), timeout_s): str(ip) for ip in hosts}
			for fut in as_completed(futs):
				ip = futs[fut]
				try:
					if fut.result():
						up.add(ip)
				except Exception:
					continue
		logger.info('Ping sweep {}: {} hosts responded', net, len(up))
		return up

	for net in ranges:
		try:
			logger.info('Discovering hosts in {}', net)
			# Discovery strategy:
			# - Root + local subnet: use ARP (-PR) for best coverage + MAC/vendor.
			# - Non-root or non-local: use ICMP + TCP ping to common ports.
			arp_ok = is_root
			args_parts = ['-sn', '-PE', f'-PS{tcp_ports}', f'--host-timeout {discovery_timeout}', f'--max-retries {discovery_retries}']
			if arp_ok:
				args_parts.insert(1, '-PR')
			args = ' '.join(args_parts)
			scanner.scan(hosts=net, arguments=args)
			
			up_count = 0
			for host in scanner.all_hosts():
				if scanner[host].state() == 'up':
					found.add(host)
					up_count += 1
			logger.info('Discovery in {}: {} hosts up', net, up_count)

			# Optional ICMP ping sweep to catch devices that don't respond to TCP probes.
			# Especially helpful when running without root, because Nmap ICMP (-PE) may be unavailable.
			try:
				ping_up = _ping_sweep(net)
				for ip in ping_up:
					found.add(ip)
			except Exception:
				pass

			# Optional fallback: if discovery returns too few hosts, allow a full sweep.
			# WARNING: this can be slow on larger CIDRs.
			if allow_full_sweep and min_hosts > 0 and up_count < min_hosts:
				logger.warning('Discovery returned {} hosts (<{}). Fallback full sweep enabled for {}', up_count, min_hosts, net)
				# Only do this for likely small ranges.
				# For safety, cap at max_full_sweep_hosts by sampling /24-like ranges.
				# (If user wants bigger, they can increase DISCOVERY_FALLBACK_MAX_HOSTS.)
				fallback_args = f'-sn -Pn --host-timeout {discovery_timeout} --max-retries {discovery_retries}'
				# python-nmap will accept CIDR; -Pn will mark all as up.
				# We cap by only taking first N discovered hosts from output.
				scanner.scan(hosts=net, arguments=fallback_args)
				count_added = 0
				for host in scanner.all_hosts():
					if count_added >= max_full_sweep_hosts:
						break
					found.add(host)
					count_added += 1
				logger.info('Fallback sweep added up to {} hosts for {}', count_added, net)
		except Exception:
			logger.exception('Host discovery failed for range {}', net)
	
	total_found = len(found)
	logger.info('Discovery complete: {} total hosts up', total_found)
	return sorted(found)


def _start_db_live_log(manager: MongoDBManager, scan_request_id: str):
	"""Capture scanner logs into scan_requests.live_log (capped).

	This enables the frontend live log even when scans run in the external (root) scanner service.
	"""
	if not scan_request_id:
		return None

	mode = (os.getenv('SCAN_LOG_TO_DB', '1') or '').strip().lower()
	if mode in ('0', 'false', 'no', 'off'):
		return None

	try:
		from bson import ObjectId
		obj_id = ObjectId(scan_request_id)
	except Exception:
		return None

	lock = threading.Lock()
	buffer: list[dict] = []
	stop_flag = {'stop': False}
	last_id = 0
	last_ms = 0
	seq = 0

	def make_id(ts_ms: int) -> int:
		nonlocal last_id, last_ms, seq
		if ts_ms == last_ms:
			seq += 1
		else:
			last_ms = ts_ms
			seq = 0
		# id stays within JS safe integer range
		last_id = ts_ms * 1000 + seq
		return last_id

	def sink(message):
		try:
			rec = message.record
			ts = rec.get('time')
			ts_dt = ts.datetime.replace(tzinfo=timezone.utc) if ts else datetime.now(timezone.utc)
			ts_ms = int(ts_dt.timestamp() * 1000)
			level = rec.get('level').name if rec.get('level') else 'INFO'
			# Use formatted output so exception traces are included.
			formatted = str(message).rstrip('\n')
			if not formatted:
				return
			lines = formatted.splitlines() or ['']
			entries = []
			for line in lines:
				line = str(line).rstrip('\n')
				if not line:
					continue
				entries.append({
					'id': make_id(ts_ms),
					'ts': ts_dt.isoformat(),
					'stream': 'scanner',
					'level': level,
					'text': line,
				})
			if not entries:
				return
			with lock:
				buffer.extend(entries)
		except Exception:
			return

	def flusher():
		while not stop_flag['stop']:
			try:
				batch = None
				with lock:
					if buffer:
						batch = buffer[:]
						buffer.clear()
				if batch:
					manager.db.get_collection('scan_requests').update_one(
						{'_id': obj_id},
						{
							'$push': {
								'live_log': {
									'$each': batch,
									'$slice': -2000,
								}
							},
							'$set': {
								'live_log_last_id': batch[-1]['id'],
								'updated_at': datetime.now(timezone.utc),
							},
						},
					)
			except Exception:
				pass
			time.sleep(0.5)

	thread = threading.Thread(target=flusher, daemon=True)
	thread.start()

	# Write an initial line immediately so the UI doesn't look broken.
	try:
		init_ts = datetime.now(timezone.utc)
		init_ms = int(init_ts.timestamp() * 1000)
		init_entry = {
			'id': make_id(init_ms),
			'ts': init_ts.isoformat(),
			'stream': 'scanner',
			'level': 'INFO',
			'text': 'Live log attached (MongoDB)',
		}
		manager.db.get_collection('scan_requests').update_one(
			{'_id': obj_id},
			{
				'$push': {
					'live_log': {
						'$each': [init_entry],
						'$slice': -2000,
					}
				},
				'$set': {
					'live_log_last_id': init_entry['id'],
					'updated_at': datetime.now(timezone.utc),
				},
			},
		)
	except Exception:
		pass

	try:
		# Include exceptions in formatted output.
		# Use a dedicated log level so DB live logs don't disappear when LOG_LEVEL is set high.
		fmt = '{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {message}{exception}'
		db_level = (os.getenv('SCAN_LOG_DB_LEVEL') or '').strip() or 'INFO'
		sink_id = logger.add(sink, level=db_level, format=fmt)
	except Exception:
		stop_flag['stop'] = True
		return None

	def stop():
		try:
			stop_flag['stop'] = True
			# Flush any remaining lines
			time.sleep(0.6)
			logger.remove(sink_id)
		except Exception:
			pass

	return stop


def _local_ipv4_addresses() -> list[str]:
	"""Return best-effort local IPv4 addresses (non-loopback)."""
	ips: list[str] = []
	try:
		import socket
		hostname = socket.gethostname()
		for res in socket.getaddrinfo(hostname, None):
			addr = res[4][0]
			if addr and '.' in addr and not addr.startswith('127.'):
				ips.append(addr)
	except Exception:
		pass

	# Deduplicate
	seen = set()
	unique: list[str] = []
	for ip in ips:
		if ip in seen:
			continue
		seen.add(ip)
		unique.append(ip)
	return unique


def _is_same_subnet_24(ip: str) -> bool:
	"""Heuristic: treat /24 as local if first 3 octets match any local IPv4."""
	try:
		parts = ip.split('.')
		if len(parts) != 4:
			return False
		prefix = '.'.join(parts[:3])
		for local_ip in _local_ipv4_addresses():
			lp = local_ip.split('.')
			if len(lp) != 4:
				continue
			if '.'.join(lp[:3]) == prefix:
				return True
	except Exception:
		return False
	return False




def _get_scan_request_id() -> str | None:
	raw = (os.getenv('SCAN_REQUEST_ID') or '').strip()
	return raw or None


def _get_scan_environment() -> dict:
	"""Best-effort local scan environment details (not per-device).

	WiFi SSID is only available on the scanning host and only
	if the system has wireless tools installed.
	"""
	env: dict = {}
	# SSID via iwgetid (if present)
	for cmd in (
		['iwgetid', '-r'],
		['iw', 'dev'],
	):
		try:
			p = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
			out = (p.stdout or '').strip()
			if cmd[0] == 'iwgetid' and p.returncode == 0 and out:
				env['wifi_ssid'] = out
				break
			if cmd[0] == 'iw' and p.returncode == 0 and out and 'Interface' in out:
				# Not parsing full iw output here; it can be detailed and varies.
				env['wifi_detected'] = True
				break
		except Exception:
			continue
	return env


def _update_scan_request_progress(db, scan_request_id: str, update: dict) -> None:
	if not scan_request_id:
		return
	try:
		from bson import ObjectId
		obj_id = ObjectId(scan_request_id)
		update = dict(update)
		update['updated_at'] = datetime.now(timezone.utc)
		db.get_collection('scan_requests').update_one({'_id': obj_id}, {'$set': update})
	except Exception:
		# Don't fail scans due to progress reporting issues.
		return


def _scan_host(ip: str, scan_at: datetime, options: dict | None = None) -> dict:
	is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
	scanner = nmap.PortScanner()
	options = options if isinstance(options, dict) else {}

	# Thorough scan by default; can be overridden via request options or SCAN_NMAP_ARGS.
	override = (str(options.get('nmap_args')).strip() if options.get('nmap_args') is not None else (os.getenv('SCAN_NMAP_ARGS') or '').strip())
	top_ports = str(options.get('top_ports')).strip() if options.get('top_ports') is not None else os.getenv('SCAN_TOP_PORTS', '1000')
	host_timeout = str(options.get('host_timeout')).strip() if options.get('host_timeout') is not None else os.getenv('SCAN_HOST_TIMEOUT', '120s')
	max_retries = str(options.get('max_retries')).strip() if options.get('max_retries') is not None else os.getenv('SCAN_MAX_RETRIES', '2')
	try:
		top_ports_n = max(1, min(65535, int(top_ports)))
		max_retries_n = max(0, min(10, int(max_retries)))
		top_ports = str(top_ports_n)
		max_retries = str(max_retries_n)
	except Exception:
		top_ports = '1000'
		max_retries = '2'

	if override:
		args = override
	elif is_root:
		# -A enables OS detection, version detection, scripts, traceroute.
		# Add a few flags that improve reliability + detail for per-host scans.
		args = f'-sS -A --version-all --reason --top-ports {top_ports} -T4 --host-timeout {host_timeout} --max-retries {max_retries}'
	else:
		# Non-root: no SYN scan. Still do service/version detection.
		args = f'-sT -sV --version-all --reason --top-ports {top_ports} -T4 --host-timeout {host_timeout} --max-retries {max_retries}'

	# For per-host scans (we already "discovered" the host), skip host discovery
	# to avoid false negatives when ICMP/TCP probes are filtered.
	assume_up = (str(options.get('assume_up')).strip().lower() if options.get('assume_up') is not None else (os.getenv('SCAN_ASSUME_UP', '1') or '').strip().lower())
	# However, on local subnets ARP-based discovery also yields MAC/vendor.
	# So only force -Pn when the target doesn't look local.
	if assume_up not in ('0', 'false', 'no', 'off') and '-Pn' not in args and not _is_same_subnet_24(ip):
		args = f'{args} -Pn'

	# Optional: let operators cap script runtime (helps on fragile networks).
	script_timeout = (str(options.get('script_timeout')).strip() if options.get('script_timeout') is not None else (os.getenv('SCAN_SCRIPT_TIMEOUT') or '').strip())
	if script_timeout and '--script-timeout' not in args:
		args = f'{args} --script-timeout {script_timeout}'

	device_data: dict = {
		'ip_address': ip,
		'status': 'online',
		'last_seen': scan_at,
		'last_scan': scan_at,
		'last_seen_on': scan_at,
		'last_scan_on': scan_at,
		'scan_profile': {
			'is_root': bool(is_root),
			'nmap_args': args,
		},
	}

	try:
		logger.info('Scanning host {} with args: {}', ip, args)
		scanner.scan(hosts=ip, arguments=args)
		if ip not in scanner.all_hosts():
			logger.warning('Host {} not found in scan results', ip)
			return device_data

		host = scanner[ip]
		try:
			device_data['host_state'] = host.state()
		except Exception:
			pass

		# Don't store raw nmap output - it contains non-string keys that break MongoDB
		# device_data['raw'] = host  # REMOVED - causes BSON errors

		# Host-level script output, traceroute, distance (best-effort)
		for k in ('hostscript', 'traceroute', 'distance'):
			try:
				if host.get(k) is not None:
					device_data[k] = host.get(k)
			except Exception:
				pass

		addresses = host.get('addresses', {})
		device_data['mac_address'] = addresses.get('mac')
		device_data['ipv4_address'] = addresses.get('ipv4') or device_data.get('ip_address')
		device_data['ipv6_address'] = addresses.get('ipv6')

		if not device_data.get('mac_address'):
			device_data['mac_address'] = _best_effort_mac_from_neighbor_table(ip)

		hostnames = host.get('hostnames', [])
		if hostnames:
			device_data['hostname'] = hostnames[0].get('name') or device_data.get('hostname')
		device_data['hostnames'] = [h.get('name') for h in hostnames if h.get('name')]
		if not device_data.get('hostname'):
			rdns = _best_effort_reverse_dns(ip)
			if rdns:
				device_data['hostname'] = rdns

		vendor = host.get('vendor', {})
		if device_data.get('mac_address') and device_data['mac_address'] in vendor:
			device_data['vendor'] = vendor[device_data['mac_address']]

		services = []
		for proto in host.all_protocols():
			ports = host[proto].keys()
			for port in sorted(ports):
				# Convert port to int for processing, then ensure all dict keys are strings
				port_num = int(port)
				svc = host[proto][port]
				services.append({
					'port': port_num,
					'protocol': proto,
					'state': svc.get('state'),
					'reason': svc.get('reason'),
					'name': svc.get('name'),
					'product': svc.get('product'),
					'product_version': svc.get('version'),
					'cpe': svc.get('cpe'),
					'version': (svc.get('product') or '') + ((' ' + svc.get('version')) if svc.get('version') else ''),
					'banner': svc.get('extrainfo'),
					'conf': svc.get('conf'),
					'method': svc.get('method'),
					'tunnel': svc.get('tunnel'),
					# Ensure script results have string keys
					'scripts': {str(k): str(v) for k, v in (svc.get('script') or {}).items()} if svc.get('script') else None,
				})
		if services:
			device_data['services'] = services
			device_data.setdefault('security', {})
			device_data['security']['open_ports_count'] = len({(s['protocol'], s['port']) for s in services})

		# OS / device type info (when available)
		try:
			if host.get('osmatch'):
				device_data['os_matches'] = host.get('osmatch')
				best = host.get('osmatch')[0]
				device_data['os'] = {
					'name': best.get('name'),
					'accuracy': best.get('accuracy'),
					'osclass': best.get('osclass') or [],
				}
				# Try to infer device_type from osclass
				for oc in best.get('osclass') or []:
					if oc.get('type'):
						device_data['device_type'] = device_data.get('device_type') or oc.get('type')
						break
		except Exception:
			pass

		try:
			if host.get('uptime'):
				device_data['uptime'] = host.get('uptime')
		except Exception:
			pass

		# Very basic heuristic if no OS type was found
		if not device_data.get('device_type'):
			inferred = _infer_device_type(device_data)
			if inferred:
				device_data['device_type'] = inferred
			elif any(s.get('name') in ('http', 'https') for s in services):
				device_data['device_type'] = 'server'

		device_data.setdefault('connection_method', 'unknown')

		return device_data
	except Exception:
		logger.exception('nmap scan failed for {}', ip)
		return device_data



def run_scan(
	manager: MongoDBManager,
	reason: str,
	network_ranges: list[str] | None = None,
	options: dict | None = None,
	scan_request_id: str | None = None,
) -> dict:
	ranges = network_ranges if network_ranges is not None else _parse_network_ranges()
	if not ranges:
		logger.warning('NETWORK_RANGES is empty; no scan performed')
		return {'reason': reason, 'error': 'NETWORK_RANGES is empty'}

	scan_request_id = scan_request_id or _get_scan_request_id()
	stop_live_log = _start_db_live_log(manager, scan_request_id) if scan_request_id else None
	scan_id = uuid.uuid4().hex
	record_id = manager.create_scan_record({
		'scan_id': scan_id,
		'scan_request_id': scan_request_id,
		'status': 'running',
		'reason': reason,
		'network_ranges': ', '.join(ranges),
		'environment': _get_scan_environment(),
		'progress': {
			'total_hosts': 0,
			'scanned_hosts': 0,
			'percent': 0,
		},
		'devices': [],
	})

	# Push key scan metadata into scan_requests so the UI can display it live.
	if scan_request_id:
		_update_scan_request_progress(manager.db, scan_request_id, {
			'network_ranges': ', '.join(ranges),
			'environment': _get_scan_environment(),
			'reason': reason,
			'status': 'running',
		})

	started = datetime.now(timezone.utc)
	scan_at = started
	try:
		discovered = _discover_hosts(ranges)
	finally:
		# Ensure early discovery logs get flushed
		pass
	current_ips: list[str] = []
	devices_snapshot: list[dict] = []

	total_hosts = len(discovered)
	if total_hosts == 0:
		logger.warning('Discovery found 0 hosts; completing scan early')
		manager.update_scan_record(record_id, {
			'completed_at': datetime.now(timezone.utc),
			'status': 'completed',
			'statistics': {
				'ranges': ranges,
				'hosts_discovered': 0,
				'devices_upserted': 0,
				'devices_marked_offline': 0,
				'duration_seconds': 0,
			},
		})
		_update_scan_request_progress(manager.db, scan_request_id or '', {
			'completed_at': datetime.now(timezone.utc),
			'progress_percent': 100,
			'status': 'completed',
		})
		return {'scan_id': scan_id, 'status': 'completed', 'statistics': {'hosts_discovered': 0}}

	# Set totals
	manager.update_scan_record(record_id, {
		'progress.total_hosts': total_hosts,
		'discovered_hosts': discovered,
	})
	_update_scan_request_progress(manager.db, scan_request_id or '', {
		'total_hosts': total_hosts,
		'scanned_hosts': 0,
		'progress_percent': 0,
		'scan_history_id': str(record_id),
	})

	for idx, ip in enumerate(discovered, start=1):
		device = _scan_host(ip, scan_at=scan_at, options=options)
		# Sanitize device data to ensure all keys are strings for MongoDB
		device = _sanitize_for_mongodb(device)
		current_ips.append(ip)
		manager.upsert_device(device)
		# Keep a snapshot for scan history detail view
		devices_snapshot.append(device)

		# Update progress frequently so UI shows real-time % and devices found
		percent = int((idx / total_hosts) * 100)
		manager.update_scan_record(record_id, {
			'progress.scanned_hosts': idx,
			'progress.percent': percent,
			'devices': devices_snapshot,  # Live update devices in scan_history
		})
		_update_scan_request_progress(manager.db, scan_request_id or '', {
			'scanned_hosts': idx,
			'progress_percent': percent,
		})
		logger.info('Scanned {}/{} ({}%): {}', idx, total_hosts, percent, ip)

	offline_count = manager.mark_devices_offline(current_ips)
	completed = datetime.now(timezone.utc)

	stats = {
		'ranges': ranges,
		'hosts_discovered': len(discovered),
		'devices_upserted': len(current_ips),
		'devices_marked_offline': offline_count,
		'duration_seconds': int((completed - started).total_seconds()),
	}

	manager.update_scan_record(record_id, {
		'completed_at': completed,
		'status': 'completed',
		'statistics': stats,
		'devices': devices_snapshot,
	})
	_update_scan_request_progress(manager.db, scan_request_id or '', {
		'completed_at': completed,
		'progress_percent': 100,
		'status': 'completed',
		'scan_id': scan_id,
		'statistics': stats,
	})

	logger.info('Scan complete: {}', stats)
	try:
		return {'scan_id': scan_id, 'status': 'completed', 'statistics': stats}
	finally:
		if stop_live_log:
			stop_live_log()


def _claim_pending_scan_request(db):
	return db.get_collection('scan_requests').find_one_and_update(
		{'status': 'queued'},
		{'$set': {'status': 'running', 'started_at': datetime.now(timezone.utc)}},
		sort=[('requested_at', 1)],
		return_document=ReturnDocument.AFTER,
	)


def main() -> int:
	_load_environment()
	_configure_logging()

	logger.info('NetLens scanner service starting...')

	run_once = ('--run-once' in sys.argv)

	manager = MongoDBManager()
	scheduler = BackgroundScheduler(daemon=True)
	scheduler.start()

	scan_lock = threading.Lock()

	def run_scan_guarded(reason: str) -> dict:
		if not scan_lock.acquire(blocking=False):
			raise RuntimeError('Scan already running')
		try:
			return run_scan(manager, reason=reason)
		finally:
			scan_lock.release()

	current_schedule_fingerprint = None

	def ensure_schedule():
		nonlocal current_schedule_fingerprint

		trigger = _get_schedule_from_db(manager.db)
		if trigger == 'disabled':
			fingerprint = ('disabled',)
		elif trigger is None:
			trigger = _get_schedule_from_env()
			if trigger == 'disabled':
				fingerprint = ('disabled',)
			else:
				fingerprint = ('env', str(trigger))
		else:
			fingerprint = ('db', str(trigger))

		if fingerprint == current_schedule_fingerprint:
			return

		current_schedule_fingerprint = fingerprint

		# Replace scheduled job
		try:
			scheduler.remove_job('scheduled_scan')
		except Exception:
			pass

		if fingerprint == ('disabled',):
			logger.info('Scheduled scans disabled')
			return

		scheduler.add_job(
			lambda: run_scan_guarded(reason='scheduled'),
			trigger=trigger,
			id='scheduled_scan',
			max_instances=1,
			coalesce=True,
			misfire_grace_time=300,
		)
		logger.info('Scheduled scans configured: {}', fingerprint)

	ensure_schedule()

	if run_once:
		run_scan_guarded(reason='manual_cli')
		return 0

	last_schedule_check = 0.0
	try:
		while True:
			# Heartbeat so the API can detect that the privileged scanner is alive.
			try:
				manager.db.get_collection('settings').update_one(
					{'_id': 'scanner_heartbeat'},
					{'$set': {
						'updated_at': datetime.now(timezone.utc),
						'pid': os.getpid(),
						'uid': (os.geteuid() if hasattr(os, 'geteuid') else None),
						'run_once': bool(run_once),
					}},
					upsert=True,
				)
			except Exception:
				pass

			# Poll scan requests from API/UI
			req = _claim_pending_scan_request(manager.db)
			if req:
				req_id = str(req.get('_id'))
				logger.info('Picked up scan request {}', req_id)
				try:
					raw_ranges = req.get('network_ranges')
					override_ranges = _parse_network_ranges_raw(raw_ranges)
					options = req.get('options') if isinstance(req.get('options'), dict) else None

					# Ensure UI sees the requested ranges even when scanner is daemonized.
					if override_ranges:
						_update_scan_request_progress(manager.db, req_id, {
							'network_ranges': ', '.join(override_ranges),
						})

					# Run scan with request-specific overrides.
					if not scan_lock.acquire(blocking=False):
						raise RuntimeError('Scan already running')
					try:
						result = run_scan(
							manager,
							reason='manual_request',
							network_ranges=(override_ranges or None),
							options=options,
							scan_request_id=req_id,
						)
					finally:
						scan_lock.release()

					logger.info('Manual scan request completed: {}', result)
					manager.db.get_collection('scan_requests').update_one(
						{'_id': req['_id']},
						{'$set': {
							'status': 'completed',
							'completed_at': datetime.now(timezone.utc),
							'result': result or {},
							'error': None,
						}}
					)
				except Exception as e:
					logger.exception('Manual scan request failed {}', req_id)
					manager.db.get_collection('scan_requests').update_one(
						{'_id': req['_id']},
						{'$set': {
							'status': 'failed',
							'completed_at': datetime.now(timezone.utc),
							'result': {},
							'error': str(e),
						}}
					)

			# Periodically re-check schedule settings
			now = time.time()
			if now - last_schedule_check > 60:
				last_schedule_check = now
				ensure_schedule()

			time.sleep(5)
	finally:
		try:
			scheduler.shutdown(wait=False)
		except Exception:
			pass
		manager.close()

	return 0


if __name__ == '__main__':
	raise SystemExit(main())

