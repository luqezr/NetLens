
import os
import sys
import time
import uuid
from datetime import datetime, timezone
import threading
import subprocess
import json
import re
import ipaddress
import shutil
import xml.etree.ElementTree as ET
from functools import lru_cache
from typing import Optional

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
	log_file = os.getenv('LOG_FILE', '/opt/netlens/logs/scanner.log')
	log_level = os.getenv('LOG_LEVEL', 'INFO')

	logger.remove()
	logger.add(sys.stderr, level=log_level)
	try:
		os.makedirs(os.path.dirname(log_file), exist_ok=True)
		logger.add(log_file, rotation='10 MB', retention='14 days', level=log_level)
		return
	except PermissionError:
		# Common when scans are launched unprivileged and /opt/netlens/logs is not writable.
		# Fall back to /tmp without emitting a scary traceback.
		fallback = f"/tmp/netlens-scanner-{os.getpid()}.log"
		try:
			logger.add(fallback, rotation='10 MB', retention='14 days', level=log_level)
			logger.warning('File logging disabled for {} (permission denied); using {}', log_file, fallback)
			return
		except Exception:
			logger.warning('File logging disabled (permission denied) and fallback failed; stderr only')
			return
	except Exception as e:
		# If file logging fails, keep stderr logging.
		logger.warning('Failed to configure file logging ({}); stderr only', str(e))
		return


def _update_scanner_heartbeat(db, is_root: bool) -> None:
	"""Best-effort heartbeat so the API can detect a privileged external scanner worker."""
	try:
		db.get_collection('scanner_heartbeat').update_one(
			{'_id': 'scanner'},
			{'$set': {
				'ts': datetime.now(timezone.utc),
				'pid': os.getpid(),
				'is_root': bool(is_root),
				'hostname': (os.uname().nodename if hasattr(os, 'uname') else None),
			}},
			upsert=True,
		)
	except Exception:
		return


def _parse_network_ranges() -> list[str]:
	raw = os.getenv('NETWORK_RANGES', '').strip()
	if not raw:
		return []
	parts = [p.strip() for p in raw.replace(';', ',').split(',')]
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


# Best-effort discovery hints (MAC/vendor) captured during the ping sweep.
_DISCOVERY_HINTS: dict[str, dict] = {}


_LOCAL_NETS_CACHE: list[ipaddress.IPv4Network] = []
_LOCAL_NETS_CACHE_AT: float = 0.0


def _local_ipv4_networks(ttl_seconds: int = 60) -> list[ipaddress.IPv4Network]:
	"""Return best-effort local IPv4 networks for deciding whether a target is L2-local.

	Uses `ip addr` when available; falls back to /24 heuristics.
	"""
	global _LOCAL_NETS_CACHE, _LOCAL_NETS_CACHE_AT
	try:
		if _LOCAL_NETS_CACHE and (time.time() - _LOCAL_NETS_CACHE_AT) < ttl_seconds:
			return list(_LOCAL_NETS_CACHE)
	except Exception:
		pass

	nets: list[ipaddress.IPv4Network] = []
	try:
		p = subprocess.run(['ip', '-o', '-f', 'inet', 'addr', 'show'], capture_output=True, text=True, timeout=2)
		out = (p.stdout or '').splitlines()
		for line in out:
			m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b', line)
			if not m:
				continue
			try:
				iface = ipaddress.IPv4Interface(m.group(1))
				if iface.ip.is_loopback:
					continue
				nets.append(iface.network)
			except Exception:
				continue
	except Exception:
		pass

	if not nets:
		# Fallback: assume /24 networks for any discovered local IPv4 addresses.
		try:
			for ip in _local_ipv4_addresses():
				try:
					iface = ipaddress.IPv4Interface(f'{ip}/24')
					nets.append(iface.network)
				except Exception:
					continue
		except Exception:
			pass

	# Deduplicate
	unique: dict[str, ipaddress.IPv4Network] = {}
	for n in nets:
		unique[str(n)] = n

	_LOCAL_NETS_CACHE = list(unique.values())
	_LOCAL_NETS_CACHE_AT = time.time()
	return list(_LOCAL_NETS_CACHE)


def _is_local_target(ip: str) -> bool:
	try:
		target = ipaddress.ip_address(ip)
		if not isinstance(target, ipaddress.IPv4Address):
			return False
		for net in _local_ipv4_networks():
			try:
				if target in net:
					return True
			except Exception:
				continue
		return False
	except Exception:
		return False


def _neighbor_mac(ip: str) -> Optional[str]:
	"""Best-effort MAC from OS neighbor table (ARP/ND)."""
	try:
		p = subprocess.run(['ip', 'neigh', 'show', ip], capture_output=True, text=True, timeout=2)
		out = (p.stdout or '').strip()
		m = re.search(r'\blladdr\s+([0-9a-fA-F:]{17})\b', out)
		if m:
			return m.group(1)
	except Exception:
		pass
	return None


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
	if not mac:
		return None
	s = str(mac).strip().upper()
	if not s:
		return None
	# Remove separators.
	s = re.sub(r'[^0-9A-F]', '', s)
	if len(s) < 6:
		return None
	return s


@lru_cache(maxsize=1)
def _load_nmap_mac_db() -> tuple[dict[str, str], list[int]]:
	"""Load Nmap's MAC prefix database for vendor lookups."""
	candidates = [
		'/usr/share/nmap/nmap-mac-prefixes',
		'/usr/local/share/nmap/nmap-mac-prefixes',
	]
	mapping: dict[str, str] = {}
	lengths: set[int] = set()
	for p in candidates:
		if not os.path.exists(p):
			continue
		try:
			with open(p, 'r', encoding='utf-8', errors='ignore') as f:
				for line in f:
					line = line.strip()
					if not line or line.startswith('#'):
						continue
					parts = line.split(None, 1)
					if len(parts) < 2:
						continue
					prefix = parts[0].strip().upper()
					vendor = parts[1].strip()
					if not prefix or not vendor:
						continue
					if not re.fullmatch(r'[0-9A-F]+', prefix):
						continue
					mapping[prefix] = vendor
					lengths.add(len(prefix))
			return mapping, sorted(lengths, reverse=True)
		except Exception:
			continue
	return mapping, sorted(lengths, reverse=True)


def _lookup_mac_vendor(mac: Optional[str]) -> Optional[str]:
	norm = _normalize_mac(mac)
	if not norm:
		return None
	mapping, lengths = _load_nmap_mac_db()
	if not mapping:
		return None
	for ln in lengths:
		if ln <= len(norm):
			prefix = norm[:ln]
			if prefix in mapping:
				return mapping[prefix]
	# Common OUI length fallback
	if len(norm) >= 6 and norm[:6] in mapping:
		return mapping[norm[:6]]
	return None


def _infer_os_family_from_name(name: Optional[str]) -> Optional[str]:
	"""Best-effort OS family inference from an Nmap osmatch name."""
	if not name:
		return None
	s = str(name).lower()
	if 'windows' in s:
		return 'Windows'
	if 'linux' in s:
		return 'Linux'
	if 'android' in s:
		return 'Android'
	if 'ios' in s or 'iphone' in s or 'ipad' in s:
		return 'iOS'
	if 'mac os' in s or 'macos' in s or 'os x' in s:
		return 'macOS'
	if 'freebsd' in s:
		return 'FreeBSD'
	if 'openbsd' in s:
		return 'OpenBSD'
	if 'netbsd' in s:
		return 'NetBSD'
	return None


def _infer_device_type(device_data: dict) -> Optional[str]:
	"""Best-effort device type inference using OS, ports, and vendor."""
	vendor = str(device_data.get('vendor') or '').lower()
	os_obj = device_data.get('os')
	os_name = ''
	osclasses = []
	if isinstance(os_obj, dict):
		os_name = str(os_obj.get('name') or '').lower()
		osclasses = os_obj.get('osclass') or []
	elif isinstance(os_obj, str):
		os_name = os_obj.lower()

	# Strong signals from nmap osclass
	try:
		for oc in osclasses:
			if isinstance(oc, dict) and oc.get('type'):
				return str(oc.get('type'))
	except Exception:
		pass

	services = device_data.get('services') or []
	ports: set[int] = set()
	names: set[str] = set()
	try:
		for s in services:
			if not isinstance(s, dict):
				continue
			p = s.get('port')
			if isinstance(p, int):
				ports.add(p)
			name = s.get('name')
			if name:
				names.add(str(name).lower())
	except Exception:
		pass

	# Mobile
	if 'android' in os_name or 'iphone' in os_name or 'ios' in os_name:
		return 'mobile'
	if any(k in vendor for k in ('apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'motorola')):
		return 'mobile'

	# Printers
	if 9100 in ports or 515 in ports or 'ipp' in names or 'printer' in names:
		return 'printer'

	# Cameras / IoT-ish
	if 554 in ports or 'rtsp' in names:
		return 'camera'

	# Network gear
	if any(k in vendor for k in ('ubiquiti', 'aruba', 'ruckus', 'mikrotik', 'cisco', 'juniper', 'tp-link', 'netgear', 'd-link', 'linksys', 'asus')):
		if any(p in ports for p in (22, 23, 80, 443, 161, 8291)):
			return 'network device'

	# Workstations
	if 445 in ports or 139 in ports or 3389 in ports:
		return 'workstation'

	# Servers
	if 'http' in names or 'https' in names:
		return 'server'

	return None


def _infer_connection_method(device_data: dict) -> str:
	"""Very rough estimation: wired/wireless/unknown."""
	vendor = str(device_data.get('vendor') or '').lower()
	os_obj = device_data.get('os')
	os_name = ''
	if isinstance(os_obj, dict):
		os_name = str(os_obj.get('name') or '').lower()
	elif isinstance(os_obj, str):
		os_name = os_obj.lower()
	device_type = str(device_data.get('device_type') or '').lower()

	if device_type in ('mobile', 'phone', 'tablet') or 'android' in os_name or 'iphone' in os_name or 'ios' in os_name:
		return 'wireless'
	if any(k in vendor for k in ('apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'motorola')):
		return 'wireless'
	if device_type in ('printer', 'server', 'workstation', 'network device', 'router', 'switch'):
		return 'wired'
	return 'unknown'


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


def _discover_hosts(ranges: list[str], log_cb=None) -> list[str]:
	if not ranges:
		return []

	def _log(level: str, message: str) -> None:
		try:
			if level == 'warning':
				logger.warning(message)
			elif level == 'error':
				logger.error(message)
			else:
				logger.info(message)
		except Exception:
			pass
		try:
			if callable(log_cb):
				log_cb(level, message)
		except Exception:
			pass

	def _nmap_ping_sweep_xml(net: str, local: bool, timeout_seconds: int) -> tuple[list[str], dict[str, dict]]:
		"""Run an nmap ping sweep and parse XML output.

		Returns (up_hosts, hints_by_ip) where hints may include mac_address/vendor.
		"""
		if not shutil.which('nmap'):
			return [], {}

		is_root = False
		try:
			is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
		except Exception:
			is_root = False

		base_args = [
			'-sn',
			'-n',
			'-PE',
			'-PP',
			'-PS21,22,23,25,53,80,110,139,143,443,445,3389,8080',
			'-PA80,443,445,3389',
			'-T4',
			'--max-retries', '2',
			'--host-timeout', '8s',
		]
		# ARP ping only works on L2-local ranges and typically requires root.
		if local and is_root:
			base_args.append('-PR')

		cmd = ['nmap', *base_args, '-oX', '-', net]
		try:
			p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, int(timeout_seconds)))
		except subprocess.TimeoutExpired:
			raise
		except Exception:
			return [], {}

		xml_text = (p.stdout or '').strip()
		if not xml_text:
			return [], {}

		up_hosts: list[str] = []
		hints: dict[str, dict] = {}
		try:
			root = ET.fromstring(xml_text)
			for host in root.findall('host'):
				status = host.find('status')
				if status is None or status.get('state') != 'up':
					continue
				ipv4 = None
				mac = None
				vendor = None
				for addr in host.findall('address'):
					type_ = addr.get('addrtype')
					if type_ == 'ipv4':
						ipv4 = addr.get('addr')
					elif type_ == 'mac':
						mac = addr.get('addr')
						vendor = addr.get('vendor')
				if ipv4:
					up_hosts.append(ipv4)
					if mac or vendor:
						hints[ipv4] = {
							'mac_address': mac,
							'vendor': vendor,
						}
			return up_hosts, hints
		except Exception:
			return [], {}
	found: set[str] = set()

	# Local network map for deciding whether ARP ping is applicable.
	local_nets = []
	try:
		local_nets = _local_ipv4_networks(ttl_seconds=60)
	except Exception:
		local_nets = []

	def _is_local_range(cidr: str) -> bool:
		try:
			n = ipaddress.ip_network(str(cidr).strip(), strict=False)
			for ln in local_nets:
				try:
					if n.overlaps(ln):
						return True
				except Exception:
					continue
			return False
		except Exception:
			return False

	for net in ranges:
		try:
			net = str(net).strip()
			if not net:
				continue

			local = _is_local_range(net)
			if not local:
				_log('warning', f'Range {net} is not directly connected to this host; ARP discovery may not work (routing/VLAN)')

			_log('info', f'Discovering hosts in {net}')

			# Hard timeout so discovery can't hang indefinitely.
			# Default scales mildly with subnet size.
			try:
				n = ipaddress.ip_network(net, strict=False)
				hosts = max(0, int(getattr(n, 'num_addresses', 0)) - 2)
			except Exception:
				hosts = 256
			base_timeout = int(os.getenv('DISCOVERY_NMAP_TIMEOUT_SECONDS', '0') or 0)
			if base_timeout <= 0:
				# ~30s min, ~180s max for common ranges
				timeout_s = max(30, min(180, int(30 + hosts / 4)))
			else:
				timeout_s = max(10, min(900, base_timeout))

			up_hosts: list[str] = []
			hints: dict[str, dict] = {}
			try:
				up_hosts, hints = _nmap_ping_sweep_xml(net, local=local, timeout_seconds=timeout_s)
			except subprocess.TimeoutExpired:
				_log('warning', f'Discovery in {net} timed out after ~{timeout_s}s; falling back')
				up_hosts, hints = [], {}

			for host in up_hosts:
				found.add(host)
				if host in hints:
					try:
						_DISCOVERY_HINTS[host] = hints[host]
					except Exception:
						pass

			up_count = len(up_hosts)
			_log('info', f'Discovery in {net}: {up_count} hosts up')

			# If this range found nothing, try a slower/more permissive probe.
			if up_count == 0:
				try:
					fallback_timeout = int(os.getenv('DISCOVERY_NMAP_FALLBACK_TIMEOUT_SECONDS', '0') or 0)
					if fallback_timeout <= 0:
						fallback_timeout = max(45, min(240, timeout_s + 45))
					up2, _ = _nmap_ping_sweep_xml(net, local=local, timeout_seconds=fallback_timeout)
					for host in up2:
						found.add(host)
					_log('info', f'Discovery fallback in {net}: {len(up2)} hosts up')
				except Exception:
					pass
		except Exception:
			try:
				logger.exception('Host discovery failed for range {}', net)
			except Exception:
				pass

	total_found = len(found)
	_log('info', f'Discovery complete: {total_found} total hosts up')

	# If discovery found nothing, optionally fall back to a limited "assume up" sweep.
	# This helps on networks where ping probes are blocked.
	if not found:
		fallback_on = (os.getenv('DISCOVERY_FALLBACK_ASSUME_UP', '1') or '').strip().lower() not in ('0', 'false', 'no', 'off')
		max_hosts = os.getenv('DISCOVERY_FALLBACK_MAX_HOSTS', '256')
		try:
			max_hosts_n = max(1, min(4096, int(max_hosts)))
		except Exception:
			max_hosts_n = 256

		if fallback_on:
			candidates: list[str] = []
			for net in ranges:
				try:
					n = ipaddress.ip_network(str(net).strip(), strict=False)
					# Limit enumeration to avoid massive subnets.
					for i, ip in enumerate(n.hosts()):
						if i >= max_hosts_n:
							break
						candidates.append(str(ip))
				except Exception:
					continue

			# De-dupe while preserving order.
			seen = set()
			unique: list[str] = []
			for ip in candidates:
				if ip in seen:
					continue
				seen.add(ip)
				unique.append(ip)
			logger.warning('Discovery found 0 hosts; falling back to limited assume-up sweep ({} hosts)', len(unique))
			return unique

	return sorted(found)


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
	"""Back-compat name: treat target as local if it belongs to any local IPv4 interface CIDR."""
	return _is_local_target(ip)


def _append_scan_log(db, scan_request_id: Optional[str], stream: str, text: str) -> None:
	"""Append a log line for the current scan request (for UI live log).

	Uses an atomic per-request sequence counter (scan_requests.log_seq) so the UI
	can page with a numeric cursor.
	"""
	if not scan_request_id:
		return
	try:
		from bson import ObjectId
		obj_id = ObjectId(scan_request_id)
		res = db.get_collection('scan_requests').find_one_and_update(
			{'_id': obj_id},
			{'$inc': {'log_seq': 1}},
			return_document=ReturnDocument.AFTER,
		)
		seq = int(res.get('log_seq') or 0) if isinstance(res, dict) else 0
		if seq <= 0:
			return
		db.get_collection('scan_logs').insert_one({
			'request_id': obj_id,
			'scan_id': (res.get('scan_id') if isinstance(res, dict) else None),
			'seq': seq,
			'ts': datetime.now(timezone.utc),
			'stream': str(stream or 'info'),
			'text': str(text or ''),
		})
	except Exception:
		return


def _apply_request_options(options: Optional[dict]):
	"""Temporarily apply scan options (from scan_requests.options) to env vars."""
	if not options or not isinstance(options, dict):
		return None
	keys = {
		'nmap_args': 'SCAN_NMAP_ARGS',
		'top_ports': 'SCAN_TOP_PORTS',
		'host_timeout': 'SCAN_HOST_TIMEOUT',
		'max_retries': 'SCAN_MAX_RETRIES',
		'assume_up': 'SCAN_ASSUME_UP',
		'script_timeout': 'SCAN_SCRIPT_TIMEOUT',
		'nmap_scripts': 'SCAN_NMAP_SCRIPTS',
		'log_level': 'LOG_LEVEL',
	}
	prior: dict[str, Optional[str]] = {}
	for opt_key, env_key in keys.items():
		if opt_key not in options:
			continue
		prior[env_key] = os.getenv(env_key)
		val = options.get(opt_key)
		if val is None:
			if env_key in os.environ:
				del os.environ[env_key]
		else:
			os.environ[env_key] = str(val)

	def restore():
		for env_key, old in prior.items():
			if old is None:
				if env_key in os.environ:
					del os.environ[env_key]
			else:
				os.environ[env_key] = old
	return restore




def _get_scan_request_id() -> Optional[str]:
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


def _scan_host(ip: str, scan_at: datetime) -> dict:
	is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
	scanner = nmap.PortScanner()

	# Thorough scan by default; can be overridden via SCAN_NMAP_ARGS.
	override = (os.getenv('SCAN_NMAP_ARGS') or '').strip()
	# Optional: NSE script selectors (e.g. "vuln" or "vuln or safe").
	# Empty/"off" disables adding a --script arg automatically.
	nmap_scripts = (os.getenv('SCAN_NMAP_SCRIPTS') or '').strip()
	top_ports = os.getenv('SCAN_TOP_PORTS', '1000')
	host_timeout = os.getenv('SCAN_HOST_TIMEOUT', '120s')
	max_retries = os.getenv('SCAN_MAX_RETRIES', '2')
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
		args = f'-sS -A --version-all --reason --osscan-guess --max-os-tries 2 --top-ports {top_ports} -T4 --host-timeout {host_timeout} --max-retries {max_retries}'
	else:
		# Non-root: no SYN scan. Still do service/version detection.
		args = f'-sT -sV --version-all --reason --top-ports {top_ports} -T4 --host-timeout {host_timeout} --max-retries {max_retries}'

	# Add vulnerability scripts unless the operator overrides args entirely.
	# Default is "vuln" to surface CVEs/known issues, but allow disabling.
	if not override:
		if not nmap_scripts:
			nmap_scripts = 'vuln'
		if nmap_scripts.lower() not in ('0', 'off', 'false', 'disable', 'disabled', 'none'):
			if '--script' not in args:
				selector = str(nmap_scripts).strip()
				# If the selector contains spaces/operators, quote it so nmap treats it as one expression.
				if any(ch.isspace() for ch in selector) and not (
					(selector.startswith('"') and selector.endswith('"')) or
					(selector.startswith("'") and selector.endswith("'"))
				):
					selector = selector.replace('"', '\\"')
					args = f'{args} --script "{selector}"'
				else:
					args = f'{args} --script {selector}'

	# For per-host scans (we already "discovered" the host), skip host discovery
	# to avoid false negatives when ICMP/TCP probes are filtered.
	assume_up = (os.getenv('SCAN_ASSUME_UP', '1') or '').strip().lower()
	# However, on local subnets ARP-based discovery also yields MAC/vendor.
	# So only force -Pn when the target doesn't look local.
	if assume_up not in ('0', 'false', 'no', 'off') and '-Pn' not in args and not _is_local_target(ip):
		args = f'{args} -Pn'

	# Optional: let operators cap script runtime (helps on fragile networks).
	script_timeout = (os.getenv('SCAN_SCRIPT_TIMEOUT') or '').strip()
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

		# Fill MAC/vendor from discovery hints or neighbor table if Nmap didn't report it.
		hint = _DISCOVERY_HINTS.get(ip) or {}
		if not device_data.get('mac_address'):
			device_data['mac_address'] = hint.get('mac_address')
		if not device_data.get('vendor') and hint.get('vendor'):
			device_data['vendor'] = hint.get('vendor')
		if not device_data.get('mac_address') and _is_local_target(ip):
			mac2 = _neighbor_mac(ip)
			if mac2:
				device_data['mac_address'] = mac2

		hostnames = host.get('hostnames', [])
		if hostnames:
			device_data['hostname'] = hostnames[0].get('name') or device_data.get('hostname')
		device_data['hostnames'] = [h.get('name') for h in hostnames if h.get('name')]

		vendor = host.get('vendor', {})
		if device_data.get('mac_address') and isinstance(vendor, dict) and device_data['mac_address'] in vendor:
			device_data['vendor'] = vendor[device_data['mac_address']]
		# MAC vendor lookup fallback
		if device_data.get('mac_address') and not device_data.get('vendor'):
			v2 = _lookup_mac_vendor(device_data.get('mac_address'))
			if v2:
				device_data['vendor'] = v2

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

		# Extract CVEs from NSE script output (service-level + host-level).
		# Note: NSE scripts often print "IDs: CVE:..." or include CVE strings inline.
		cve_set: set[str] = set()
		try:
			# Host scripts:
			for hs in host.get('hostscript') or []:
				out = (hs.get('output') or '') if isinstance(hs, dict) else str(hs)
				for c in re.findall(r'\bCVE-\d{4}-\d{4,7}\b', out, flags=re.IGNORECASE):
					cve_set.add(c.upper())
		except Exception:
			pass
		try:
			# Service scripts:
			for svc in services:
				scripts = svc.get('scripts') or {}
				if not isinstance(scripts, dict):
					continue
				for out in scripts.values():
					for c in re.findall(r'\bCVE-\d{4}-\d{4,7}\b', str(out), flags=re.IGNORECASE):
						cve_set.add(c.upper())
		except Exception:
			pass
		if cve_set:
			device_data.setdefault('security', {})
			device_data['security']['cves'] = sorted(cve_set)
			device_data['security']['cve_count'] = len(cve_set)

		# OS / device type info (when available)
		try:
			if host.get('osmatch'):
				device_data['os_matches'] = host.get('osmatch')
				best = host.get('osmatch')[0]
				osclasses = best.get('osclass') or []
				best_class = None
				try:
					best_class = sorted(
						[c for c in osclasses if isinstance(c, dict)],
						key=lambda c: int(c.get('accuracy') or 0),
						reverse=True,
					)[0] if osclasses else None
				except Exception:
					best_class = None

				best_name = best.get('name')
				os_obj = {
					'name': best_name,
					'accuracy': best.get('accuracy'),
					'osclass': osclasses,
				}
				if isinstance(best_class, dict):
					os_obj['vendor'] = best_class.get('vendor')
					os_obj['family'] = best_class.get('osfamily')
					os_obj['type'] = best_class.get('type')
					os_obj['gen'] = best_class.get('osgen')
					if best_class.get('osgen'):
						os_obj['version'] = str(best_class.get('osgen'))

				# Ensure we always have a human-friendly label.
				if not os_obj.get('family'):
					inf = _infer_os_family_from_name(best_name)
					if inf:
						os_obj['family'] = inf
				if not os_obj.get('name'):
					fam = os_obj.get('family')
					gen = os_obj.get('gen') or os_obj.get('version')
					if fam and gen:
						os_obj['name'] = f"{fam} {gen}"
					elif fam:
						os_obj['name'] = str(fam)

				device_data['os'] = os_obj
		except Exception:
			pass

		try:
			if host.get('uptime'):
				device_data['uptime'] = host.get('uptime')
		except Exception:
			pass

		# Device type inference (prefer fresh inference each scan)
		try:
			inferred = _infer_device_type(device_data)
			if inferred:
				device_data['device_type'] = inferred
		except Exception:
			pass

		# Connection type estimation (best-effort)
		try:
			device_data['connection_method'] = _infer_connection_method(device_data)
		except Exception:
			device_data.setdefault('connection_method', 'unknown')

		return device_data
	except Exception:
		logger.exception('nmap scan failed for {}', ip)
		return device_data


def run_scan(manager: MongoDBManager, reason: str, scan_request_id: Optional[str] = None, network_ranges: Optional[str] = None) -> dict:
	def _auto_detect_ranges() -> list[str]:
		"""Best-effort local CIDR detection.

		Prefers the actual interface CIDRs (via `_local_ipv4_networks()`), but clamps
		very large networks down to /24 for safety.
		"""
		try:
			nets = _local_ipv4_networks(ttl_seconds=10)
		except Exception:
			nets = []
		out: list[str] = []
		seen = set()
		for n in nets:
			try:
				if not isinstance(n, ipaddress.IPv4Network):
					continue
				# Skip loopback.
				if n.network_address.is_loopback:
					continue
				# Clamp very large subnets to /24 to avoid accidental /16+/0 scans.
				if n.prefixlen < 24:
					clamped = ipaddress.IPv4Network(f"{n.network_address}/24", strict=False)
					s = str(clamped)
				else:
					s = str(n)
				if s in seen:
					continue
				seen.add(s)
				out.append(s)
			except Exception:
				continue
		return out

	# Determine scan target ranges.
	if network_ranges:
		ranges = [p.strip() for p in str(network_ranges).replace(';', ',').split(',') if p.strip()]
	else:
		ranges = _parse_network_ranges()
	if not ranges and str(reason or '').strip().lower() == 'scheduled':
		ranges = _auto_detect_ranges()
		if ranges:
			logger.info('Auto-detected ranges for scheduled scan: {}', ', '.join(ranges))
	if not ranges:
		logger.warning('NETWORK_RANGES is empty; no scan performed')
		return {'reason': reason, 'error': 'NETWORK_RANGES is empty'}

	if not scan_request_id:
		scan_request_id = _get_scan_request_id()
	scan_id = uuid.uuid4().hex
	_append_scan_log(manager.db, scan_request_id, 'info', f"Scan starting (reason={reason}, ranges={', '.join(ranges)})")
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
			'scan_id': scan_id,
			'progress.phase': 'starting',
		})

	started = datetime.now(timezone.utc)
	scan_at = started
	_append_scan_log(manager.db, scan_request_id, 'info', 'Discovering hosts...')
	_update_scan_request_progress(manager.db, scan_request_id or '', {
		'progress.phase': 'discovering',
		'progress_percent': 0,
	})
	discovered = _discover_hosts(
		ranges,
		log_cb=lambda level, msg: _append_scan_log(manager.db, scan_request_id, level, msg),
	)
	# Track which IPs were targeted vs which were confirmed up.
	scanned_targets: list[str] = []
	up_ips: list[str] = []
	devices_snapshot: list[dict] = []

	total_hosts = len(discovered)
	_append_scan_log(manager.db, scan_request_id, 'info', f"Discovered {total_hosts} hosts")
	if total_hosts == 0:
		logger.warning('Discovery found 0 hosts; completing scan early')
		completed0 = datetime.now(timezone.utc)
		duration0 = int((completed0 - started).total_seconds())
		_append_scan_log(manager.db, scan_request_id, 'warning', 'Discovery found 0 hosts. Check NETWORK_RANGES / routing / ICMP filtering. Completing scan.')
		manager.update_scan_record(record_id, {
			'completed_at': completed0,
			'status': 'completed',
			'progress.percent': 100,
			'progress.scanned_hosts': 0,
			'statistics': {
				'ranges': ranges,
				'hosts_discovered': 0,
				'devices_upserted': 0,
				'devices_marked_offline': 0,
				'duration_seconds': duration0,
			},
		})
		_update_scan_request_progress(manager.db, scan_request_id or '', {
			'completed_at': completed0,
			'progress_percent': 100,
			'total_hosts': 0,
			'scanned_hosts': 0,
			'status': 'completed',
			'progress.phase': 'completed',
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
		'progress.phase': 'scanning',
	})

	# Treat discovery output as scan targets. Some discovery modes (assume-up fallback)
	# may include candidates that are not actually up.
	scanned_targets = list(discovered)

	for idx, ip in enumerate(scanned_targets, start=1):
		_append_scan_log(manager.db, scan_request_id, 'info', f"Scanning {ip} ({idx}/{total_hosts})")
		device = _scan_host(ip, scan_at=scan_at)
		# Sanitize device data to ensure all keys are strings for MongoDB
		device = _sanitize_for_mongodb(device)

		host_state = str(device.get('host_state') or '').strip().lower()
		is_up = host_state == 'up'
		if is_up:
			up_ips.append(ip)
			manager.upsert_device(device)
			# Keep a snapshot for scan history detail view (only confirmed devices)
			devices_snapshot.append(device)
		else:
			# Don't persist "ghost" devices for targets that are not confirmed up.
			pass

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

	# Mark devices offline only within this scan's target set, and only if they were previously online.
	# This avoids flipping unrelated devices offline when scanning an alternate range.
	offline_count = 0
	try:
		if scanned_targets:
			res = manager.devices.update_many(
				{
					"ip_address": {"$in": scanned_targets, "$nin": up_ips},
					"status": "online",
				},
				{"$set": {"status": "offline"}},
			)
			offline_count = int(getattr(res, 'modified_count', 0) or 0)
	except Exception:
		offline_count = 0
	completed = datetime.now(timezone.utc)

	stats = {
		'ranges': ranges,
		'hosts_discovered': len(discovered),
		'hosts_targeted': len(scanned_targets),
		'hosts_up': len(up_ips),
		'devices_upserted': len(up_ips),
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
		'progress.phase': 'completed',
	})
	_append_scan_log(manager.db, scan_request_id, 'info', f"Scan complete: hosts={stats.get('hosts_discovered')} duration={stats.get('duration_seconds')}s")

	logger.info('Scan complete: {}', stats)
	return {'scan_id': scan_id, 'status': 'completed', 'statistics': stats}


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
	is_root = (os.geteuid() == 0) if hasattr(os, 'geteuid') else False
	_update_scanner_heartbeat(manager.db, is_root=is_root)
	scheduler = BackgroundScheduler(daemon=True)
	scheduler.start()

	scan_lock = threading.Lock()

	def run_scan_guarded(reason: str, scan_request_id: Optional[str] = None, network_ranges: Optional[str] = None) -> dict:
		if not scan_lock.acquire(blocking=False):
			raise RuntimeError('Scan already running')
		try:
			return run_scan(manager, reason=reason, scan_request_id=scan_request_id, network_ranges=network_ranges)
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
		# Embedded mode (spawned by the Node API) can provide context via env vars.
		# Honor SCAN_REASON so scheduled scans can auto-detect ranges.
		env_reason = (os.getenv('SCAN_REASON') or '').strip()
		run_scan_guarded(reason=(env_reason or 'manual_cli'))
		return 0

	last_schedule_check = 0.0
	last_heartbeat = 0.0
	try:
		while True:
			# Heartbeat for API process coordination.
			now = time.time()
			if now - last_heartbeat > 10:
				last_heartbeat = now
				_update_scanner_heartbeat(manager.db, is_root=is_root)

			# Poll scan requests from API/UI
			req = _claim_pending_scan_request(manager.db)
			if req:
				req_id = str(req.get('_id'))
				logger.info('Picked up scan request {}', req_id)
				try:
					restore = _apply_request_options(req.get('options'))
					try:
						reason = str(req.get('type') or '').strip() or 'manual_request'
						result = run_scan_guarded(
							reason=reason,
							scan_request_id=req_id,
							network_ranges=req.get('network_ranges'),
						)
					finally:
						if callable(restore):
							restore()
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
					_append_scan_log(manager.db, req_id, 'error', f"Scan failed: {str(e)}")
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

