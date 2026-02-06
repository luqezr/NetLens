
import os
import sys
import time
import uuid
from datetime import datetime, timezone
import threading
import subprocess
import json
import re

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
	except Exception:
		# If file logging fails, keep stderr logging.
		logger.exception('Failed to configure file logging')


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
	for net in ranges:
		try:
			logger.info('Discovering hosts in {}', net)
			# Fast, reliable host discovery:
			# - Use ICMP echo + TCP SYN to common ports
			# - Prefer ARP on local networks to gather MAC/vendor when possible
			# - Short timeout to skip unresponsive hosts quickly
			args = '-sn -PR -PE -PS21,22,23,25,80,443,3389 --host-timeout 3s --max-retries 1'
			scanner.scan(hosts=net, arguments=args)
			
			up_count = 0
			for host in scanner.all_hosts():
				if scanner[host].state() == 'up':
					found.add(host)
					up_count += 1
			logger.info('Discovery in {}: {} hosts up', net, up_count)
		except Exception:
			logger.exception('Host discovery failed for range {}', net)
	
	total_found = len(found)
	logger.info('Discovery complete: {} total hosts up', total_found)
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
		args = f'-sS -A --version-all --reason --top-ports {top_ports} -T4 --host-timeout {host_timeout} --max-retries {max_retries}'
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
				args = f'{args} --script {nmap_scripts}'

	# For per-host scans (we already "discovered" the host), skip host discovery
	# to avoid false negatives when ICMP/TCP probes are filtered.
	assume_up = (os.getenv('SCAN_ASSUME_UP', '1') or '').strip().lower()
	# However, on local subnets ARP-based discovery also yields MAC/vendor.
	# So only force -Pn when the target doesn't look local.
	if assume_up not in ('0', 'false', 'no', 'off') and '-Pn' not in args and not _is_same_subnet_24(ip):
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

		hostnames = host.get('hostnames', [])
		if hostnames:
			device_data['hostname'] = hostnames[0].get('name') or device_data.get('hostname')
		device_data['hostnames'] = [h.get('name') for h in hostnames if h.get('name')]

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
		if not device_data.get('device_type') and any(s.get('name') in ('http', 'https') for s in services):
			device_data['device_type'] = 'server'

		device_data.setdefault('connection_method', 'unknown')

		return device_data
	except Exception:
		logger.exception('nmap scan failed for {}', ip)
		return device_data


def run_scan(manager: MongoDBManager, reason: str) -> dict:
	ranges = _parse_network_ranges()
	if not ranges:
		logger.warning('NETWORK_RANGES is empty; no scan performed')
		return {'reason': reason, 'error': 'NETWORK_RANGES is empty'}

	scan_request_id = _get_scan_request_id()
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
	discovered = _discover_hosts(ranges)
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
		device = _scan_host(ip, scan_at=scan_at)
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
			# Poll scan requests from API/UI
			req = _claim_pending_scan_request(manager.db)
			if req:
				req_id = str(req.get('_id'))
				logger.info('Picked up scan request {}', req_id)
				try:
					result = run_scan_guarded(reason='manual_request')
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

