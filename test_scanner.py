#!/usr/bin/env python3
"""
Manual scanner test script
Run this to test the scanner directly with verbose output
"""

import os
import sys

# Set verbose logging
os.environ['LOG_LEVEL'] = 'DEBUG'
os.environ['ENV_FILE'] = '/opt/netlens/config.env'

# Import after setting env vars
from scanner_service import (
    _load_environment,
    _configure_logging,
    _parse_network_ranges,
    _discover_hosts,
    _scan_host,
    run_scan
)
from database.mongo_manager import MongoDBManager
from loguru import logger

def main():
    print("=" * 60)
    print("NetLens Scanner Manual Test")
    print("=" * 60)
    
    # Load environment
    _load_environment()
    _configure_logging()
    
    # Parse network ranges
    ranges = _parse_network_ranges()
    print(f"\n✓ Network ranges: {ranges}")
    
    if not ranges:
        print("ERROR: No network ranges configured!")
        print("Set NETWORK_RANGES in /opt/netlens/config.env")
        return 1
    
    # Test discovery
    print(f"\n→ Discovering hosts in {', '.join(ranges)}...")
    discovered = _discover_hosts(ranges)
    print(f"✓ Discovered {len(discovered)} hosts: {discovered}")
    
    if not discovered:
        print("\n⚠️  No hosts discovered. Network might be offline or ranges incorrect.")
        return 0
    
    # Test scanning first host
    if discovered:
        test_ip = discovered[0]
        print(f"\n→ Scanning first host: {test_ip}")
        device_data = _scan_host(test_ip)
        print(f"✓ Scan result:")
        import json
        print(json.dumps(device_data, indent=2, default=str))
    
    # Test full scan with MongoDB
    print("\n→ Testing full scan with MongoDB...")
    try:
        manager = MongoDBManager()
        result = run_scan(manager, reason='manual_test')
        print(f"\n✓ Scan completed successfully!")
        print(f"Result: {result}")
        manager.close()
    except Exception as e:
        print(f"\n✗ Scan failed: {e}")
        logger.exception("Full scan error")
        return 1
    
    print("\n" + "=" * 60)
    print("Test completed successfully!")
    print("=" * 60)
    return 0

if __name__ == '__main__':
    sys.exit(main())
