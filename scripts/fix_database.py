#!/usr/bin/env python3
"""Fix MongoDB database issues.

1. Drop and recreate MAC address index as a *partial unique* index (ignores null/empty)
2. Unset mac_address when it's null/empty to avoid unique-index collisions
3. Clean up failed scan requests

Why partial vs sparse?
    - sparse indexes still include explicit null values.
    - partialFilterExpression can ignore null/empty values entirely.
"""

import os
import sys
from pymongo import MongoClient

# Load environment
env_file = os.getenv('ENV_FILE', '/opt/netlens/config.env')
if os.path.exists(env_file):
    from dotenv import load_dotenv
    load_dotenv(env_file)

mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
db_name = os.getenv('MONGO_DB_NAME', 'netlens')

print(f"Connecting to MongoDB: {mongo_uri}")
print(f"Database: {db_name}")

client = MongoClient(mongo_uri)
db = client[db_name]

print("\n" + "="*60)
print("MongoDB Database Repair")
print("="*60)

# 1. Fix MAC address index
print("\n→ Checking devices collection indexes...")
indexes = db.devices.index_information()
print(f"Current indexes: {list(indexes.keys())}")

if 'mac_address_1' in indexes:
    index_info = indexes['mac_address_1']
    has_partial = 'partialFilterExpression' in index_info
    is_sparse = index_info.get('sparse', False)
    print(f"  mac_address_1 index: sparse={is_sparse} partial={has_partial}")

    print("  Dropping and recreating mac_address index as partial unique...")
    db.devices.drop_index('mac_address_1')
    db.devices.create_index(
        'mac_address',
        unique=True,
        partialFilterExpression={
            'mac_address': {'$type': 'string', '$ne': ''}
        }
    )
    print("  ✅ Recreated mac_address index as partial unique")
else:
    print("  Creating mac_address index as partial unique...")
    db.devices.create_index(
        'mac_address',
        unique=True,
        partialFilterExpression={
            'mac_address': {'$type': 'string', '$ne': ''}
        }
    )
    print("  ✅ Created mac_address index")

# 2. Remove null/empty MAC addresses from existing devices
print("\n→ Checking for devices with null/empty MAC addresses...")
null_mac_count = db.devices.count_documents({'mac_address': None})
empty_mac_count = db.devices.count_documents({'mac_address': ''})
print(f"  Found {null_mac_count} devices with null MAC address")
print(f"  Found {empty_mac_count} devices with empty MAC address")

if null_mac_count + empty_mac_count > 0:
    print("  Unsetting mac_address field from these devices...")
    result = db.devices.update_many(
        {'mac_address': {'$in': [None, '']}},
        {'$unset': {'mac_address': ''}}
    )
    print(f"  ✅ Updated {result.modified_count} devices")

# 3. Clean up old failed scan requests with result: null
print("\n→ Checking scan_requests for null results...")
null_result_count = db.scan_requests.count_documents({'result': None})
print(f"  Found {null_result_count} scan requests with null result")

if null_result_count > 0:
    print("  Fixing null results...")
    result = db.scan_requests.update_many(
        {'result': None},
        {'$set': {'result': {}}}
    )
    print(f"  ✅ Updated {result.modified_count} scan requests")

# 4. Show device stats
print("\n→ Device statistics:")
total_devices = db.devices.count_documents({})
online_devices = db.devices.count_documents({'status': 'online'})
offline_devices = db.devices.count_documents({'status': 'offline'})
with_mac = db.devices.count_documents({'mac_address': {'$exists': True, '$ne': None}})
without_mac = total_devices - with_mac

print(f"  Total devices: {total_devices}")
print(f"  Online: {online_devices}")
print(f"  Offline: {offline_devices}")
print(f"  With MAC address: {with_mac}")
print(f"  Without MAC address: {without_mac}")

# 5. Show scan request stats
print("\n→ Scan request statistics:")
total_scans = db.scan_requests.count_documents({})
queued_scans = db.scan_requests.count_documents({'status': 'queued'})
running_scans = db.scan_requests.count_documents({'status': 'running'})
completed_scans = db.scan_requests.count_documents({'status': 'completed'})
failed_scans = db.scan_requests.count_documents({'status': 'failed'})

print(f"  Total scan requests: {total_scans}")
print(f"  Queued: {queued_scans}")
print(f"  Running: {running_scans}")
print(f"  Completed: {completed_scans}")
print(f"  Failed: {failed_scans}")

print("\n" + "="*60)
print("Database repair complete!")
print("="*60)

client.close()
