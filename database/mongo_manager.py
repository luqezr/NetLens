from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from datetime import datetime
from bson import ObjectId
import os

class MongoDBManager:
    def __init__(self):
        # Get MongoDB connection from environment
        mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
        db_name = os.getenv('MONGO_DB_NAME', 'netlens')
        
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        
        # Collections
        self.devices = self.db.devices
        self.scan_history = self.db.scan_history
        self.topology = self.db.topology
        self.alerts = self.db.alerts
        
        # Create indexes
        self._create_indexes()
    
    def _create_indexes(self):
        """Create indexes for better query performance"""
        # Devices
        try:
            self.devices.create_index("ip_address", unique=True)
        except Exception:
            pass
        # Unique MAC when present, but allow many docs without MAC.
        # NOTE: sparse=True still indexes explicit nulls; prefer partial index so null/empty values are ignored.
        try:
            self.devices.create_index(
                "mac_address",
                unique=True,
                partialFilterExpression={
                    "mac_address": {"$type": "string", "$ne": ""}
                },
            )
        except Exception:
            # Fallback for older MongoDB versions
            try:
                self.devices.create_index("mac_address", unique=True, sparse=True)
            except Exception:
                pass
        for idx in ("status", "last_seen", "last_seen_on", "last_scan_on"):
            try:
                self.devices.create_index(idx)
            except Exception:
                pass
        try:
            self.devices.create_index([("device_type", ASCENDING), ("status", ASCENDING)])
        except Exception:
            pass
        
        # Scan history
        self.scan_history.create_index([("started_at", DESCENDING)])
        self.scan_history.create_index("scan_id", unique=True)
        
        # Topology
        self.topology.create_index("source_device_id")
        self.topology.create_index("target_device_id")
        
        # Alerts
        self.alerts.create_index([("created_at", DESCENDING)])
        self.alerts.create_index("acknowledged")
    
    def upsert_device(self, device_data):
        """Insert or update a device"""
        # Never persist null/empty MACs; they break unique indexes and aren't useful.
        if device_data.get('mac_address') in (None, '', '-', '—'):
            device_data.pop('mac_address', None)
        if device_data.get('hostname') in (None, '', '-', '—'):
            device_data.pop('hostname', None)

        ip_address = device_data.get('ip_address')
        mac_address = device_data.get('mac_address')

        now = datetime.utcnow()
        seen_at = device_data.get('last_seen_on') or device_data.get('last_seen') or now
        scan_at = device_data.get('last_scan_on') or device_data.get('last_scan') or seen_at

        device_data['last_seen'] = seen_at
        device_data['last_scan'] = scan_at
        device_data['last_seen_on'] = seen_at
        device_data['last_scan_on'] = scan_at
        device_data['status'] = device_data.get('status') or 'online'

        # Prefer stable identity by MAC (IP can change).
        existing = None
        if mac_address:
            existing = self.devices.find_one({"mac_address": mac_address})
        if not existing and ip_address:
            existing = self.devices.find_one({"ip_address": ip_address})

        if existing:
            # Update existing device by _id to allow IP changes.
            # If a different doc already occupies the target IP (stale ip-only doc), prefer the MAC identity.
            if ip_address and existing.get('ip_address') != ip_address:
                conflict = self.devices.find_one({"ip_address": ip_address, "_id": {"$ne": existing["_id"]}})
                if conflict and not conflict.get('mac_address'):
                    try:
                        self.devices.delete_one({"_id": conflict["_id"]})
                    except Exception:
                        pass

            try:
                self.devices.update_one(
                    {"_id": existing["_id"]},
                    {"$set": device_data}
                )
            except DuplicateKeyError:
                # If IP uniqueness conflicts remain, retry without changing ip_address.
                safe = dict(device_data)
                safe.pop('ip_address', None)
                # Also avoid forcing a null/empty mac into a unique index.
                if safe.get('mac_address') in (None, '', '-', '—'):
                    safe.pop('mac_address', None)
                self.devices.update_one({"_id": existing["_id"]}, {"$set": safe})

            return existing['_id']

        # Insert new device
        device_data.setdefault('first_seen', now)
        # Remove null/empty mac_address to avoid duplicate key errors
        if device_data.get('mac_address') in (None, '', '-', '—'):
            device_data.pop('mac_address', None)
        result = self.devices.insert_one(device_data)

        # Create alert for new device
        self.create_alert(
            device_id=result.inserted_id,
            alert_type="new_device",
            severity="medium",
            title="New device detected",
            message=f"Device {device_data.get('hostname', ip_address)} joined the network"
        )

        return result.inserted_id
    
    def mark_devices_offline(self, current_ips):
        """Mark devices as offline if not seen in current scan"""
        result = self.devices.update_many(
            {
                "ip_address": {"$nin": current_ips},
                "status": "online"
            },
            {
                "$set": {"status": "offline"}
            }
        )
        return result.modified_count
    
    def get_all_devices(self, status=None):
        """Get all devices, optionally filtered by status"""
        query = {}
        if status:
            query['status'] = status
        
        return list(self.devices.find(query).sort("last_seen", DESCENDING))
    
    def get_device_by_ip(self, ip_address):
        """Get device by IP address"""
        return self.devices.find_one({"ip_address": ip_address})
    
    def create_scan_record(self, scan_data):
        """Create a new scan history record"""
        scan_data['started_at'] = datetime.utcnow()
        result = self.scan_history.insert_one(scan_data)
        return result.inserted_id
    
    def update_scan_record(self, scan_id, update_data):
        """Update scan history record"""
        self.scan_history.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": update_data}
        )
    
    def create_alert(self, device_id, alert_type, severity, title, message):
        """Create a new alert"""
        alert = {
            "device_id": device_id,
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "message": message,
            "created_at": datetime.utcnow(),
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None
        }
        return self.alerts.insert_one(alert)
    
    def get_recent_alerts(self, limit=50, acknowledged=None):
        """Get recent alerts"""
        query = {}
        if acknowledged is not None:
            query['acknowledged'] = acknowledged
        
        return list(self.alerts.find(query).sort("created_at", DESCENDING).limit(limit))
    
    def upsert_topology(self, source_ip, target_ip, connection_type, details):
        """Insert or update topology connection"""
        source_device = self.devices.find_one({"ip_address": source_ip})
        target_device = self.devices.find_one({"ip_address": target_ip})
        
        if not source_device or not target_device:
            return None
        
        topology_data = {
            "source_device_id": source_device['_id'],
            "target_device_id": target_device['_id'],
            "connection_type": connection_type,
            "details": details,
            "last_verified": datetime.utcnow()
        }
        
        result = self.topology.update_one(
            {
                "source_device_id": source_device['_id'],
                "target_device_id": target_device['_id']
            },
            {
                "$set": topology_data,
                "$setOnInsert": {"discovered_at": datetime.utcnow()}
            },
            upsert=True
        )
        
        return result.upserted_id or result.modified_count
    
    def get_device_statistics(self):
        """Get device statistics for dashboard"""
        pipeline = [
            {
                "$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        status_counts = {doc['_id']: doc['count'] for doc in self.devices.aggregate(pipeline)}
        
        # Device types
        type_pipeline = [
            {
                "$match": {"status": "online"}
            },
            {
                "$group": {
                    "_id": "$device_type",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        type_counts = {doc['_id']: doc['count'] for doc in self.devices.aggregate(type_pipeline)}
        
        return {
            "total_devices": self.devices.count_documents({}),
            "online_devices": status_counts.get('online', 0),
            "offline_devices": status_counts.get('offline', 0),
            "by_type": type_counts,
            "unacknowledged_alerts": self.alerts.count_documents({"acknowledged": False})
        }
    
    def close(self):
        """Close MongoDB connection"""
        self.client.close()