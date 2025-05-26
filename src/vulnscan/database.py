"""
database.py - Database functionality for storing scan results and tracking targets over time
"""
import os
import json
import sqlite3
from datetime import datetime

class VulnDatabase:
    def __init__(self, db_path='vulnscan.db'):
        """Initialize database connection"""
        self.db_path = db_path
        self.conn = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Create database and tables if they don't exist"""
        # Connect to database (creates file if it doesn't exist)
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            first_seen DATETIME NOT NULL,
            last_scan DATETIME NOT NULL,
            tags TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            target_id INTEGER NOT NULL,
            scan_time DATETIME NOT NULL,
            scan_type TEXT NOT NULL,
            raw_results TEXT NOT NULL,
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            score REAL,
            description TEXT,
            details TEXT,
            detected_time DATETIME NOT NULL,
            status TEXT DEFAULT 'Open',
            FOREIGN KEY (scan_id) REFERENCES scans (id),
            FOREIGN KEY (target_id) REFERENCES targets (id)
        )
        ''')
        
        self.conn.commit()
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def add_target(self, ip_address, hostname=None, tags=None):
        """Add a new target to the database"""
        cursor = self.conn.cursor()
        now = datetime.now()
        
        # Check if target exists
        cursor.execute("SELECT id FROM targets WHERE ip_address = ?", (ip_address,))
        result = cursor.fetchone()
        
        if result:
            # Update existing target
            target_id = result[0]
            cursor.execute(
                "UPDATE targets SET last_scan = ?, hostname = ?, tags = ? WHERE id = ?",
                (now, hostname, json.dumps(tags) if tags else None, target_id)
            )
        else:
            # Insert new target
            cursor.execute(
                "INSERT INTO targets (ip_address, hostname, first_seen, last_scan, tags) VALUES (?, ?, ?, ?, ?)",
                (ip_address, hostname, now, now, json.dumps(tags) if tags else None)
            )
            target_id = cursor.lastrowid
        
        self.conn.commit()
        return target_id
    
    def add_scan_result(self, target_id, scan_type, results):
        """Add scan results to the database"""
        cursor = self.conn.cursor()
        now = datetime.now()
        
        # Insert scan record
        cursor.execute(
            "INSERT INTO scans (target_id, scan_time, scan_type, raw_results) VALUES (?, ?, ?, ?)",
            (target_id, now, scan_type, json.dumps(results))
        )
        
        scan_id = cursor.lastrowid
        
        # Process vulnerabilities from results
        if scan_type == 'web':
            # Process web vulnerabilities
            if 'xss_vulnerabilities' in results:
                for vuln in results['xss_vulnerabilities']:
                    self._add_vulnerability(
                        scan_id, target_id, 'XSS', 'High', 7.5,
                        f"Cross-Site Scripting in {vuln['param']} parameter", 
                        json.dumps(vuln)
                    )
            
            if 'sql_vulnerabilities' in results:
                for vuln in results['sql_vulnerabilities']:
                    self._add_vulnerability(
                        scan_id, target_id, 'SQL Injection', 'Critical', 9.0,
                        f"SQL Injection in {vuln['param']} parameter", 
                        json.dumps(vuln)
                    )
        
        elif scan_type == 'service':
            # Process service vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    self._add_vulnerability(
                        scan_id, target_id, vuln.get('cve_id', 'Unknown'),
                        vuln.get('severity', 'Unknown'), vuln.get('score', 0.0),
                        vuln.get('description', 'No description'), 
                        json.dumps(vuln)
                    )
        
        elif scan_type == 'port':
            # Process port scan results (basic)
            for port, port_info in results.items():
                if port_info.get('open') and port_info.get('vulnerabilities'):
                    for vuln_desc in port_info['vulnerabilities']:
                        severity = 'Medium'
                        score = 5.0
                        if 'Directory listing' in vuln_desc:
                            severity = 'Medium'
                            score = 5.0
                        elif 'Default credentials' in vuln_desc:
                            severity = 'High'
                            score = 8.0
                        
                        self._add_vulnerability(
                            scan_id, target_id, 'Port Vulnerability', 
                            severity, score, vuln_desc,
                            json.dumps({'port': port, 'description': vuln_desc})
                        )
        
        self.conn.commit()
        return scan_id
    
    def _add_vulnerability(self, scan_id, target_id, vuln_type, severity, score, description, details):
        """Helper to add a vulnerability to the database"""
        cursor = self.conn.cursor()
        now = datetime.now()
        
        cursor.execute(
            """
            INSERT INTO vulnerabilities 
            (scan_id, target_id, vulnerability_type, severity, score, description, details, detected_time) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, target_id, vuln_type, severity, score, description, details, now)
        )
    
    def get_target_history(self, ip_address):
        """Get scan history for a target"""
        cursor = self.conn.cursor()
        
        # Get target ID
        cursor.execute("SELECT id FROM targets WHERE ip_address = ?", (ip_address,))
        target = cursor.fetchone()
        if not target:
            return None
        
        target_id = target[0]
        
        # Get all scans for target
        cursor.execute(
            "SELECT id, scan_time, scan_type FROM scans WHERE target_id = ? ORDER BY scan_time DESC",
            (target_id,)
        )
        scans = [
            {
                'id': scan[0],
                'time': scan[1],
                'type': scan[2]
            }
            for scan in cursor.fetchall()
        ]
        
        # Get all vulnerabilities for target
        cursor.execute(
            """
            SELECT vulnerability_type, severity, score, description, detected_time, status
            FROM vulnerabilities 
            WHERE target_id = ?
            ORDER BY detected_time DESC
            """,
            (target_id,)
        )
        vulnerabilities = [
            {
                'type': vuln[0],
                'severity': vuln[1],
                'score': vuln[2],
                'description': vuln[3],
                'detected': vuln[4],
                'status': vuln[5]
            }
            for vuln in cursor.fetchall()
        ]
        
        return {
            'scans': scans,
            'vulnerabilities': vulnerabilities
        }
    
    def get_recent_scans(self, limit=10):
        """Get recent scan summaries"""
        cursor = self.conn.cursor()
        
        cursor.execute(
            """
            SELECT s.id, t.ip_address, s.scan_time, s.scan_type, 
                   COUNT(v.id) as vuln_count
            FROM scans s
            JOIN targets t ON s.target_id = t.id
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            GROUP BY s.id
            ORDER BY s.scan_time DESC
            LIMIT ?
            """,
            (limit,)
        )
        
        return [
            {
                'id': row[0],
                'ip_address': row[1],
                'time': row[2],
                'type': row[3],
                'vulnerability_count': row[4]
            }
            for row in cursor.fetchall()
        ]
    
    def get_vulnerability_stats(self):
        """Get vulnerability statistics"""
        cursor = self.conn.cursor()
        
        # Get count by severity
        cursor.execute(
            """
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            WHERE status = 'Open'
            GROUP BY severity
            """
        )
        
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Get count by type
        cursor.execute(
            """
            SELECT vulnerability_type, COUNT(*) as count
            FROM vulnerabilities
            WHERE status = 'Open'
            GROUP BY vulnerability_type
            ORDER BY count DESC
            LIMIT 10
            """
        )
        
        by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        return {
            'by_severity': by_severity,
            'by_type': by_type
        }