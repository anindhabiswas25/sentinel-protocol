"""
Community-driven scam reporting system.

Allows users to report suspicious contracts and builds a reputation-weighted
scoring system to detect scams that automated tools might miss.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


class CommunityReports:
    """User-submitted scam reports with reputation scoring"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize community reports service.
        
        Args:
            db_path: Path to SQLite database (default: data/community_reports.db)
        """
        if db_path is None:
            db_path = Path(__file__).parent.parent.parent / "data" / "community_reports.db"
        
        self.db_path = str(db_path)
        self._init_database()
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        try:
            # Ensure data directory exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scam_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract_address TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    category TEXT,
                    description TEXT,
                    reporter_id TEXT,
                    reporter_reputation REAL DEFAULT 1.0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    verified BOOLEAN DEFAULT 0
                )
            """)
            
            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_contract_address 
                ON scam_reports(contract_address, chain)
            """)
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Community reports database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize community reports database: {e}")
    
    async def get_report_score(self, address: str, chain: str = "ethereum") -> Dict:
        """
        Get community report score for an address.
        
        Returns:
            - report_count: Number of reports in last 30 days
            - avg_severity: Average reported severity
            - risk_adjustment: Score penalty (0-25)
            - recent_reports: List of recent report details
        """
        
        address = address.lower()
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get reports from last 30 days
            cursor.execute("""
                SELECT severity, reporter_reputation, category, description, timestamp
                FROM scam_reports
                WHERE LOWER(contract_address) = ?
                AND LOWER(chain) = ?
                AND timestamp > datetime('now', '-30 days')
                ORDER BY timestamp DESC
            """, [address, chain.lower()])
            
            reports = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            if not reports:
                return {
                    'report_count': 0,
                    'avg_severity': 0,
                    'risk_adjustment': 0,
                    'recent_reports': []
                }
            
            # Calculate weighted severity (higher reputation = more weight)
            total_weight = sum(r['reporter_reputation'] for r in reports)
            weighted_severity = sum(
                r['severity'] * r['reporter_reputation'] 
                for r in reports
            ) / total_weight if total_weight > 0 else 0
            
            # More reports from reputable users = higher adjustment
            # Formula: (avg_severity / 10) * sqrt(report_count) * 10
            import math
            risk_adjustment = (weighted_severity / 10.0) * math.sqrt(len(reports)) * 10
            risk_adjustment = min(risk_adjustment, 25)  # Cap at 25 point penalty
            
            return {
                'report_count': len(reports),
                'avg_severity': weighted_severity,
                'risk_adjustment': round(risk_adjustment, 1),
                'recent_reports': reports[:5]  # Return last 5 reports
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to get community reports for {address}: {e}")
            return {
                'report_count': 0,
                'avg_severity': 0,
                'risk_adjustment': 0,
                'recent_reports': []
            }
    
    async def submit_report(
        self,
        address: str,
        chain: str,
        severity: int,
        category: str,
        description: str,
        reporter_id: str,
        reporter_reputation: float = 1.0
    ) -> bool:
        """
        Submit a new scam report.
        
        Args:
            address: Contract address
            chain: Blockchain network
            severity: Severity score (1-10)
            category: Report category (e.g., "honeypot", "rug_pull")
            description: User description of the issue
            reporter_id: Unique reporter identifier
            reporter_reputation: Reporter's reputation score (default 1.0)
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO scam_reports 
                (contract_address, chain, severity, category, description, 
                 reporter_id, reporter_reputation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [
                address.lower(),
                chain.lower(),
                severity,
                category,
                description,
                reporter_id,
                reporter_reputation
            ])
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Report submitted for {address} by {reporter_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to submit report: {e}")
            return False


# Singleton instance
community_reports = CommunityReports()
