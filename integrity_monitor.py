#!/usr/bin/env python3
"""
integrity_monitor.py - Advanced Blockchain Tamper Detection System
WITH FORENSIC ANALYSIS
"""

import os
import time
import json
import hashlib
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import copy

class IntegrityMonitor:
    def __init__(self, blockchain_file, alert_callback=None, check_interval=30):
        self.blockchain_file = blockchain_file
        self.alert_callback = alert_callback
        self.check_interval = check_interval
        
        self.last_valid_state = None
        self.last_valid_chain = None  # Store entire last known good chain
        self.last_check_time = None
        self.tampering_detected = False
        self.alerts = []
        
        self.running = False
        self.monitor_thread = None
        self.observer = None
        
        print("[Integrity Monitor] Initialized with Forensic Analysis")
    
    def start(self):
        if self.running:
            return
        
        self.running = True
        
        # Store initial baseline
        self._store_baseline()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self._start_file_watcher()
        
        print("[Integrity Monitor] Started - checking every {}s".format(self.check_interval))
    
    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        print("[Integrity Monitor] Stopped")
    
    def _store_baseline(self):
        """Store the current valid blockchain as baseline"""
        try:
            if os.path.exists(self.blockchain_file):
                with open(self.blockchain_file, 'r') as f:
                    chain = json.load(f)
                    # Deep copy to preserve original state
                    self.last_valid_chain = copy.deepcopy(chain)
                    print(f"[Integrity Monitor] Baseline stored: {len(chain)} blocks")
        except Exception as e:
            print(f"[Integrity Monitor] Could not store baseline: {e}")
    
    def _start_file_watcher(self):
        class BlockchainFileHandler(FileSystemEventHandler):
            def __init__(self, monitor):
                self.monitor = monitor
            
            def on_modified(self, event):
                if event.src_path.endswith(self.monitor.blockchain_file):
                    print("[File Watcher] Blockchain modified - verifying...")
                    self.monitor._verify_now()
        
        event_handler = BlockchainFileHandler(self)
        self.observer = Observer()
        watch_dir = os.path.dirname(self.blockchain_file) or '.'
        self.observer.schedule(event_handler, watch_dir, recursive=False)
        self.observer.start()
    
    def _monitor_loop(self):
        while self.running:
            try:
                self._verify_now()
                time.sleep(self.check_interval)
            except Exception as e:
                print(f"[Integrity Monitor] Error: {e}")
                time.sleep(5)
    
    def _verify_now(self):
        self.last_check_time = datetime.now()
        
        if not os.path.exists(self.blockchain_file):
            self._raise_alert("CRITICAL", "BLOCKCHAIN_DELETED", 
                            "⚠️ Blockchain file has been DELETED!",
                            forensics={
                                'deleted': True,
                                'last_known_blocks': len(self.last_valid_chain) if self.last_valid_chain else 0
                            })
            return
        
        try:
            with open(self.blockchain_file, 'r') as f:
                current_chain = json.load(f)
        except Exception as e:
            self._raise_alert("CRITICAL", "BLOCKCHAIN_CORRUPTED",
                            f"⚠️ Cannot read blockchain: {e}",
                            forensics={'error': str(e)})
            return
        
        # Perform forensic analysis
        is_valid, forensics = self._forensic_analysis(current_chain)
        
        if not is_valid:
            # TAMPERING DETECTED!
            self.tampering_detected = True
            
            # Build detailed message
            message = self._build_forensic_report(forensics)
            
            self._raise_alert("CRITICAL", "BLOCKCHAIN_TAMPERED", message, forensics)
        else:
            if self.tampering_detected:
                # Previously tampered, now restored
                self._raise_alert("INFO", "BLOCKCHAIN_RESTORED",
                                "✓ Blockchain integrity restored", {})
                self.tampering_detected = False
            
            # Update baseline with current valid state
            self.last_valid_chain = copy.deepcopy(current_chain)
            self.last_valid_state = {
                'block_count': len(current_chain),
                'tip_hash': current_chain[-1]['hash'],
                'timestamp': datetime.now().isoformat()
            }
    
    def _forensic_analysis(self, current_chain):
        """
        Detailed forensic analysis of blockchain tampering
        Returns: (is_valid: bool, forensics: dict)
        """
        forensics = {
            'total_blocks': len(current_chain),
            'tampered_blocks': [],
            'changes_detected': [],
            'severity': 'NONE'
        }
        
        if len(current_chain) == 0:
            forensics['severity'] = 'CRITICAL'
            forensics['changes_detected'].append('Blockchain is empty')
            return False, forensics
        
        # Compare with baseline if available
        if self.last_valid_chain:
            forensics['baseline_blocks'] = len(self.last_valid_chain)
            
            # Check for block count changes
            if len(current_chain) < len(self.last_valid_chain):
                deleted_count = len(self.last_valid_chain) - len(current_chain)
                forensics['changes_detected'].append(
                    f'{deleted_count} block(s) DELETED from chain'
                )
                forensics['severity'] = 'CRITICAL'
            elif len(current_chain) > len(self.last_valid_chain):
                added_count = len(current_chain) - len(self.last_valid_chain)
                # This is normal - new blocks added
                pass
        
        # Verify integrity of each block
        for i in range(1, len(current_chain)):
            current = current_chain[i]
            previous = current_chain[i-1]
            
            block_tampering = {}
            
            # Verify hash
            calculated_hash = self._calculate_hash(current)
            if current['hash'] != calculated_hash:
                block_tampering['hash_mismatch'] = True
                block_tampering['stored_hash'] = current['hash']
                block_tampering['calculated_hash'] = calculated_hash
                forensics['severity'] = 'CRITICAL'
            
            # Verify link
            if current['previous_hash'] != previous['hash']:
                block_tampering['link_broken'] = True
                block_tampering['expected_prev_hash'] = previous['hash']
                block_tampering['actual_prev_hash'] = current['previous_hash']
                forensics['severity'] = 'CRITICAL'
            
            # Compare with baseline if available
            if self.last_valid_chain and i < len(self.last_valid_chain):
                baseline_block = self.last_valid_chain[i]
                changes = self._compare_blocks(baseline_block, current)
                if changes:
                    block_tampering['field_changes'] = changes
                    forensics['severity'] = 'HIGH'
            
            if block_tampering:
                forensics['tampered_blocks'].append({
                    'block_index': i,
                    'tampering': block_tampering
                })
        
        # Determine if valid
        is_valid = len(forensics['tampered_blocks']) == 0 and forensics['severity'] == 'NONE'
        
        return is_valid, forensics
    
    def _compare_blocks(self, baseline, current):
        """Compare two blocks and return list of changes"""
        changes = []
        
        fields_to_check = ['index', 'timestamp', 'data', 'previous_hash', 'hash']
        
        for field in fields_to_check:
            if baseline.get(field) != current.get(field):
                change_info = {
                    'field': field,
                    'original': str(baseline.get(field))[:100],  # Truncate long values
                    'modified': str(current.get(field))[:100]
                }
                changes.append(change_info)
        
        return changes
    
    def _build_forensic_report(self, forensics):
        """Build human-readable forensic report"""
        lines = ["🚨 TAMPERING DETECTED - FORENSIC ANALYSIS:\n"]
        
        lines.append(f"📊 Total Blocks: {forensics['total_blocks']}")
        
        if 'baseline_blocks' in forensics:
            lines.append(f"📊 Baseline Blocks: {forensics['baseline_blocks']}")
        
        if forensics['changes_detected']:
            lines.append(f"\n⚠️ CRITICAL CHANGES:")
            for change in forensics['changes_detected']:
                lines.append(f"   • {change}")
        
        if forensics['tampered_blocks']:
            lines.append(f"\n🔍 TAMPERED BLOCKS: {len(forensics['tampered_blocks'])}")
            
            for tampered in forensics['tampered_blocks'][:5]:  # Show first 5
                block_idx = tampered['block_index']
                tampering = tampered['tampering']
                
                lines.append(f"\n   Block #{block_idx}:")
                
                if tampering.get('hash_mismatch'):
                    lines.append(f"      ❌ Hash Mismatch Detected")
                    lines.append(f"         Stored:     {tampering['stored_hash'][:16]}...")
                    lines.append(f"         Calculated: {tampering['calculated_hash'][:16]}...")
                
                if tampering.get('link_broken'):
                    lines.append(f"      ❌ Chain Link Broken")
                
                if tampering.get('field_changes'):
                    lines.append(f"      📝 Field Changes:")
                    for change in tampering['field_changes'][:3]:  # Show first 3 changes
                        lines.append(f"         • {change['field'].upper()}:")
                        lines.append(f"           Before: {change['original'][:50]}...")
                        lines.append(f"           After:  {change['modified'][:50]}...")
            
            if len(forensics['tampered_blocks']) > 5:
                lines.append(f"\n   ... and {len(forensics['tampered_blocks']) - 5} more tampered blocks")
        
        return "\n".join(lines)
    
    def _calculate_hash(self, block):
        block_data = json.dumps({
            'index': block['index'],
            'timestamp': block['timestamp'],
            'data': block['data'],
            'previous_hash': block['previous_hash']
        }, sort_keys=True)
        return hashlib.sha256(block_data.encode()).hexdigest()
    
    def _raise_alert(self, severity, alert_type, message, forensics):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'type': alert_type,
            'message': message,
            'forensics': forensics,
            'last_valid_state': self.last_valid_state
        }
        
        self.alerts.append(alert)
        
        # Print to console with forensics
        print(f"\n{'='*70}")
        print(f"🚨 INTEGRITY ALERT - {severity}")
        print(f"{'='*70}")
        print(f"Type: {alert_type}")
        print(f"Time: {alert['timestamp']}")
        print(f"\n{message}")
        
        if forensics and severity == 'CRITICAL':
            print(f"\n📋 FORENSIC DETAILS:")
            if 'tampered_blocks' in forensics:
                print(f"   Tampered Blocks: {len(forensics['tampered_blocks'])}")
                for tb in forensics['tampered_blocks'][:3]:
                    print(f"   • Block #{tb['block_index']}")
        
        print(f"{'='*70}\n")
        
        if self.alert_callback:
            self.alert_callback(alert)
    
    def get_status(self):
        return {
            'running': self.running,
            'last_check': self.last_check_time.isoformat() if self.last_check_time else None,
            'tampering_detected': self.tampering_detected,
            'last_valid_state': self.last_valid_state,
            'total_alerts': len(self.alerts),
            'recent_alerts': self.alerts[-10:]
        }

