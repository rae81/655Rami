#!/usr/bin/env python3
"""
SDN LLDP IDS Testbed Orchestrator
Complete automation for IDS testing: controller startup, attack execution, artifact collection.

Integrates from:
- github.com/byaussy/ryu-mininet-custom (Ryu controller automation)
- github.com/pranav93y/multipath-RYU (subprocess orchestration patterns)
- Standard OVS utilities (ovs-vsctl, ovs-ofctl)
"""

import argparse
import subprocess
import time
import json
import os
import sys
import signal
import socket
from datetime import datetime
from pathlib import Path


# CONFIGURATION LOADING
# From: Standard Python patterns
def load_config(config_file="config.yaml"):
    """Load configuration from YAML file."""
    import yaml
    if not os.path.exists(config_file):
        print(f"[!] Config file not found: {config_file}")
        return None
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


# PROCESS MANAGEMENT
# From: github.com/pranav93y/multipath-RYU (subprocess patterns)
class ProcessManager:
    """Manage background processes with cleanup."""

    def __init__(self):
        self.processes = {}

    def start(self, name, cmd, log_file=None):
        """Start background process with logging."""
        print(f"[*] Starting {name}...")
        print(f"    Command: {' '.join(cmd)}")

        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_handle = open(log_file, 'w')
            proc = subprocess.Popen(cmd, stdout=log_handle, stderr=subprocess.STDOUT)
        else:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.processes[name] = {'proc': proc, 'log': log_file}
        print(f"[+] {name} started (PID: {proc.pid})")
        return proc

    def stop(self, name):
        """Stop background process gracefully."""
        if name not in self.processes:
            return

        proc_info = self.processes[name]
        proc = proc_info['proc']

        if proc.poll() is None:  # Still running
            print(f"[*] Stopping {name} (PID: {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
                print(f"[+] {name} stopped")
            except subprocess.TimeoutExpired:
                print(f"[!] {name} didn't stop, killing...")
                proc.kill()
                proc.wait()

        del self.processes[name]

    def stop_all(self):
        """Stop all managed processes."""
        for name in list(self.processes.keys()):
            self.stop(name)


# RYU CONTROLLER MANAGEMENT
# From: github.com/byaussy/ryu-mininet-custom (controller startup)
def check_controller_ready(host='127.0.0.1', port=6653, timeout=30):
    """Wait for OpenFlow controller to be ready."""
    print(f"[*] Waiting for controller on {host}:{port}...")
    start = time.time()

    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            sock.close()
            print(f"[+] Controller ready on port {port}")
            return True
        except (socket.error, ConnectionRefusedError):
            time.sleep(1)

    print(f"[!] Controller not ready after {timeout}s")
    return False


# OVS BRIDGE MANAGEMENT
# From: Standard OVS documentation
def configure_ovs_bridge(bridge_name, interfaces=None):
    """Configure OVS bridge with LLDP punt rules."""
    print(f"[*] Configuring OVS bridge: {bridge_name}")

    # Check if bridge exists
    result = subprocess.run(['ovs-vsctl', 'br-exists', bridge_name],
                          capture_output=True)

    if result.returncode != 0:
        # Create bridge
        subprocess.run(['ovs-vsctl', 'add-br', bridge_name], check=True)
        print(f"[+] Created bridge {bridge_name}")

        # Add interfaces if specified
        if interfaces:
            for iface in interfaces:
                subprocess.run(['ovs-vsctl', 'add-port', bridge_name, iface], check=True)
                print(f"[+] Added port {iface} to {bridge_name}")

    # Set controller
    subprocess.run(['ovs-vsctl', 'set-controller', bridge_name, 'tcp:127.0.0.1:6653'], check=True)
    print(f"[+] Set controller for {bridge_name}")

    # Install LLDP punt rule (send all LLDP to controller)
    # Priority 65535 to match IDS interception flows
    subprocess.run([
        'ovs-ofctl', 'add-flow', bridge_name,
        'priority=65535,dl_type=0x88cc,actions=controller'
    ], check=True)
    print(f"[+] Installed LLDP punt rule")


def dump_ovs_flows(bridge_name, output_file):
    """Dump OVS flow table to file."""
    print(f"[*] Dumping flows from {bridge_name}...")
    result = subprocess.run(['ovs-ofctl', 'dump-flows', bridge_name],
                          capture_output=True, text=True)

    with open(output_file, 'w') as f:
        f.write(result.stdout)

    print(f"[+] Flows saved to {output_file}")


# ATTACK EXECUTION
# From: github.com/pranav93y/multipath-RYU (test orchestration)
def run_attack(attack_script, mode, interface, output_dir, **kwargs):
    """Execute attack script with specified mode."""
    print(f"\n{'='*60}")
    print(f"[*] Running attack: {mode}")
    print(f"{'='*60}")

    cmd = [attack_script, mode, '-i', interface]

    # Add mode-specific arguments
    if mode == 'spoof':
        cmd.extend(['-c', kwargs.get('chassis', 'aa:bb:cc:dd:ee:ff')])
        cmd.extend(['-p', kwargs.get('port', 'eth1')])
        cmd.extend(['--count', str(kwargs.get('count', 50))])
    elif mode == 'flood':
        cmd.extend(['--count', str(kwargs.get('count', 500))])
        cmd.extend(['--rate', str(kwargs.get('rate', 50))])
    elif mode == 'replay':
        cmd.extend(['--pcap', kwargs.get('pcap', 'captured.pcap')])
        cmd.extend(['--count', str(kwargs.get('count', 30))])
    elif mode == 'relay':
        cmd.extend(['--sniff-iface', kwargs.get('sniff_iface', 'eth1')])
        cmd.extend(['--duration', str(kwargs.get('duration', 60))])
    elif mode == 'ttl':
        cmd.extend(['-c', kwargs.get('chassis', 'aa:bb:cc:dd:ee:ff')])
        cmd.extend(['-p', kwargs.get('port', 'eth1')])
        cmd.extend(['--ttl', str(kwargs.get('ttl', 0))])
        cmd.extend(['--count', str(kwargs.get('count', 30))])
    elif mode == 'malformed':
        cmd.extend(['-c', kwargs.get('chassis', 'aa:bb:cc:dd:ee:ff')])
        cmd.extend(['-p', kwargs.get('port', 'eth1')])
        cmd.extend(['--count', str(kwargs.get('count', 30))])
    elif mode == 'capture':
        cmd.extend(['--duration', str(kwargs.get('duration', 30))])

    # Set output PCAP location
    pcap_file = f"{output_dir}/attack_{mode}.pcap"
    cmd.extend(['-o', pcap_file])

    # Run attack
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)

        if result.returncode != 0:
            print(f"[!] Attack failed: {result.stderr}")
            return False

        # Move metadata file to output directory
        if os.path.exists('attack_meta.json'):
            meta_dest = f"{output_dir}/attack_{mode}_meta.json"
            os.rename('attack_meta.json', meta_dest)
            print(f"[+] Metadata saved to {meta_dest}")

        return True

    except subprocess.TimeoutExpired:
        print(f"[!] Attack timeout after 300s")
        return False


# ARTIFACT COLLECTION
def collect_artifacts(run_dir, ids_dir='.'):
    """Collect all IDS and attack artifacts."""
    print(f"\n[*] Collecting artifacts to {run_dir}...")

    artifacts = {
        'events.jsonl': f"{ids_dir}/events.jsonl",
        'mitigation_log.json': f"{ids_dir}/mitigation_log.json",
        'stats.json': f"{ids_dir}/stats.json",
        'lldp_ids_alerts.log': f"{ids_dir}/lldp_ids_alerts.log"
    }

    collected = []
    for name, src_path in artifacts.items():
        if os.path.exists(src_path):
            dest_path = f"{run_dir}/{name}"
            subprocess.run(['cp', src_path, dest_path])
            collected.append(name)
            print(f"[+] Collected {name}")

    return collected


# METRICS COMPUTATION
def compute_metrics(run_dir):
    """Compute detection metrics from collected artifacts."""
    print(f"\n[*] Computing metrics...")

    events_file = f"{run_dir}/events.jsonl"
    mitigation_file = f"{run_dir}/mitigation_log.json"

    if not os.path.exists(events_file):
        print(f"[!] No events.jsonl found")
        return None

    # Parse events
    events = []
    with open(events_file, 'r') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    # Parse mitigations
    mitigations = []
    if os.path.exists(mitigation_file):
        with open(mitigation_file, 'r') as f:
            mitigations = json.load(f)

    # Compute statistics
    total = len(events)
    attacks_detected = len([e for e in events if e['final_action'] == 'drop'])
    normal_forwarded = len([e for e in events if e['final_action'] == 'forward'])

    # Latency statistics
    latencies = [e['latency_ms'] for e in events if 'latency_ms' in e]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0

    # Attack type breakdown
    attack_types = {}
    for e in events:
        if e['final_action'] == 'drop':
            pred = e.get('ml_prediction', 'unknown')
            attack_types[pred] = attack_types.get(pred, 0) + 1

    # Rule vs ML breakdown
    rule_blocks = len([e for e in events if e.get('rule_decision') == 'block'])
    ml_blocks = attacks_detected - rule_blocks

    metrics = {
        'total_events': total,
        'attacks_detected': attacks_detected,
        'normal_forwarded': normal_forwarded,
        'detection_rate_pct': (attacks_detected / total * 100) if total > 0 else 0,
        'latency_avg_ms': avg_latency,
        'latency_max_ms': max_latency,
        'attack_types': attack_types,
        'rule_blocks': rule_blocks,
        'ml_blocks': ml_blocks,
        'mitigations_installed': len(mitigations)
    }

    # Save metrics
    metrics_file = f"{run_dir}/metrics.json"
    with open(metrics_file, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"[+] Metrics computed:")
    print(f"    Total events: {total}")
    print(f"    Attacks detected: {attacks_detected}")
    print(f"    Detection rate: {metrics['detection_rate_pct']:.2f}%")
    print(f"    Avg latency: {avg_latency:.2f}ms")
    print(f"    Rule blocks: {rule_blocks} | ML blocks: {ml_blocks}")

    return metrics


# MAIN ORCHESTRATION
def main():
    parser = argparse.ArgumentParser(
        description="SDN LLDP IDS Testbed Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Orchestration Workflow:
  1. Start Ryu IDS controller
  2. Configure OVS bridge with LLDP punt rules
  3. Wait for topology learning (60s)
  4. Execute attack scenarios
  5. Collect artifacts (logs, PCAPs, flow dumps)
  6. Compute detection metrics
  7. Save to runs/<timestamp>/

Examples:
  # Full test with all attacks
  ./orchestrate_testbed.py --bridge br0 --interface eth0 --all-attacks

  # Single attack test
  ./orchestrate_testbed.py --bridge br0 --interface eth0 --attack flood

  # Custom attack parameters
  ./orchestrate_testbed.py --bridge br0 --interface eth0 --attack flood --count 1000 --rate 100
        """
    )

    parser.add_argument('--bridge', default='br0', help='OVS bridge name (default: br0)')
    parser.add_argument('--interface', '-i', required=True, help='Network interface for attacks')
    parser.add_argument('--controller-port', type=int, default=6653, help='OpenFlow controller port (default: 6653)')
    parser.add_argument('--learning-duration', type=int, default=60, help='Topology learning duration in seconds (default: 60)')

    parser.add_argument('--all-attacks', action='store_true', help='Run all attack modes')
    parser.add_argument('--attack', choices=['spoof', 'flood', 'replay', 'ttl', 'malformed', 'capture'],
                       help='Single attack mode to run')

    # Attack parameters
    parser.add_argument('--count', type=int, default=50, help='Number of attack packets (default: 50)')
    parser.add_argument('--rate', type=int, default=50, help='Flood rate in pkt/s (default: 50)')
    parser.add_argument('--chassis', default='aa:bb:cc:dd:ee:ff', help='Fake chassis ID (default: aa:bb:cc:dd:ee:ff)')
    parser.add_argument('--port', default='eth1', help='Fake port ID (default: eth1)')
    parser.add_argument('--ttl', type=int, default=0, help='TTL value for ttl attack (default: 0)')

    parser.add_argument('--no-controller', action='store_true', help='Skip controller startup (already running)')
    parser.add_argument('--no-cleanup', action='store_true', help='Keep processes running after test')

    args = parser.parse_args()

    # Create run directory
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_dir = f"runs/{timestamp}"
    os.makedirs(run_dir, exist_ok=True)
    print(f"\n{'='*60}")
    print(f"SDN LLDP IDS Testbed Orchestrator")
    print(f"Run directory: {run_dir}")
    print(f"{'='*60}\n")

    pm = ProcessManager()

    def cleanup(signum=None, frame=None):
        """Cleanup handler."""
        print(f"\n[*] Cleaning up...")
        pm.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        # Step 1: Start Ryu IDS controller
        # From: github.com/byaussy/ryu-mininet-custom
        if not args.no_controller:
            controller_log = f"{run_dir}/controller.log"
            controller_cmd = [
                'ryu-manager',
                '--observe-links',
                'ryu.topology.switches',
                'ramifinal655/lldp_ids_system.py',
                '--verbose'
            ]
            pm.start('controller', controller_cmd, controller_log)

            # Wait for controller ready
            if not check_controller_ready(port=args.controller_port):
                print(f"[!] Controller failed to start")
                cleanup()
                return 1

            time.sleep(2)  # Extra stabilization time
        else:
            print(f"[*] Skipping controller startup (--no-controller)")

        # Step 2: Configure OVS bridge
        configure_ovs_bridge(args.bridge)

        # Step 3: Wait for topology learning
        print(f"\n[*] Waiting {args.learning_duration}s for topology learning...")
        time.sleep(args.learning_duration)

        # Step 4: Execute attacks
        attack_script = './ramifinal655/scapy_lldp_attacks.py'

        if args.all_attacks:
            # Run all attack modes
            attacks = [
                ('capture', {'duration': 30}),
                ('flood', {'count': args.count, 'rate': args.rate}),
                ('spoof', {'chassis': args.chassis, 'port': args.port, 'count': args.count}),
                ('ttl', {'chassis': args.chassis, 'port': args.port, 'ttl': args.ttl, 'count': args.count}),
                ('malformed', {'chassis': args.chassis, 'port': args.port, 'count': args.count}),
            ]

            for mode, params in attacks:
                run_attack(attack_script, mode, args.interface, run_dir, **params)
                time.sleep(5)  # Pause between attacks

        elif args.attack:
            # Run single attack
            params = {
                'count': args.count,
                'rate': args.rate,
                'chassis': args.chassis,
                'port': args.port,
                'ttl': args.ttl
            }
            run_attack(attack_script, args.attack, args.interface, run_dir, **params)

        else:
            print(f"[!] No attack specified. Use --attack or --all-attacks")

        # Step 5: Collect artifacts
        time.sleep(2)  # Let IDS finish logging
        collect_artifacts(run_dir, 'ramifinal655')

        # Step 6: Dump OVS flows
        dump_ovs_flows(args.bridge, f"{run_dir}/ovs_flows.txt")

        # Step 7: Compute metrics
        compute_metrics(run_dir)

        print(f"\n{'='*60}")
        print(f"[+] Test complete!")
        print(f"[+] Results saved to: {run_dir}/")
        print(f"{'='*60}\n")

        # Cleanup
        if not args.no_cleanup:
            cleanup()

        return 0

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        cleanup()
        return 1


if __name__ == "__main__":
    sys.exit(main())
