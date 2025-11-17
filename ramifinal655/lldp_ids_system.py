"""
LLDP Intrusion Detection System for SDN Controllers
Complete production implementation with hybrid detection (rule-based + ML) and real-time mitigation.

Integrates from:
- github.com/faucetsdn/ryu (LLDP parsing, topology integration)
- github.com/macauleycheng/AOS_OF_Example (packet handling)
- github.com/ranauzairahmed/MininetIDS (ML model loading)
- github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS structure)
- github.com/SySS-Research/WireBug (TLV validation patterns)
- github.com/GoozeyX/python_lldp (structural checks)
"""

import logging
import logging.handlers
import time
import os
import json
from collections import defaultdict
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, lldp, ether_types
from ryu.topology import event

import joblib
import numpy as np
import yaml


# CONFIGURATION LOADING
# From: PyYAML docs
def load_config(config_path=None):
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = os.getenv('CONFIG_FILE', 'config.yaml')
    if not os.path.exists(config_path):
        return None
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


# LOGGING SETUP
# From: stackoverflow.com/questions/13733552
def setup_logger(name, log_file, level=logging.INFO, rotate_mb=10, backups=3):
    """Configure rotating logger for file and console output."""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, mode='a', maxBytes=rotate_mb*1024*1024, backupCount=backups
    )
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    logger.propagate = False
    return logger


# TLV VALIDATION
# From: github.com/SySS-Research/WireBug (TLV validation) + IEEE 802.1AB
class LLDPValidator:
    """Rule-based LLDP validation for structural and behavioral anomalies."""

    TLV_CHASSIS_ID = 1
    TLV_PORT_ID = 2
    TLV_TTL = 3
    TLV_END = 0

    def __init__(self, min_ttl=5, max_ttl=65535, max_frame_size=1500, min_frame_size=60,
                 max_burst_rate=50, min_inter_arrival=0.01):
        self.MIN_TTL = min_ttl
        self.MAX_TTL = max_ttl
        self.MAX_FRAME_SIZE = max_frame_size
        self.MIN_FRAME_SIZE = min_frame_size
        self.MAX_BURST_RATE = max_burst_rate
        self.MIN_INTER_ARRIVAL = min_inter_arrival
        self.last_seen = {}  # From: github.com/GoozeyX/python_lldp (timing analysis)

    def validate_frame(self, pkt_lldp, frame_size, flow_key, timestamp):
        """Comprehensive rule-based validation. Returns: (is_valid, reason)"""

        # Frame size check - From: IEEE 802.3
        if frame_size < self.MIN_FRAME_SIZE or frame_size > self.MAX_FRAME_SIZE:
            return False, f"Invalid frame size: {frame_size}"

        # Mandatory TLVs check - From: IEEE 802.1AB
        has_chassis = False
        has_port = False
        has_ttl = False
        has_end = False
        ttl_value = 0
        tlv_types_seen = []

        for tlv in pkt_lldp.tlvs:
            if isinstance(tlv, lldp.ChassisID):
                has_chassis = True
                tlv_types_seen.append(self.TLV_CHASSIS_ID)
            elif isinstance(tlv, lldp.PortID):
                has_port = True
                tlv_types_seen.append(self.TLV_PORT_ID)
            elif isinstance(tlv, lldp.TTL):
                has_ttl = True
                ttl_value = int(tlv.ttl) if hasattr(tlv, 'ttl') else 0
                tlv_types_seen.append(self.TLV_TTL)
            elif isinstance(tlv, lldp.End):
                has_end = True
                tlv_types_seen.append(self.TLV_END)

        if not (has_chassis and has_port and has_ttl):
            return False, f"Missing mandatory TLVs"

        # TLV order validation - From: IEEE 802.1AB Section 9.2.7
        if len(tlv_types_seen) >= 3:
            if tlv_types_seen[0] != self.TLV_CHASSIS_ID:
                return False, f"First TLV must be ChassisID"
            if tlv_types_seen[1] != self.TLV_PORT_ID:
                return False, f"Second TLV must be PortID"
            if tlv_types_seen[2] != self.TLV_TTL:
                return False, f"Third TLV must be TTL"
        if has_end and tlv_types_seen[-1] != self.TLV_END:
            return False, "End TLV must be last"

        # TTL range validation - From: IEEE 802.1AB Section 9.2.5.5
        if ttl_value < self.MIN_TTL or ttl_value > self.MAX_TTL:
            return False, f"TTL out of range: {ttl_value}"

        # Burst rate check - From: github.com/GoozeyX/python_lldp
        if flow_key in self.last_seen:
            time_delta = timestamp - self.last_seen[flow_key]
            if time_delta < self.MIN_INTER_ARRIVAL:
                rate = 1.0 / time_delta if time_delta > 0 else float('inf')
                if rate > self.MAX_BURST_RATE:
                    return False, f"Burst rate too high: {rate:.2f} pkt/s"

        self.last_seen[flow_key] = timestamp
        return True, "pass"


# FLOW STATE TRACKING
# From: github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS_RyuApp.py)
class LLDPFlowState:
    """Track per-flow LLDP state with bounded memory."""

    def __init__(self, max_flows=10000, window_size=10.0):
        self.MAX_FLOWS = max_flows
        self.window_size = window_size
        self.flows = defaultdict(lambda: {
            'first_seen': None, 'last_seen': None, 'packet_count': 0,
            'packet_timestamps': [], 'ttl_values': [], 'tlv_counts': [],
            'dpid': None, 'in_port': None
        })

    def get_flow_key(self, chassis_id, port_id):
        """Generate normalized flow identifier."""
        return f"{str(chassis_id).lower()}:{str(port_id).lower()}"

    def update_flow(self, chassis_id, port_id, timestamp, ttl, tlv_count, dpid, in_port):
        """Update flow state with new packet data."""
        if len(self.flows) >= self.MAX_FLOWS:  # LRU eviction
            oldest = min(self.flows.items(), key=lambda x: x[1]['last_seen'])
            del self.flows[oldest[0]]

        flow_key = self.get_flow_key(chassis_id, port_id)
        flow = self.flows[flow_key]

        if flow['first_seen'] is None:
            flow['first_seen'] = timestamp
            flow['dpid'] = dpid
            flow['in_port'] = in_port

        flow['last_seen'] = timestamp
        flow['packet_count'] += 1
        flow['packet_timestamps'].append(timestamp)
        flow['ttl_values'].append(ttl)
        flow['tlv_counts'].append(tlv_count)

        cutoff = timestamp - self.window_size
        flow['packet_timestamps'] = [ts for ts in flow['packet_timestamps'] if ts >= cutoff]
        return flow


# TOPOLOGY BASELINE LEARNING
# From: github.com/faucetsdn/ryu (ryu.topology.switches)
class TopologyBaseline:
    """Learn normal topology during initialization period."""

    def __init__(self, learning_duration=60.0):
        self.learning_duration = learning_duration
        self.start_time = time.time()
        self.is_learning = True
        self.known_links = {}  # (chassis_id, port_id) -> (dpid, in_port)
        self.port_sources = defaultdict(set)  # (dpid, in_port) -> set(chassis_ids)

    def update(self, chassis_id, port_id, dpid, in_port, timestamp):
        """Update topology knowledge."""
        current_time = time.time()
        if self.is_learning and (current_time - self.start_time) >= self.learning_duration:
            self.is_learning = False

        link_key = (chassis_id, port_id)
        location = (dpid, in_port)

        if self.is_learning:
            self.known_links[link_key] = location
            self.port_sources[location].add(chassis_id)
            return True, "learning"
        else:
            if link_key in self.known_links:
                known_location = self.known_links[link_key]
                if known_location != location:
                    return False, f"Link moved: {link_key} from {known_location} to {location}"
            else:
                return False, f"Unknown link: {link_key} at {location}"

            if len(self.port_sources[location]) > 3:
                return False, f"Port instability: {location} has {len(self.port_sources[location])} sources"

            return True, "valid"


# FEATURE EXTRACTION
# From: PROJECT MODEL (mlmodel/README.md - 5 features)
class LLDPFeatureExtractor:
    """Extract 5 behavioral features matching trained model."""

    def __init__(self, expected_ttl=120, ttl_tolerance=10, window_sec=10.0, max_flows=10000):
        self.EXPECTED_TTL = expected_ttl
        self.TTL_TOLERANCE = ttl_tolerance
        self.flow_state = LLDPFlowState(max_flows=max_flows, window_size=window_sec)

    def extract_features(self, pkt_lldp, frame_size, timestamp, dpid, in_port):
        """Extract features: packet_rate_win, age_since_first, tlv_density, ttl_dev, ttl_anom_flag."""

        # Parse TLVs - From: github.com/faucetsdn/ryu (switches.py)
        chassis_id = "unknown"
        port_id = "unknown"
        ttl_value = 0

        for tlv in pkt_lldp.tlvs:
            try:
                if isinstance(tlv, lldp.ChassisID):
                    chassis_id = str(tlv.chassis_id) if hasattr(tlv, 'chassis_id') else "unknown"
                elif isinstance(tlv, lldp.PortID):
                    port_id_raw = tlv.port_id if hasattr(tlv, 'port_id') else None
                    port_id = port_id_raw.hex() if isinstance(port_id_raw, bytes) else str(port_id_raw) if port_id_raw else "unknown"
                elif isinstance(tlv, lldp.TTL):
                    ttl_value = int(tlv.ttl) if hasattr(tlv, 'ttl') else 0
            except Exception:
                continue

        tlv_count = len(pkt_lldp.tlvs)
        flow = self.flow_state.update_flow(chassis_id, port_id, timestamp, ttl_value, tlv_count, dpid, in_port)

        # Compute 5 features (training order from MODEL_EVALUATION_REPORT.txt)
        tlv_density = tlv_count / frame_size if frame_size > 0 else 0.0
        age_since_first = timestamp - flow['first_seen'] if flow['first_seen'] else 0.0
        packet_rate_win = len(flow['packet_timestamps']) / self.flow_state.window_size
        ttl_dev = abs(ttl_value - self.EXPECTED_TTL)
        ttl_anom_flag = 1 if ttl_dev > self.TTL_TOLERANCE else 0

        return {
            'packet_rate_win': packet_rate_win, 'age_since_first': age_since_first,
            'tlv_density': tlv_density, 'ttl_dev': ttl_dev, 'ttl_anom_flag': ttl_anom_flag,
            'chassis_id': chassis_id, 'port_id': port_id, 'ttl_value': ttl_value,
            'tlv_count': tlv_count, 'timestamp': timestamp
        }


# MAIN IDS APPLICATION
# From: github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS_RyuApp.py)
class LLDPIDS(app_manager.RyuApp):
    """Complete LLDP IDS with hybrid detection (rules + ML), classification, and mitigation."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    LLDP_MACS = ['01:80:c2:00:00:0e', '01:80:c2:00:00:03', '01:80:c2:00:00:00']  # From: IEEE 802.1AB Table 8-1

    def __init__(self, *args, **kwargs):
        super(LLDPIDS, self).__init__(*args, **kwargs)

        config = load_config()
        if config is None:
            self.logger.warning("No config.yaml found, using defaults")
            config = {
                'model': {'path': 'mlmodel/02_Training/lldp_rf_model.pkl'},
                'detection': {
                    'enabled_classes': ['flood', 'replay', 'spoofed'],
                    'expected_ttl': 120, 'ttl_tolerance': 10, 'window_sec': 10, 'max_flows': 10000,
                    'learning_duration': 60, 'enable_rules': True, 'min_ttl': 5, 'max_ttl': 65535, 'max_burst_rate': 50
                },
                'mitigation': {'drop_flow_idle_sec': 30, 'drop_flow_hard_sec': 60},
                'logging': {
                    'file': 'lldp_ids_alerts.log', 'events_jsonl': 'events.jsonl',
                    'mitigation_json': 'mitigation_log.json', 'stats_json': 'stats.json',
                    'level': 'INFO', 'rotate_mb': 10, 'backups': 3
                }
            }

        self.CRITICAL_ATTACKS = config['detection']['enabled_classes']
        self.DROP_IDLE_SEC = config['mitigation']['drop_flow_idle_sec']
        self.DROP_HARD_SEC = config['mitigation']['drop_flow_hard_sec']
        self.ENABLE_RULES = config['detection'].get('enable_rules', True)

        log_path = config['logging']['file']
        log_level = getattr(logging, config['logging']['level'], logging.INFO)
        self.ids_logger = setup_logger('LLDP-IDS', log_path, log_level,
                                       config['logging'].get('rotate_mb', 10),
                                       config['logging'].get('backups', 3))

        self.events_jsonl_path = config['logging'].get('events_jsonl', 'events.jsonl')
        self.mitigation_json_path = config['logging'].get('mitigation_json', 'mitigation_log.json')
        self.stats_json_path = config['logging'].get('stats_json', 'stats.json')
        self._init_json_logs()

        self.ids_logger.info("="*80)
        self.ids_logger.info("LLDP IDS System Starting")
        self.ids_logger.info("="*80)

        self.feature_extractor = LLDPFeatureExtractor(
            expected_ttl=config['detection']['expected_ttl'],
            ttl_tolerance=config['detection']['ttl_tolerance'],
            window_sec=config['detection']['window_sec'],
            max_flows=config['detection']['max_flows']
        )

        if self.ENABLE_RULES:
            self.validator = LLDPValidator(
                min_ttl=config['detection'].get('min_ttl', 5),
                max_ttl=config['detection'].get('max_ttl', 65535),
                max_burst_rate=config['detection'].get('max_burst_rate', 50)
            )
            self.ids_logger.info("Rule-based validation: ENABLED")
        else:
            self.validator = None
            self.ids_logger.info("Rule-based validation: DISABLED")

        self.topology_baseline = TopologyBaseline(
            learning_duration=config['detection'].get('learning_duration', 60)
        )
        self.ids_logger.info(f"Topology learning: {config['detection'].get('learning_duration', 60)}s")

        self.datapaths = {}
        self.stats = {
            'total': 0, 'normal': 0, 'attacks': 0, 'dropped': 0,
            'rule_blocked': 0, 'ml_blocked': 0, 'by_type': defaultdict(int)
        }
        self.latencies = []

        self.MODEL_PATH = config['model']['path']
        if not os.path.isabs(self.MODEL_PATH):
            self.MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.MODEL_PATH)
        self._load_model()
        self.ids_logger.info("System initialized successfully")

    def _init_json_logs(self):
        """Initialize JSON log files."""
        if not os.path.exists(self.events_jsonl_path):
            open(self.events_jsonl_path, 'w').close()
        if not os.path.exists(self.mitigation_json_path):
            with open(self.mitigation_json_path, 'w') as f:
                json.dump([], f)

    def _load_model(self):
        """Load Random Forest model - From: github.com/ranauzairahmed/MininetIDS"""
        try:
            if not os.path.exists(self.MODEL_PATH):
                raise FileNotFoundError(f"Model not found: {self.MODEL_PATH}")
            self.model = joblib.load(self.MODEL_PATH)
            self.ids_logger.info(f"Model loaded: {self.MODEL_PATH}")
            self.ids_logger.info(f"Type: {type(self.model).__name__}")
            if hasattr(self.model, 'n_estimators'):
                self.ids_logger.info(f"Trees: {self.model.n_estimators}")
            if hasattr(self.model, 'n_features_in_'):
                self.ids_logger.info(f"Features: {self.model.n_features_in_}")
                if self.model.n_features_in_ != 5:
                    self.ids_logger.error(f"Feature mismatch! Expected 5, got {self.model.n_features_in_}")
        except Exception as e:
            self.ids_logger.error(f"Model load failed: {e}")
            self.model = None

    # OPENFLOW EVENT HANDLERS
    # From: github.com/macauleycheng/AOS_OF_Example (packet_lldp_in_out.py)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install LLDP interception flows for all LLDP MAC addresses."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.ids_logger.info(f"Switch connected: DPID={datapath.id}")

        # Priority ladder: Intercept(65535) > Drop(65530) > Normal(lower)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 65535, match, actions)

        for lldp_mac in self.LLDP_MACS:
            match = parser.OFPMatch(eth_dst=lldp_mac)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, 65534, match, actions)

        self.ids_logger.info(f"LLDP flows installed on DPID={datapath.id}")

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        """Install flow entry with optional timeouts."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
            priority=priority, match=match, instructions=inst, idle_timeout=idle, hard_timeout=hard
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track datapath connections."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.ids_logger.info(f"Datapath {datapath.id} registered")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.ids_logger.info(f"Datapath {datapath.id} unregistered")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Route packets to LLDP handler."""
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.dst in self.LLDP_MACS:
            self._handle_lldp(ev, pkt)

    # LLDP PROCESSING WITH HYBRID DETECTION
    # From: IDS_RyuApp.py + predictionapp.py
    def _handle_lldp(self, ev, pkt):
        """Complete LLDP processing with hybrid detection and mitigation."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        t_start = time.perf_counter()
        self.stats['total'] += 1
        timestamp = time.time()

        try:
            pkt_lldp = pkt.get_protocol(lldp.lldp)
            if not pkt_lldp:
                self.ids_logger.warning(f"LLDP parse failed: DPID={datapath.id} port={in_port}")
                self._forward_to_topology(ev)
                return

            frame_size = len(msg.data)
            features = self.feature_extractor.extract_features(pkt_lldp, frame_size, timestamp, datapath.id, in_port)
            flow_key = self.feature_extractor.flow_state.get_flow_key(features['chassis_id'], features['port_id'])

            # PHASE 1: Rule-based validation
            rule_decision = "pass"
            rule_reason = "disabled"
            if self.ENABLE_RULES and self.validator:
                rule_valid, rule_reason = self.validator.validate_frame(pkt_lldp, frame_size, flow_key, timestamp)
                if not rule_valid:
                    rule_decision = "block"
                    self._handle_rule_block(rule_reason, features, datapath, in_port, t_start, timestamp)
                    return

            # PHASE 2: Topology baseline check
            topo_valid, topo_reason = self.topology_baseline.update(
                features['chassis_id'], features['port_id'], datapath.id, in_port, timestamp
            )
            if not topo_valid:
                rule_decision = "block"
                self._handle_rule_block(f"Topology anomaly: {topo_reason}", features, datapath, in_port, t_start, timestamp)
                return

            # PHASE 3: ML classification
            if not self.model:
                self.ids_logger.error("Model unavailable")
                self._log_event(timestamp, datapath.id, in_port, features, rule_decision, "error", 0.0, "forward", 0.0)
                self._forward_to_topology(ev)
                return

            feature_vec = [[features['packet_rate_win'], features['age_since_first'], features['tlv_density'],
                           features['ttl_dev'], features['ttl_anom_flag']]]
            prediction = self.model.predict(feature_vec)[0]
            confidence = self.model.predict_proba(feature_vec).max()

            t_end = time.perf_counter()
            latency_ms = (t_end - t_start) * 1000
            self.latencies.append(latency_ms)

            if prediction in self.CRITICAL_ATTACKS:
                self._handle_attack(prediction, confidence, features, datapath, in_port, latency_ms, timestamp, rule_decision)
            else:
                self._handle_normal(prediction, confidence, latency_ms, timestamp, datapath.id, in_port, features, rule_decision)
                self._forward_to_topology(ev)

        except Exception as e:
            self.ids_logger.error(f"Processing error: {e}")
            self._forward_to_topology(ev)

    def _handle_rule_block(self, reason, features, datapath, in_port, t_start, timestamp):
        """Handle rule-based blocks."""
        self.stats['attacks'] += 1
        self.stats['dropped'] += 1
        self.stats['rule_blocked'] += 1
        self.stats['by_type']['rule_violation'] += 1

        t_end = time.perf_counter()
        latency_ms = (t_end - t_start) * 1000
        self.latencies.append(latency_ms)

        self.ids_logger.warning("="*80)
        self.ids_logger.warning(f"RULE VIOLATION: {reason}")
        self.ids_logger.warning(f"Latency: {latency_ms:.2f}ms | Source: DPID={datapath.id} Port={in_port}")
        self.ids_logger.warning(f"Chassis: {features['chassis_id']} | Port ID: {features['port_id']}")
        self.ids_logger.warning("ACTION: DROPPED + BLOCK FLOW INSTALLED")
        self.ids_logger.warning("="*80)

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_flow(datapath, 65530, match, [], idle=self.DROP_IDLE_SEC, hard=self.DROP_HARD_SEC)

        self._log_event(timestamp, datapath.id, in_port, features, "block", "rule_violation", 1.0, "drop", latency_ms)
        self._log_mitigation(timestamp, "rule_violation", datapath.id, in_port, reason)

    def _handle_attack(self, attack_type, confidence, features, datapath, in_port, latency_ms, timestamp, rule_decision):
        """Log attack, drop packet, install temporary block flow."""
        self.stats['attacks'] += 1
        self.stats['dropped'] += 1
        self.stats['ml_blocked'] += 1
        self.stats['by_type'][attack_type] += 1

        self.ids_logger.warning("="*80)
        self.ids_logger.warning(f"ATTACK: {attack_type.upper()}")
        self.ids_logger.warning(f"Confidence: {confidence:.1%} | Latency: {latency_ms:.2f}ms")
        self.ids_logger.warning(f"Source: DPID={datapath.id} Port={in_port}")
        self.ids_logger.warning(f"Chassis: {features['chassis_id']} | Port ID: {features['port_id']}")
        self.ids_logger.warning(f"Rate: {features['packet_rate_win']:.2f} pkt/s | Age: {features['age_since_first']:.3f}s")
        self.ids_logger.warning(f"TLV Density: {features['tlv_density']:.4f} | TTL: {features['ttl_value']} (dev: {features['ttl_dev']})")
        self.ids_logger.warning("ACTION: DROPPED + TEMPORARY BLOCK FLOW INSTALLED")
        self.ids_logger.warning("="*80)

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_LLDP)
        self._add_flow(datapath, 65530, match, [], idle=self.DROP_IDLE_SEC, hard=self.DROP_HARD_SEC)

        self._log_event(timestamp, datapath.id, in_port, features, rule_decision, attack_type, confidence, "drop", latency_ms)
        self._log_mitigation(timestamp, attack_type, datapath.id, in_port, f"{confidence:.1%} confidence")

    def _handle_normal(self, prediction, confidence, latency_ms, timestamp, dpid, in_port, features, rule_decision):
        """Log normal classification."""
        self.stats['normal'] += 1
        self.ids_logger.info(f"Normal: {prediction} ({confidence:.1%}) | Latency: {latency_ms:.2f}ms")
        self._log_event(timestamp, dpid, in_port, features, rule_decision, prediction, confidence, "forward", latency_ms)

    # JSON LOGGING
    # From: Standard Python json module
    def _log_event(self, timestamp, dpid, in_port, features, rule_decision, ml_prediction, ml_confidence, final_action, latency_ms):
        """Append event to events.jsonl."""
        event = {
            "timestamp": timestamp, "dpid": dpid, "in_port": in_port,
            "chassis_id": features['chassis_id'], "port_id": features['port_id'],
            "ttl": features['ttl_value'], "tlv_count": features['tlv_count'],
            "features": {
                "packet_rate_win": features['packet_rate_win'], "age_since_first": features['age_since_first'],
                "tlv_density": features['tlv_density'], "ttl_dev": features['ttl_dev'], "ttl_anom_flag": features['ttl_anom_flag']
            },
            "rule_decision": rule_decision, "ml_prediction": ml_prediction,
            "ml_confidence": float(ml_confidence), "final_action": final_action, "latency_ms": latency_ms
        }
        try:
            with open(self.events_jsonl_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            self.ids_logger.error(f"Failed to write event: {e}")

    def _log_mitigation(self, timestamp, attack_type, dpid, in_port, details):
        """Append mitigation action to mitigation_log.json."""
        mitigation = {
            "timestamp": timestamp, "attack_type": attack_type, "dpid": dpid, "in_port": in_port,
            "action": "drop_flow_installed", "flow_idle_timeout": self.DROP_IDLE_SEC,
            "flow_hard_timeout": self.DROP_HARD_SEC, "details": details
        }
        try:
            with open(self.mitigation_json_path, 'r') as f:
                log = json.load(f)
            log.append(mitigation)
            with open(self.mitigation_json_path, 'w') as f:
                json.dump(log, f, indent=2)
        except Exception as e:
            self.ids_logger.error(f"Failed to write mitigation: {e}")

    # TOPOLOGY INTEGRATION
    # From: github.com/faucetsdn/ryu (switches.py)
    def _forward_to_topology(self, ev):
        """Forward legitimate LLDP to topology module."""
        self.send_event_to_observers(event.EventPacketIn(ev.msg))

    # STATISTICS API
    # From: Traffic_Monitor.py
    def get_stats(self):
        """Return current statistics."""
        avg_latency = np.mean(self.latencies) if self.latencies else 0.0
        median_latency = np.median(self.latencies) if self.latencies else 0.0
        p95_latency = np.percentile(self.latencies, 95) if self.latencies else 0.0

        return {
            'total_packets': self.stats['total'], 'normal_packets': self.stats['normal'],
            'attacks_detected': self.stats['attacks'], 'packets_dropped': self.stats['dropped'],
            'rule_blocked': self.stats['rule_blocked'], 'ml_blocked': self.stats['ml_blocked'],
            'detection_rate': (self.stats['attacks'] / self.stats['total'] * 100) if self.stats['total'] > 0 else 0.0,
            'attacks_by_type': dict(self.stats['by_type']),
            'latency_ms_avg': avg_latency, 'latency_ms_median': median_latency, 'latency_ms_p95': p95_latency,
            'topology_learning': self.topology_baseline.is_learning
        }

    def export_stats(self):
        """Export statistics to JSON file."""
        stats = self.get_stats()
        stats['timestamp'] = time.time()
        stats['datetime'] = datetime.now().isoformat()
        try:
            with open(self.stats_json_path, 'w') as f:
                json.dump(stats, f, indent=2)
            self.ids_logger.info(f"Statistics exported to {self.stats_json_path}")
        except Exception as e:
            self.ids_logger.error(f"Failed to export stats: {e}")

    def log_stats(self):
        """Log statistics summary."""
        s = self.get_stats()
        self.ids_logger.info("="*80)
        self.ids_logger.info("STATISTICS")
        self.ids_logger.info(f"Total: {s['total_packets']} | Normal: {s['normal_packets']} | Attacks: {s['attacks_detected']} | Dropped: {s['packets_dropped']}")
        self.ids_logger.info(f"Rule Blocked: {s['rule_blocked']} | ML Blocked: {s['ml_blocked']}")
        self.ids_logger.info(f"Detection Rate: {s['detection_rate']:.2f}%")
        self.ids_logger.info(f"Latency: Avg={s['latency_ms_avg']:.2f}ms | Median={s['latency_ms_median']:.2f}ms | P95={s['latency_ms_p95']:.2f}ms")
        self.ids_logger.info(f"Topology Learning: {'ACTIVE' if s['topology_learning'] else 'COMPLETE'}")
        if s['attacks_by_type']:
            for atype, count in s['attacks_by_type'].items():
                self.ids_logger.info(f"  {atype}: {count}")
        self.ids_logger.info("="*80)
        self.export_stats()
