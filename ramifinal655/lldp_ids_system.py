"""
LLDP Intrusion Detection System for SDN Controllers
Complete production implementation with ML-based detection and real-time mitigation.

Integrates from:
- github.com/faucetsdn/ryu (LLDP parsing, topology integration)
- github.com/macauleycheng/AOS_OF_Example (packet handling)
- github.com/ranauzairahmed/MininetIDS (ML model loading)
- github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS structure)
"""

import logging
import logging.handlers
import time
import os
from collections import defaultdict

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
# From: PyYAML docs (YAML config parsing)
def load_config(config_path=None):
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = os.getenv('CONFIG_FILE', 'config.yaml')

    if not os.path.exists(config_path):
        return None

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


# LOGGING SETUP
# Extracted from: stackoverflow.com/questions/13733552 (dual file+console logging with rotation)
def setup_logger(name, log_file, level=logging.INFO, rotate_mb=10, backups=3):
    """Configure rotating logger for file and console output."""
    # Timestamp format: YYYY-MM-DD HH:MM:SS for benchmark parsing
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')

    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Rotating file handler with configurable size and backups
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, mode='a', maxBytes=rotate_mb*1024*1024, backupCount=backups
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    logger.propagate = False
    return logger


# FLOW STATE TRACKING
# Extracted from: github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS_RyuApp.py - state management)
class LLDPFlowState:
    """Track per-flow LLDP state with bounded memory."""

    def __init__(self, max_flows=10000, window_size=10.0):
        self.MAX_FLOWS = max_flows
        self.window_size = window_size
        self.flows = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'packet_count': 0,
            'packet_timestamps': [],
            'ttl_values': [],
            'tlv_counts': []
        })

    def get_flow_key(self, chassis_id, port_id):
        """Generate normalized flow identifier."""
        return f"{str(chassis_id).lower()}:{str(port_id).lower()}"

    def update_flow(self, chassis_id, port_id, timestamp, ttl, tlv_count):
        """Update flow state with new packet data."""
        # Enforce max flows (LRU eviction)
        if len(self.flows) >= self.MAX_FLOWS:
            oldest = min(self.flows.items(), key=lambda x: x[1]['last_seen'])
            del self.flows[oldest[0]]

        flow_key = self.get_flow_key(chassis_id, port_id)
        flow = self.flows[flow_key]

        if flow['first_seen'] is None:
            flow['first_seen'] = timestamp

        flow['last_seen'] = timestamp
        flow['packet_count'] += 1
        flow['packet_timestamps'].append(timestamp)
        flow['ttl_values'].append(ttl)
        flow['tlv_counts'].append(tlv_count)

        # Prune old timestamps (prevent unbounded growth)
        cutoff = timestamp - self.window_size
        flow['packet_timestamps'] = [ts for ts in flow['packet_timestamps'] if ts >= cutoff]

        return flow


# FEATURE EXTRACTION
# Extracted from: PROJECT MODEL (mlmodel/README.md - 5 features matching training dataset)
class LLDPFeatureExtractor:
    """Extract 5 behavioral features matching trained model."""

    def __init__(self, expected_ttl=120, ttl_tolerance=10, window_sec=10.0, max_flows=10000):
        self.EXPECTED_TTL = expected_ttl
        self.TTL_TOLERANCE = ttl_tolerance
        self.flow_state = LLDPFlowState(max_flows=max_flows, window_size=window_sec)

    def extract_features(self, pkt_lldp, frame_size, timestamp):
        """Extract features: packet_rate_win, age_since_first, tlv_density, ttl_dev, ttl_anom_flag."""

        # Parse TLVs by type (robust to reordering)
        # Extracted from: github.com/faucetsdn/ryu (switches.py LLDPPacket.lldp_parse)
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

        # Update flow state
        flow = self.flow_state.update_flow(chassis_id, port_id, timestamp, ttl_value, tlv_count)

        # Compute 5 features (exact training order from MODEL_EVALUATION_REPORT.txt)
        tlv_density = tlv_count / frame_size if frame_size > 0 else 0.0
        age_since_first = timestamp - flow['first_seen'] if flow['first_seen'] else 0.0
        packet_rate_win = len(flow['packet_timestamps']) / self.flow_state.window_size
        ttl_dev = abs(ttl_value - self.EXPECTED_TTL)
        ttl_anom_flag = 1 if ttl_dev > self.TTL_TOLERANCE else 0

        return {
            # Model features (training order)
            'packet_rate_win': packet_rate_win,
            'age_since_first': age_since_first,
            'tlv_density': tlv_density,
            'ttl_dev': ttl_dev,
            'ttl_anom_flag': ttl_anom_flag,
            # Metadata
            'chassis_id': chassis_id,
            'port_id': port_id,
            'ttl_value': ttl_value,
            'tlv_count': tlv_count,
            'timestamp': timestamp
        }


# MAIN IDS APPLICATION
# Extracted from: github.com/arsheen/IDS-on-SDN-using-Machine-Learning (IDS_RyuApp.py - base structure)
class LLDPIDS(app_manager.RyuApp):
    """Complete LLDP IDS with interception, classification, and mitigation."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # LLDP multicast MAC for VLAN-tagged matching
    LLDP_MAC = '01:80:c2:00:00:0e'

    def __init__(self, *args, **kwargs):
        super(LLDPIDS, self).__init__(*args, **kwargs)

        # Load configuration from YAML
        config = load_config()
        if config is None:
            self.logger.warning("No config.yaml found, using defaults")
            config = {
                'model': {'path': 'mlmodel/02_Training/lldp_rf_model.pkl'},
                'detection': {'enabled_classes': ['flood', 'replay', 'spoofed'],
                             'expected_ttl': 120, 'ttl_tolerance': 10,
                             'window_sec': 10, 'max_flows': 10000},
                'mitigation': {'drop_flow_idle_sec': 30, 'drop_flow_hard_sec': 60},
                'logging': {'file': 'lldp_ids_alerts.log', 'level': 'INFO',
                           'rotate_mb': 10, 'backups': 3}
            }

        # Extract config values
        self.CRITICAL_ATTACKS = config['detection']['enabled_classes']
        self.DROP_IDLE_SEC = config['mitigation']['drop_flow_idle_sec']
        self.DROP_HARD_SEC = config['mitigation']['drop_flow_hard_sec']

        # Logging
        log_path = config['logging']['file']
        log_level = getattr(logging, config['logging']['level'], logging.INFO)
        rotate_mb = config['logging'].get('rotate_mb', 10)
        backups = config['logging'].get('backups', 3)
        self.ids_logger = setup_logger('LLDP-IDS', log_path, log_level, rotate_mb, backups)

        self.ids_logger.info("="*80)
        self.ids_logger.info("LLDP IDS System Starting")
        self.ids_logger.info("="*80)

        # Components with config
        self.feature_extractor = LLDPFeatureExtractor(
            expected_ttl=config['detection']['expected_ttl'],
            ttl_tolerance=config['detection']['ttl_tolerance'],
            window_sec=config['detection']['window_sec'],
            max_flows=config['detection']['max_flows']
        )

        self.datapaths = {}
        self.stats = {
            'total': 0,
            'normal': 0,
            'attacks': 0,
            'dropped': 0,
            'by_type': defaultdict(int)
        }

        # Latency tracking
        self.latencies = []

        # Load model from configured path
        self.MODEL_PATH = config['model']['path']
        if not os.path.isabs(self.MODEL_PATH):
            self.MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.MODEL_PATH)

        self._load_model()
        self.ids_logger.info("System initialized successfully")

    def _load_model(self):
        """Load Random Forest model with validation."""
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
                    self.ids_logger.error(f"Feature mismatch! Expected 5, model has {self.model.n_features_in_}")

            # No scaler needed - model trained on raw features (verified in train_rf_model.py)

        except Exception as e:
            self.ids_logger.error(f"Model load failed: {e}")
            self.model = None

    # OPENFLOW EVENT HANDLERS
    # Extracted from: github.com/macauleycheng/AOS_OF_Example (packet_lldp_in_out.py - flow installation)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install LLDP interception flows only (no table-miss)."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.ids_logger.info(f"Switch connected: DPID={datapath.id}")

        # High-priority LLDP interception (eth_type=0x88cc)
        # Extracted from: packet_lldp_in_out.py (OFPMatch with eth_type)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 65535, match, actions)

        # VLAN-tagged LLDP (match LLDP multicast MAC)
        match = parser.OFPMatch(eth_dst=self.LLDP_MAC)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 65534, match, actions)

        self.ids_logger.info(f"LLDP flows installed on DPID={datapath.id}")

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        """Install flow entry with optional timeouts."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle,
            hard_timeout=hard
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

    # PACKET PROCESSING
    # Extracted from: packet_lldp_in_out.py (packet_in_handler with LLDP routing)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Route packets to LLDP handler."""
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.dst == self.LLDP_MAC:
            self._handle_lldp(ev, pkt)

    # LLDP PROCESSING WITH ML CLASSIFICATION
    # Extracted from: IDS_RyuApp.py (classification pipeline) + predictionapp.py (ML inference)
    def _handle_lldp(self, ev, pkt):
        """Complete LLDP processing with ML classification and mitigation."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        t_start = time.perf_counter()  # Latency tracking
        self.stats['total'] += 1

        try:
            # Parse LLDP
            pkt_lldp = pkt.get_protocol(lldp.lldp)
            if not pkt_lldp:
                self.ids_logger.warning(f"LLDP parse failed: DPID={datapath.id} port={in_port}")
                self._forward_to_topology(ev)  # Fail open
                return

            # Extract features
            features = self.feature_extractor.extract_features(pkt_lldp, len(msg.data), time.time())

            # Classify
            if not self.model:
                self.ids_logger.error("Model unavailable")
                self._forward_to_topology(ev)  # Fail open
                return

            # Feature vector (training order from train_rf_model.py)
            feature_vec = [[
                features['packet_rate_win'],
                features['age_since_first'],
                features['tlv_density'],
                features['ttl_dev'],
                features['ttl_anom_flag']
            ]]

            prediction = self.model.predict(feature_vec)[0]
            confidence = self.model.predict_proba(feature_vec).max()

            # Measure latency
            t_end = time.perf_counter()
            latency_ms = (t_end - t_start) * 1000
            self.latencies.append(latency_ms)

            # Decision and action
            if prediction in self.CRITICAL_ATTACKS:
                self._handle_attack(prediction, confidence, features, datapath, in_port, latency_ms)
            else:
                self._handle_normal(prediction, confidence, latency_ms)
                self._forward_to_topology(ev)  # Forward normal LLDP

        except Exception as e:
            self.ids_logger.error(f"Processing error: {e}")
            self._forward_to_topology(ev)  # Fail open

    # ATTACK HANDLING WITH PERSISTENT MITIGATION
    # Extracted from: IDS_RyuApp.py (attack logging) + switches.py (flow installation)
    def _handle_attack(self, attack_type, confidence, features, datapath, in_port, latency_ms):
        """Log attack, drop packet, install temporary block flow."""
        self.stats['attacks'] += 1
        self.stats['dropped'] += 1
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

        # Install temporary drop flow (30 second idle timeout)
        # Prevents flood storms and reduces log spam
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=in_port,
            eth_dst=self.LLDP_MAC
        )
        # Empty actions = drop
        self._add_flow(datapath, 65533, match, [], idle=self.DROP_IDLE_SEC, hard=self.DROP_HARD_SEC)

        # Packet already dropped (not forwarded)

    def _handle_normal(self, prediction, confidence, latency_ms):
        """Log normal classification."""
        self.stats['normal'] += 1
        self.ids_logger.info(f"Normal: {prediction} ({confidence:.1%}) | Latency: {latency_ms:.2f}ms")

    # TOPOLOGY INTEGRATION
    # Extracted from: github.com/faucetsdn/ryu (switches.py - event forwarding)
    def _forward_to_topology(self, ev):
        """Forward legitimate LLDP to topology module."""
        # Send to observers (e.g., ryu.topology.switches)
        # This allows normal topology discovery to work
        self.send_event_to_observers(event.EventPacketIn(ev.msg))

    # STATISTICS API
    # Extracted from: Traffic_Monitor.py (statistics collection)
    def get_stats(self):
        """Return current statistics."""
        avg_latency = np.mean(self.latencies) if self.latencies else 0.0
        median_latency = np.median(self.latencies) if self.latencies else 0.0
        p95_latency = np.percentile(self.latencies, 95) if self.latencies else 0.0

        return {
            'total_packets': self.stats['total'],
            'normal_packets': self.stats['normal'],
            'attacks_detected': self.stats['attacks'],
            'packets_dropped': self.stats['dropped'],
            'detection_rate': (self.stats['attacks'] / self.stats['total'] * 100) if self.stats['total'] > 0 else 0.0,
            'attacks_by_type': dict(self.stats['by_type']),
            'latency_ms_avg': avg_latency,
            'latency_ms_median': median_latency,
            'latency_ms_p95': p95_latency
        }

    def log_stats(self):
        """Log statistics summary."""
        s = self.get_stats()
        self.ids_logger.info("="*80)
        self.ids_logger.info("STATISTICS")
        self.ids_logger.info(f"Total: {s['total_packets']} | Normal: {s['normal_packets']} | Attacks: {s['attacks_detected']} | Dropped: {s['packets_dropped']}")
        self.ids_logger.info(f"Detection Rate: {s['detection_rate']:.2f}%")
        self.ids_logger.info(f"Latency: Avg={s['latency_ms_avg']:.2f}ms | Median={s['latency_ms_median']:.2f}ms | P95={s['latency_ms_p95']:.2f}ms")
        if s['attacks_by_type']:
            for atype, count in s['attacks_by_type'].items():
                self.ids_logger.info(f"  {atype}: {count}")
        self.ids_logger.info("="*80)
