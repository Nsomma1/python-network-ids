from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from collections import defaultdict, deque
import threading, queue, logging, json, re, joblib, os, time

from scapy.packet import Raw
from sklearn.ensemble import IsolationForest
import numpy as np
from datetime import datetime
from urllib.parse import unquote

# Captures packets with both IP and TCP layers and places them into a queue
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.capture_thread = None

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface):
        def capture_thread():
            # sniff() is looped with a small timeout in order to poll the flag even if
            # the interface is idle.
            while not self.stop_capture.is_set():
                sniff(iface=interface,
                      prn=self.packet_callback,
                      store=0,
                      timeout=1,
                      stop_filter=lambda _: self.stop_capture.is_set())

        # This marks the thread as daemon so it can't keep the process alive
        # if something else crashes before stop() is called.
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        # Prevents a crash if stop() is called before packet capture starts
        if self.capture_thread is not None:
            self.capture_thread.join()

# Analyzes packets for information like source IP and port and destination IP and port
class TrafficAnalyzer:
    # Tracks a short window of recent packet timestamps and sizes per flow
    WINDOW_SECONDS = 5.0
    MAX_FLOWS = 20000  # cap to bound memory on long-running captures

    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'start_time': None,
            'last_time': None,
            'recent': deque()  # (timestamp, size)
        })

    # drops the flows that have been idle the longest
    def _prune_flows(self, now):
        if len(self.flow_stats) <= self.MAX_FLOWS:
            return
        stale = sorted(self.flow_stats.items(), key=lambda kv: kv[1]['last_time'] or 0)
        for key, _ in stale[: len(self.flow_stats) - self.MAX_FLOWS]:
            del self.flow_stats[key]
    # looks up the flow then records this packet and drops entries older than 5 seconds from the front of the deque
    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)
            stats = self.flow_stats[flow_key]
            current_time = packet.time
            pkt_len = len(packet)

            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            stats['recent'].append((current_time, pkt_len))
            while stats['recent'] and current_time - stats['recent'][0][0] > self.WINDOW_SECONDS:
                stats['recent'].popleft()

            self._prune_flows(current_time)

            return self.extract_features(packet, stats, current_time)

    def extract_features(self, packet, stats, current_time):
        window_start = stats['recent'][0][0] if stats['recent'] else current_time
        window_duration = max(current_time - window_start, 0.01)
        window_packets = len(stats['recent'])
        window_bytes = sum(size for _, size in stats['recent'])

        return {
            # not used by the model but kept for future detection rules
            # could be used to detect very short flows common in scans
            'flow_duration': current_time - stats['start_time'],

            # Used in the model
            'packet_size': len(packet),
            'packet_rate': min(window_packets / window_duration, 10000),
            'byte_rate': min(window_bytes / window_duration, 10000000),
            'tcp_flags': str(packet[TCP].flags),
        }

# Uses an isolation forrest model trained on normal traffic to detect anomalies on the network
class DetectionEngine:
    def __init__(self, enable_anomaly_detection=True, required_training_samples=500,
                 state_ttl_seconds=300):
        self.syn_timestamps = defaultdict(list)
        self.enable_anomaly_detection = enable_anomaly_detection
        self.required_training_samples = required_training_samples
        self.training_data = []
        self.is_trained = False
        self.state_ttl_seconds = state_ttl_seconds
        self._last_cleanup = time.time()

        if enable_anomaly_detection and os.path.exists("anomaly_model.pkl"):
            try:
                self.anomaly_detector = joblib.load("anomaly_model.pkl")
                self.is_trained = True
                print("*** Loaded pre-trained Isolation Forest model from disk.")
            except Exception as e:
                print(f"Error loading saved model ({e}), initializing fresh model.")
                self.anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
        elif enable_anomaly_detection:
            self.anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
        else:
            self.anomaly_detector = None
        # Memory that the signature rules use to track behavior over time
        self.port_history = defaultdict(dict)
        self.alerted_scanners = {}
        self.alerted_syn_floods = {}

        # Regex for common web attacks (could cause false positives i.e. "--" is common in legitimate network traffic)
        self.web_signatures = {
            'SQL Injection (SQLi)': re.compile(r"(UNION\s+SELECT|' OR '1'='1|--|SELECT\s+.*\s+FROM)", re.IGNORECASE),
            'Cross-Site Scripting (XSS)': re.compile(r"(<script>|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE),
            'Path Traversal': re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|win\.ini)", re.IGNORECASE)
        }

    # Cleans expired entries to prevent infinite growth and to allow alerts to trigger on the same IP multiple times
    def _cleanup_state(self, now):
        if now - self._last_cleanup < 30:
            return
        self._last_cleanup = now

        for flow in list(self.syn_timestamps.keys()):
            self.syn_timestamps[flow] = [t for t in self.syn_timestamps[flow] if now - t <= 2.0]
            if not self.syn_timestamps[flow]:
                del self.syn_timestamps[flow]

        for src in list(self.port_history.keys()):
            ports = self.port_history[src]
            for port in list(ports.keys()):
                if now - ports[port] > self.state_ttl_seconds:
                    del ports[port]
            if not ports:
                del self.port_history[src]

        for d in (self.alerted_scanners, self.alerted_syn_floods):
            for key in list(d.keys()):
                if now - d[key] > self.state_ttl_seconds:
                    del d[key]
    # Trains an isolation forrest based on 500 feature vectors based on normal traffic collected
    # Gives each feature vector a score and sends an alert for any -0.75 or below
    def collect_or_detect(self, packet, features):
        threats = []
        now = time.time()
        self._cleanup_state(now)

        threats.extend(self.detect_signatures(packet, features, now))

        # Skips loop back traffic
        if packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1":
            return threats

        if self.enable_anomaly_detection:
            feature_vector = [
                # Each value is placed on a log scale to prevent big numbers from dominating the model
                np.log1p(features['packet_size']),
                np.log1p(features['packet_rate']),
                np.log1p(features['byte_rate'])
            ]

            if not self.is_trained:
                self.training_data.append(feature_vector)

                if len(self.training_data) >= self.required_training_samples:
                    print(f"*** Collected {len(self.training_data)} samples. Training Isolation Forest baseline...")
                    X_train = np.array(self.training_data)
                    self.anomaly_detector.fit(X_train)
                    self.is_trained = True

                    joblib.dump(self.anomaly_detector, "anomaly_model.pkl")
                    print("*** Anomaly engine trained and saved to 'anomaly_model.pkl'")
                    print("*** Please note: this baseline was trained on whatever traffic was "
                          "captured during startup. If that window included attack "
                          "traffic, it will be treated as normal. "
                          "Train on a known and clean traffic sample instead.")
            else:
                xpredict = np.array([feature_vector])
                anomaly_score = self.anomaly_detector.score_samples(xpredict)[0]

                if anomaly_score < -0.75:
                    threats.append({
                        'type': 'anomaly',
                        'rule': 'network_anomaly_detected',
                        'score': float(anomaly_score),
                        'confidence': 0.75
                    })

        return threats
    # Pulls the raw layer's bytes and decodes them into text. Ignores invalid bytes
    def extract_http_payload(self, packet):
        if packet.haslayer('Raw'):
            try:
                payload_bytes = packet[Raw].load
                return payload_bytes.decode('utf-8', errors='ignore')
            except Exception:
                return None
        return None
    # Detects for SYN Flood, Port Scan, and HTTP attacks
    def detect_signatures(self, packet, features, now):
        threats = []
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport

        flow = (src, dst, dport)
        tcp_flags = features['tcp_flags']

        # Detects a threat if more than 20 SYNs are detected within 2 seconds
        if "S" in tcp_flags and "A" not in tcp_flags:
            self.syn_timestamps[flow].append(now)
            self.syn_timestamps[flow] = [
                t for t in self.syn_timestamps[flow] if now - t <= 2.0
            ]

            if len(self.syn_timestamps[flow]) >= 20 and flow not in self.alerted_syn_floods:
                self.alerted_syn_floods[flow] = now
                threats.append({
                    'type': 'signature',
                    'rule': 'syn_flood',
                    'confidence': 1.0
                })

        # Records which distinct ports each source IP sent SYNs to. If there are 15 or more then an alert is sent
        is_syn_attempt = "S" in tcp_flags and "A" not in tcp_flags
        if is_syn_attempt and (dport < 1024 or dport in [8080, 8000, 8443]):
            self.port_history[src][dport] = now

            if len(self.port_history[src]) >= 15 and src not in self.alerted_scanners:
                self.alerted_scanners[src] = now
                threats.append({
                    'type': 'signature',
                    'rule': 'port_scan',
                    'confidence': 1.0
                })

        # Checks raw and decoded HTTP requests for if they match the web signature regexes and sends an alert
        if dport in [80, 8080] or sport in [80, 8080]:
            http_text = self.extract_http_payload(packet)
            if http_text:
                decoded_text = unquote(http_text)
                for attack_name, pattern in self.web_signatures.items():
                    if pattern.search(http_text) or pattern.search(decoded_text):
                        threats.append({
                            'type': 'signature',
                            'rule': f'http_malicious_payload ({attack_name})',
                            'confidence': 0.9,
                            'matched_pattern': pattern.pattern
                        })

        return threats

# Logs threat alerts to a log file
class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        # BUGFIX: previously a new FileHandler was attached every time
        # AlertSystem() was instantiated, so re-constructing it (e.g. in
        # tests, or if the IDS is restarted within the same process) would
        # duplicate every log line once per extra handler.
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    # Creates a dictionary with timestamp, threat type, source and destination IPs
    # and confidence level then logs to a json file and prints to the console
    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat.get('confidence', 0.0) > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )

        print("\n===== IDS ALERT =====")
        print(f"Threat: {threat.get('rule')}")
        print(f"Source: {packet_info.get('source_ip')}:{packet_info.get('source_port')}")
        print(f"Destination: {packet_info.get('destination_ip')}:{packet_info.get('destination_port')}")
        print(f"Confidence: {threat.get('confidence', 0.0)}")
        print("=====================\n")

# Grabs packets from the queue and analyzes it, detects threats, and generates alerts
class IntrusionDetectionSystem:
    def __init__(self, interface):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1) # timeout so that the loops wake up regularly instead of blocking forever
                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        threats = self.detection_engine.collect_or_detect(packet, features)
                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport,
                            }
                            self.alert_system.generate_alert(threat, packet_info)
                except queue.Empty:
                    continue
                except KeyboardInterrupt:
                    print("Stopping IDS...")
                    break
                except Exception as e:
                    # Log any exceptions in order to not stop the loop
                    logging.getLogger("IDS_Alerts").exception(
                        f"Error processing packet: {e}"
                    )
                    continue
        finally:
            # Ensure capture is always stopped
            self.packet_capture.stop()

# parses command line arguments input from the user in order to set the desired interfaces
# without the need for the user to edit the code
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Lightweight network intrusion detection system "
                    "(signature rules + Isolation Forest anomaly detection). "
                    "Only use on networks you own or are authorized to monitor."
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to sniff (name as shown by --list-interfaces)",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        from scapy.all import show_interfaces
        show_interfaces()
        return

    if not args.interface:
        parser.error("--interface is required (use --list-interfaces to see options)")

    ids = IntrusionDetectionSystem(interface=args.interface)
    ids.start()


if __name__ == "__main__":
    main()