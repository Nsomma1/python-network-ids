"""Unit tests for the IDS. Uses synthetic Scapy packets, so no network
access, root privileges, or Npcap capture is needed."""
import os
import sys
import time

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ids import AlertSystem, DetectionEngine, PacketCapture, TrafficAnalyzer  # noqa: E402


def make_packet(src, dst, sport, dport, flags="S", payload=None):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload is not None:
        pkt = pkt / Raw(load=payload)
    pkt.time = time.time()
    return pkt


def run(analyzer, engine, pkt):
    features = analyzer.analyze_packet(pkt)
    return engine.collect_or_detect(pkt, features)


@pytest.fixture
def analyzer():
    return TrafficAnalyzer()


@pytest.fixture
def engine(tmp_path, monkeypatch):
    # Run in a temp dir so a stray anomaly_model.pkl is never loaded/written
    monkeypatch.chdir(tmp_path)
    return DetectionEngine(enable_anomaly_detection=False)


# ---------- Signature detection ----------

def test_syn_flood_detected(analyzer, engine):
    fired = []
    for i in range(25):
        pkt = make_packet("10.0.0.5", "10.0.0.1", 40000 + i, 80, flags="S")
        fired += [t["rule"] for t in run(analyzer, engine, pkt)]
    assert "syn_flood" in fired


def test_syn_flood_alerts_only_once_during_cooldown(analyzer, engine):
    count = 0
    for i in range(60):
        pkt = make_packet("10.0.0.5", "10.0.0.1", 40000 + i, 80, flags="S")
        count += sum(t["rule"] == "syn_flood" for t in run(analyzer, engine, pkt))
    assert count == 1


def test_syn_flood_not_triggered_by_normal_handshakes(analyzer, engine):
    for i in range(5):
        pkt = make_packet("10.0.0.5", "10.0.0.1", 40000 + i, 80, flags="S")
        threats = run(analyzer, engine, pkt)
        assert not any(t["rule"] == "syn_flood" for t in threats)


def test_port_scan_detected_on_syn_attempts(analyzer, engine):
    fired = []
    for port in range(1, 21):
        pkt = make_packet("10.0.0.9", "10.0.0.1", 55000, port, flags="S")
        fired += [t["rule"] for t in run(analyzer, engine, pkt)]
    assert "port_scan" in fired


def test_port_scan_ignores_established_traffic(analyzer, engine):
    for port in range(1, 21):
        pkt = make_packet("10.0.0.9", "10.0.0.1", 55000, port, flags="A")
        threats = run(analyzer, engine, pkt)
        assert not any(t["rule"] == "port_scan" for t in threats)


def test_port_scan_state_expires(analyzer):
    engine = DetectionEngine(enable_anomaly_detection=False, state_ttl_seconds=0)
    engine._last_cleanup = 0  # force cleanup on next call
    for port in range(1, 10):
        run(analyzer, engine, make_packet("10.0.0.9", "10.0.0.1", 55000, port, flags="S"))
    time.sleep(0.01)
    engine._last_cleanup = 0
    engine._cleanup_state(time.time())
    assert len(engine.port_history) == 0


@pytest.mark.parametrize("payload,expected", [
    (b"GET /?id=1' OR '1'='1 HTTP/1.1\r\n\r\n", "SQL Injection"),
    (b"GET /?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\n\r\n", "SQL Injection"),
    (b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n", "Cross-Site Scripting"),
    (b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n\r\n", "Cross-Site Scripting"),
    (b"GET /../../etc/passwd HTTP/1.1\r\n\r\n", "Path Traversal"),
])
def test_http_signatures(analyzer, engine, payload, expected):
    pkt = make_packet("10.0.0.9", "10.0.0.1", 55000, 8080, flags="PA", payload=payload)
    threats = run(analyzer, engine, pkt)
    assert any(expected in t["rule"] for t in threats)


def test_benign_http_not_flagged(analyzer, engine):
    pkt = make_packet("10.0.0.9", "10.0.0.1", 55000, 8080, flags="PA",
                      payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert run(analyzer, engine, pkt) == []


# ---------- Anomaly detection plumbing ----------

def test_loopback_excluded_from_training(analyzer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = DetectionEngine(enable_anomaly_detection=True, required_training_samples=1000)
    run(analyzer, engine, make_packet("127.0.0.1", "10.0.0.1", 1234, 80, flags="PA"))
    run(analyzer, engine, make_packet("10.0.0.1", "127.0.0.1", 80, 1234, flags="PA"))
    assert len(engine.training_data) == 0


def test_non_loopback_collected_for_training(analyzer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = DetectionEngine(enable_anomaly_detection=True, required_training_samples=1000)
    run(analyzer, engine, make_packet("10.0.0.2", "10.0.0.1", 1234, 80, flags="PA"))
    assert len(engine.training_data) == 1


def test_model_trains_and_saves(analyzer, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = DetectionEngine(enable_anomaly_detection=True, required_training_samples=20)
    for i in range(20):
        run(analyzer, engine, make_packet("10.0.0.2", "10.0.0.1", 2000 + i, 80, flags="PA"))
    assert engine.is_trained
    assert (tmp_path / "anomaly_model.pkl").exists()


# ---------- Feature extraction ----------

def test_features_use_sliding_window(analyzer):
    base = time.time()
    # one old packet, then a long gap, then a new packet in the same flow
    old = make_packet("10.0.0.2", "10.0.0.1", 1234, 80, flags="PA")
    old.time = base
    analyzer.analyze_packet(old)
    new = make_packet("10.0.0.2", "10.0.0.1", 1234, 80, flags="PA")
    new.time = base + 100
    features = analyzer.analyze_packet(new)
    # old packet fell out of the window, so only 1 packet counts
    key = ("10.0.0.2", "10.0.0.1", 1234, 80)
    assert len(analyzer.flow_stats[key]["recent"]) == 1
    assert features["packet_rate"] <= 100


def test_flow_table_is_bounded():
    analyzer = TrafficAnalyzer()
    analyzer.MAX_FLOWS = 50
    for i in range(200):
        analyzer.analyze_packet(make_packet("10.0.0.2", "10.0.0.1", 1000 + i, 80, flags="PA"))
    assert len(analyzer.flow_stats) <= 50


# ---------- Infrastructure fixes ----------

def test_stop_before_start_does_not_crash():
    PacketCapture().stop()


def test_alert_system_does_not_duplicate_handlers(tmp_path):
    log = str(tmp_path / "alerts.log")
    AlertSystem(log_file=log)
    before = len(AlertSystem(log_file=log).logger.handlers)
    AlertSystem(log_file=log)
    after = len(AlertSystem(log_file=log).logger.handlers)
    assert before == after


def test_alert_generation_handles_missing_fields(tmp_path, capsys):
    alerts = AlertSystem(log_file=str(tmp_path / "alerts.log"))
    alerts.generate_alert({"type": "signature", "rule": "x", "confidence": 1.0}, {})
    assert "IDS ALERT" in capsys.readouterr().out
