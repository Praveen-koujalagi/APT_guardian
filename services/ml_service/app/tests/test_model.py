from app.model import build_model
from app.graph_builder import build_snapshot


def test_factory_iforest():
    m = build_model("iforest", 0.5)
    assert m.name == "isolation_forest"
    evt = {"bytes": 1000, "duration": 0.1, "dport": 80, "sport": 50000}
    score = m.score_event(evt)
    assert 0 <= score <= 1


def test_graph_builder_basic():
    events = [
        {"src": "10.0.0.1", "dst": "10.0.0.2", "bytes": 100, "dport": 80},
        {"src": "10.0.0.2", "dst": "10.0.0.1", "bytes": 200, "dport": 22},
    ]
    snap = build_snapshot(events)
    assert len(snap["nodes"]) == 2
    assert snap["edge_index"].shape[1] == 2
