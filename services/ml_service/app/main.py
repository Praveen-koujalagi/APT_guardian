import os, time, threading, asyncio, json
from typing import Optional, List
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
from .model import build_model, BaseAnomalyModel
from .db import mongo, graph, ensure_graph_constraints
from .blockchain_client import ChainClient

THRESH = float(os.getenv("ANOMALY_THRESHOLD", "0.65"))

app = FastAPI(title="APT Guardian ML Service", version="0.1.0")

MODEL_KIND = os.getenv("MODEL_KIND", "iforest")
detector: BaseAnomalyModel = build_model(MODEL_KIND, threshold=THRESH)
ensure_graph_constraints()
chain = ChainClient()
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "false").lower() == "true"
KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "netflows")

class NetEvent(BaseModel):
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    proto: str = "TCP"
    bytes: int = 0
    duration: float = 0.01
    ts: Optional[float] = Field(default_factory=lambda: time.time())
    meta: Optional[dict] = None

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ingest")
def ingest(evt: NetEvent):
    evt_dict = evt.model_dump()
    evt_dict["createdAt"] = datetime.utcnow()
    is_bad, score = detector.is_anomalous(evt_dict)
    evt_dict["anomaly_score"] = score
    evt_dict["is_anomaly"] = bool(is_bad)

    # Store raw event
    mongo.raw_events.insert_one(evt_dict)

    incident_tx = None
    if is_bad:
        # Save alert
        alert = {
            "src": evt.src, "dst": evt.dst, "score": score, "proto": evt.proto,
            "bytes": evt.bytes, "ts": evt.ts, "createdAt": datetime.utcnow(),
            "explanation": "IsolationForest baseline flagged this flow as anomalous."
        }
        mongo.alerts.insert_one(alert)
        # Graph: upsert hosts and link
        graph.run("MERGE (a:Host {ip:$src})", src=evt.src)
        graph.run("MERGE (b:Host {ip:$dst})", dst=evt.dst)
        graph.run("""            MATCH (a:Host {ip:$src}), (b:Host {ip:$dst})
            MERGE (a)-[r:SUSPICIOUS {proto:$proto}]->(b)
            ON CREATE SET r.firstSeen = datetime(), r.bytes=$bytes, r.score=$score
            ON MATCH SET r.lastSeen = datetime(), r.bytes = coalesce(r.bytes,0)+$bytes, r.score=max(r.score, $score)
        """, src=evt.src, dst=evt.dst, proto=evt.proto, bytes=evt.bytes, score=score)

        # Blockchain log (tamper-proof breadcrumbs)
        try:
            details = f"{evt.src}->{evt.dst} {evt.proto} bytes={evt.bytes} score={score:.3f}"
            sev = "HIGH" if score > 0.85 else "MEDIUM"
            incident_tx = chain.log_incident(details, sev)  # returns tx hash
        except Exception as e:
            incident_tx = None

    return {"ok": True, "anomaly_score": score, "is_anomaly": bool(is_bad), "incident_tx": incident_tx}


@app.get("/model/info")
def model_info():
    return detector.info()


class TrainRequest(BaseModel):
    limit: int = 2000  # number of most recent raw events to pull for retraining
    query_minutes: int = 60  # window backward in minutes


def _load_recent_events(limit: int, minutes: int) -> List[dict]:
    cutoff = time.time() - (minutes * 60)
    cursor = mongo.raw_events.find({"ts": {"$gte": cutoff}}).sort("ts", -1).limit(limit)
    return list(cursor)


def _retrain_job(limit: int, minutes: int):
    try:
        events = _load_recent_events(limit, minutes)
        metrics = detector.fit(events)
        # persist metrics in Mongo
        mongo.model_metrics.insert_one({
            **metrics.__dict__,
            "createdAt": time.time()
        })
        print(f"[Model] Retrained {detector.name} on {metrics.train_samples} samples")
    except Exception as e:
        print(f"[Model] Retrain failed: {e}")


@app.post("/model/retrain")
def retrain(req: TrainRequest, background: BackgroundTasks):
    background.add_task(_retrain_job, req.limit, req.query_minutes)
    return {"ok": True, "status": "scheduled"}


def _periodic_retrainer():  # lightweight periodic job (every 15 mins)
    interval = int(os.getenv("MODEL_AUTORETRAIN_MINUTES", "15"))
    if interval <= 0:
        return
    while True:
        _retrain_job(limit=1500, minutes=interval)
        time.sleep(interval * 60)


@app.on_event("startup")
def _startup_bg():
    t = threading.Thread(target=_periodic_retrainer, daemon=True)
    t.start()
    if KAFKA_ENABLED:
        loop = asyncio.get_event_loop()
        loop.create_task(_start_kafka_consumer())


async def _start_kafka_consumer():  # pragma: no cover - runtime integration
    try:
        from aiokafka import AIOKafkaConsumer
    except ImportError:
        print("[Kafka] aiokafka not installed; skipping consumer.")
        return
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )
    await consumer.start()
    print(f"[Kafka] consuming from {KAFKA_TOPIC} at {KAFKA_BROKERS}")
    try:
        async for msg in consumer:
            evt = msg.value
            try:
                ingest(NetEvent(**evt))  # reuse existing path
            except Exception as e:
                print("[Kafka] ingest error", e)
    finally:
        await consumer.stop()

@app.get("/alerts/latest")
def latest_alerts(limit: int = 25):
    docs = list(mongo.alerts.find().sort("createdAt", -1).limit(limit))
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"alerts": docs}
