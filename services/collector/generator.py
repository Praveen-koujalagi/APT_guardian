import os, time, random, argparse
import numpy as np
import requests
from dotenv import load_dotenv

load_dotenv()
API = os.getenv("ML_API", "http://ml_service:8000/ingest" if os.getenv("DOCKER") else "http://127.0.0.1:8000/ingest")

BENIGN_SUBNETS = ["10.0.0.", "10.0.1.", "192.168.1.", "172.16.0."]
TARGETS = ["10.0.0.5", "10.0.0.8", "10.0.1.10", "192.168.1.200"]

def rand_ip(prefix):
    return prefix + str(random.randint(2, 254))

def gen_event():
    src = rand_ip(random.choice(BENIGN_SUBNETS))
    dst = random.choice(TARGETS)
    proto = random.choice(["TCP","UDP"])
    sport = random.randint(1024, 65535)
    dport = random.choice([22, 80, 443, 3389, 8080, 3306, 5900])
    # Mostly normal, occasionally spiky
    if random.random() < 0.1:
        bytes_ = int(np.random.lognormal(mean=12, sigma=1.2))  # large spike
        duration = float(np.random.exponential(2.5))
    else:
        bytes_ = int(max(50, np.random.normal(5000, 1500)))
        duration = float(np.random.exponential(0.3))
    return {
        "src": src, "dst": dst, "sport": sport, "dport": dport,
        "proto": proto, "bytes": bytes_, "duration": duration, "ts": time.time()
    }

def main(rate):
    interval = 1.0 / rate if rate > 0 else 0.0
    print(f"[generator] sending ~{rate}/sec to {API}")
    while True:
        evt = gen_event()
        try:
            r = requests.post(API, json=evt, timeout=3)
            if r.ok and r.json().get("is_anomaly"):
                print("[ALERT]", r.json())
        except Exception as e:
            print("post error:", e)
        time.sleep(interval)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=2.0, help="events per second")
    args = ap.parse_args()
    main(args.rate)
