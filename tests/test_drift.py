from ml_models.drift import detect_drift
import pandas as pd

def test_detect_drift():
    feature_stats = {'f1': {'mean':0.0,'std':1.0,'min':-3,'max':3}}
    batch = pd.DataFrame({'f1':[0,0.1,0.2,0.05,0.3]})
    report = detect_drift(feature_stats, batch)
    assert 'f1' in report
