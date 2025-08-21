from ml_models.train import train_models
from ml_models.inference import load_models, predict_flows
import pandas as pd

def test_train_and_infer_small():
    df = pd.DataFrame({
        'src_ip':['1.1.1.1']*20,
        'dst_ip':['2.2.2.2']*20,
        'protocol':['TCP']*20,
        'packet_count': list(range(20)),
        'byte_count': [x*100 for x in range(20)],
        'label':[0]*10 + [1]*10
    })
    trained = train_models({'models':['RandomForest'],'output_dir':'models','dataframe':df})
    assert 'RandomForest' in trained
    bundle = load_models(['RandomForest'])
    flows = [{'src_ip':'1.1.1.1','dst_ip':'2.2.2.2','src_port':1234,'dst_port':80,'protocol':'TCP','packet_count':5,'byte_count':500}]
    pred_df = predict_flows(bundle, flows)
    assert not pred_df.empty
