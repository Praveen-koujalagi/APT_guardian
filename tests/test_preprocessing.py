from ml_models.preprocessing import auto_preprocess
import pandas as pd

def test_auto_preprocess_basic():
    df = pd.DataFrame({
        'src_ip':['1.1.1.1','1.1.1.2'],
        'dst_ip':['2.2.2.2','2.2.2.3'],
        'protocol':['TCP','UDP'],
        'packet_count':[10,20],
        'byte_count':[1000,2000],
        'label':[0,1]
    })
    pipe = auto_preprocess(df)
    assert 'X_train' in pipe and not pipe['X_train'].empty
    assert pipe['artifacts']['feature_list']
