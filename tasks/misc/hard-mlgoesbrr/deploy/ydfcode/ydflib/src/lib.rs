pub mod proto;

use anyhow::{bail, Result};
use std::{collections::HashMap, fs::File, io::{BufReader, Read}, path::PathBuf};

use prost::{bytes, Message};
use proto::{dataset::{Column, DataSpecification}, decision_tree::Node, model::Task, random_forest::Header as RandomForestHeader};
use proto::model::AbstractModel;
use byteorder::{LittleEndian, ReadBytesExt};

static DATA_SPEC: &str = "data_spec.pb";
static HEADER: &str = "header.pb";
static FOREST_HEADER: &str = "random_forest_header.pb";
static NODES_PATH: &str = "nodes-00000-of-00001";

pub struct TreeProto {
    pub abstract_model: AbstractModel,
    pub forest_header: RandomForestHeader,
    pub data_spec: proto::dataset::DataSpecification,
    pub node: TreeNode,
}

pub enum FeatureType {
    Categorical(CategoricalSpec),
    Numerical,
    Boolean,
}

pub struct TreeNode {
    pub raw_node: Node,
    pub pos_child: Option<Box<TreeNode>>,
    pub neg_child: Option<Box<TreeNode>>,
}

impl TreeNode {
    pub fn is_leaf(&self) -> bool {
        self.pos_child.is_none()
    }
}

pub struct CategoricalSpec {
    pub items: HashMap<i64, String>
}

pub struct FeatureSpec {
    pub name: String,
    pub feature_type: FeatureType,
    pub raw_proto: Column,
}

pub struct TreeData {
    pub root: TreeNode,
    pub input_features: Vec<i32>,
    pub feature_spec: Vec<FeatureSpec>,
}


fn read_proto<T: Message + Default>(path: PathBuf) -> Result<T> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(T::decode(bytes::Bytes::from(buf))?)
}

fn read_tree_node(reader: &mut BufReader<File>) -> Result<TreeNode> {
    let node_len = reader.read_u32::<LittleEndian>()?;
    let mut buffer = vec![0u8; node_len.try_into().unwrap()];

    reader.read_exact(&mut buffer)?;

    let node = Node::decode(buffer.as_slice())?;

    if node.condition.is_none() {
        return Ok(TreeNode{
            raw_node: node,
            pos_child: None,
            neg_child: None,
        });
    }

    let neg_child = read_tree_node(reader)?;
    let pos_child = read_tree_node(reader)?;
    
    Ok(TreeNode{
        raw_node: node,
        pos_child: Some(Box::new(pos_child)),
        neg_child: Some(Box::new(neg_child)),
    })
}

fn read_node(path: PathBuf) -> Result<TreeNode> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut magic_buf = vec![0u8; 2];

    reader.read_exact(&mut magic_buf)?;

    if magic_buf != [b'B', b'S'] {
        bail!("Invalid magic number");
    }

    let version = reader.read_u16::<LittleEndian>()?;

    if version != 0 {
        bail!("Invalid version");
    }

    let _ = reader.read_u32::<LittleEndian>()?;

    read_tree_node(&mut reader)
}

fn read_tree(base_path: PathBuf) -> Result<TreeProto> {
    let data_spec: proto::dataset::DataSpecification = read_proto(base_path.join(DATA_SPEC))?;
    

    let abstract_model: proto::model::AbstractModel = read_proto(base_path.join(HEADER))?;


    let forest_header: RandomForestHeader = read_proto(base_path.join(FOREST_HEADER))?;

    if abstract_model.task() != Task::Regression {
        bail!("Only regression task is supported");
    }

    if forest_header.num_trees() != 1 {
        bail!("Only single tree models are supported");
    }

    if forest_header.node_format() != "BLOB_SEQUENCE" {
        bail!("Only BLOB_SEQUENCE node format is supported");
    }

    let node = read_node(base_path.join(NODES_PATH))?;

    let tree_metadata: TreeProto = TreeProto{
        abstract_model,
        forest_header,
        data_spec,
        node,
    };
    Ok(tree_metadata)
}

fn process_column(col: Column) -> FeatureSpec {
    let feature_name = col.name().to_string();

    if let Some(ref cat_spec) = col.categorical {
        let mut inverse = HashMap::new();
        for (key, item) in cat_spec.items.iter() {
            inverse.insert(item.index(), key.clone());
        }
        return FeatureSpec{
            name: feature_name,
            feature_type: FeatureType::Categorical(CategoricalSpec{items: inverse}),
            raw_proto: col,
        };
    }
    if col.numerical.is_some() {
        return FeatureSpec{
            name: feature_name,
            feature_type: FeatureType::Numerical,
            raw_proto: col,
        };
    }
    if col.boolean.is_some() {
        return FeatureSpec{
            name: feature_name,
            feature_type: FeatureType::Boolean,
            raw_proto: col,
        }
    }
    panic!("Unsupported feature type");
}

fn parse_data_spec(data_spec: DataSpecification) -> Vec<FeatureSpec> {
    let mut feature_spec = Vec::new();
    for feature in data_spec.columns {
        feature_spec.push(process_column(feature));
    }
    
    feature_spec
}


fn convert_tree(proto: TreeProto) -> Result<TreeData> {
    Ok(TreeData{
        root: proto.node,
        input_features: proto.abstract_model.input_features,
        feature_spec: parse_data_spec(proto.data_spec),
    })
}

pub fn parse_tree(base_path: PathBuf) -> Result<TreeData> {
    convert_tree(read_tree(base_path)?)
}
