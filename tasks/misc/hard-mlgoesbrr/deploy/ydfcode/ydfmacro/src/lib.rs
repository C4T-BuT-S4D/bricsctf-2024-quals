extern crate proc_macro;

use core::f32;

use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};

use ydflib::{parse_tree, proto::decision_tree::{condition::Type as ConditionType, node::Output}, CategoricalSpec, FeatureSpec, FeatureType, TreeData, TreeNode};


fn generate_field_name(c_name: &String) -> String {
    c_name.to_case(Case::Snake)
}

fn get_enum_name_for_categorical(c_name: &String) -> String {
    c_name.to_case(Case::Pascal)
}

fn generate_enum_definitions(c_name: &String, cat_spec: &CategoricalSpec) -> impl ToTokens {
    let enum_options = cat_spec.items.iter().map(|it| {
        let option_str = format!("#[serde(rename = \"{}\")]", it.1);
        let option_stream: proc_macro2::TokenStream = option_str.parse().unwrap();
        let option_name = format_ident!("Option{}", it.0.to_string());
        let option_value = *it.0 as isize;
        let kek = quote! {
            #option_stream
            #option_name = #option_value
        };
        kek
    });

    let enum_name = format_ident!("{}", get_enum_name_for_categorical(c_name));
    quote! {
        #[derive(Debug, PartialEq,::serde::Serialize, ::serde::Deserialize, Clone, Copy)]
        enum #enum_name {
            #(#enum_options),*
        }

    }
}

fn generate_struct(tree: &TreeData) -> impl ToTokens {
    let enum_definitions = tree.feature_spec.iter().filter_map(|col| {
        if let FeatureType::Categorical(cat_spec) = &col.feature_type {
            return Some(generate_enum_definitions(&col.name, cat_spec))
        }
        None
    });
    let input_features = tree.input_features.iter().map(|i| tree.feature_spec.get(*i as usize).unwrap());
    let features = input_features.map(|col| {
        let field_name = format_ident!("{}", generate_field_name(&col.name));
        let col_type = match &col.feature_type {
            ydflib::FeatureType::Categorical(_) => get_enum_name_for_categorical(&col.name),
            ydflib::FeatureType::Numerical => "f32".to_string(),
            ydflib::FeatureType::Boolean => "bool".to_string(),
        };
        let col = format_ident!("{}", col_type);
        quote! {
            #field_name: #col
        }
    });
    quote! {
        #(#enum_definitions)*

        #[derive(::serde::Serialize, ::serde::Deserialize)]
        struct TreeInput {
            #(#features),*
        }
    }
}

fn generate_condition(cond_type: &ConditionType, field_name: impl ToTokens) -> impl ToTokens {
    match cond_type {
        ydflib::proto::decision_tree::condition::Type::NaCondition(_) => todo!(),
            ydflib::proto::decision_tree::condition::Type::HigherCondition(higher) => {
                let val = higher.threshold();
                quote! {
                    input.#field_name >= #val
                }
            }
            ydflib::proto::decision_tree::condition::Type::TrueValueCondition(_) => {
                quote! {
                    input.#field_name
                }
            },
            ydflib::proto::decision_tree::condition::Type::ContainsCondition(_) => todo!(),
            ydflib::proto::decision_tree::condition::Type::ContainsBitmapCondition(contains_bitmap) => {
                let mut variants: Vec<i32> = Vec::new();
                for i in 0..contains_bitmap.elements_bitmap().len() {
                    for j in 0..8 {
                        let bitmap = contains_bitmap.elements_bitmap()[i];
                        let mask = 1 << j;
                        if mask & bitmap > 0 {
                            variants.push((j + i * 8) as i32);
                        }
                    }
                }
                
                let cond_parts = variants.iter().map(|x| {
                    let x = *x as isize;
                    quote! {
                        ((input.#field_name as isize) == #x)
                    }
                });
                quote! {
                    false #(  || #cond_parts )*
                }
            }
            ydflib::proto::decision_tree::condition::Type::DiscretizedHigherCondition(_) => todo!(),
            ydflib::proto::decision_tree::condition::Type::ObliqueCondition(_) => todo!(),
    }    

}

fn generate_branch(tree_node: &TreeNode, features: &Vec<FeatureSpec>) -> impl ToTokens {
    if tree_node.is_leaf() {
        let output = tree_node.raw_node.output.as_ref().unwrap();
        let mut result = f32::NAN;
        if let Output::Regressor(x) = output {
            result = x.top_value();
        }
        return quote! {
            return #result
        }
    }
    
    let neg_node = tree_node.neg_child.as_ref().unwrap();
    let right_node = tree_node.pos_child.as_ref().unwrap();
    let neg_part = generate_branch(neg_node, features);
    let pos_part = generate_branch(right_node, features);
    if let Some(cond) = &tree_node.raw_node.condition {
        let feature = features.get(cond.attribute() as usize).unwrap();
        let field_name = format_ident!("{}", generate_field_name(&feature.name));
        let cond_type = cond.condition.as_ref().and_then(|x| x.r#type.as_ref()).unwrap();
        let cond = generate_condition(cond_type, field_name);
        return quote! {
            if #cond {
                #pos_part
            } else {
                #neg_part
            }
        };
    }
    
    panic!("unexpected node: {:?}", tree_node.raw_node)
}

fn generate_predict_function(tree: &TreeData) -> impl ToTokens {
    let body = generate_branch(&tree.root, &tree.feature_spec);
    quote! {
        fn predict(input: &TreeInput) -> f32 {
            #body
        }
    }
}

fn generate_features_info_function(tree: &TreeData) -> impl ToTokens {
    let input_features = tree.input_features.iter().map(|i| tree.feature_spec.get(*i as usize).unwrap())
    .map(|col| {
        let f_name = generate_field_name(&col.name);
        quote! {
            #f_name.into()
        }
    });
    
        
    quote! {
        fn features_info() -> Vec<String> {
            vec![#(#input_features),*]        
        }
    }
}

#[proc_macro]
pub fn generate_tree(_item: TokenStream) -> TokenStream {
    let path_str = _item.to_string();
    let path_substr: String = path_str.chars().skip(1).take(path_str.len() - 2).collect();
    let path = std::path::PathBuf::from(path_substr);
    let tree = parse_tree(path).unwrap();


    let struct_definition = generate_struct(&tree);
    let info_definition = generate_features_info_function(&tree);
    let predict_definition = generate_predict_function(&tree);
    

    let result = quote! {
        #struct_definition
        #info_definition
        #predict_definition
    };
    result.into()
}