use crate::issuer::{attr_tree::AttributeTree, attribute_set::AttributeSet};

pub mod crypto;
pub mod issuer;

fn main() {
    let name: String = String::from("Sufi");
    let gender : &str = "X";
    let dob: u64 = 20040613;
    let country: &str = "IND";

    let set = AttributeSet::new(name, gender, dob, country).unwrap();
    let leaves = set.leaf_hashes().unwrap();
    let salts = set.salts();

    println!("leaves: {:?}",leaves);
    println!("salts: {:?}", salts);

    let tree = AttributeTree::new(&set).unwrap();
    println!("Attibute Tree: {:?}", tree);
}
