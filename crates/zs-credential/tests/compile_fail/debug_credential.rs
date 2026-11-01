use zs_credential::Credential;

fn main() {
    let c = Credential::from_bytes(vec![1, 2, 3]).unwrap();
    println!("{:?}", c);
}
