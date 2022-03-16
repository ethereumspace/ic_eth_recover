pub mod types;
pub mod utils;

#[cfg(test)]
mod test_encode{
    use rlp::{decode, encode};
    use super::*;
    #[test]
    fn test_rlp(){
       let addr_encode:types::Address = "D32927BF9c8F54C5955Fa415eF9A045cC211125B".parse().unwrap();
       let rlp_data = encode(&addr_encode);
       let addr_decode:types::Address= decode(&rlp_data[..]).unwrap();
       assert_eq!(addr_decode ,addr_encode);
    }
}
