/*! PeerInfoRequest struct.
*/

use nom::{be_u32, be_u64};

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;

/** PeerInfoRequest is a struct that holds info to send peer info request packet to a peer.

Serialized form:

Length      | Content
----------- | ------
`1`         | `0x5b`
`4`         | `hash id`
`32`        | `PK of sender`
`24`        | `nonce`
`1`         | `0xf4`(packet kind: peer info request)
`8`         | `message id`
`4`         | `sender pk hash`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerInfoRequest {
    hash_id: u32,
    sender_pk: PublicKey,
    nonce: Nonce,
    message_id: u64,
    sender_pk_hash: u32,
}

impl FromBytes for PeerInfoRequest {
    named!(from_bytes<PeerInfoRequest>, do_parse!(
        tag!("\x5b") >>
        hash_id: be_u32 >>
        sender_pk: call!(PublicKey::from_bytes) >>
        nonce: call!(Nonce::from_bytes) >>
        tag!(&[0xf4][..]) >>
        message_id: be_u64 >>
        sender_pk_hash: be_u32 >>
        (PeerInfoRequest {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
        })
    ));
}

impl ToBytes for PeerInfoRequest {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x5b) >>
            gen_be_u32!(self.hash_id) >>
            gen_slice!(self.sender_pk.as_ref()) >>
            gen_slice!(self.nonce.as_ref()) >>
            gen_be_u8!(0xf4) >>
            gen_be_u64!(self.message_id) >>
            gen_be_u32!(self.sender_pk_hash)
        )
    }
}

impl PeerInfoRequest {
    /// Create new PeerInfoRequest object.
    pub fn new(hash_id: u32, sender_pk: PublicKey, nonce: Nonce, message_id: u64, sender_pk_hash: u32) -> Self {
        PeerInfoRequest {
            hash_id,
            sender_pk,
            nonce,
            message_id,
            sender_pk_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        announce_peer_encode_decode,
        PeerInfoRequest::new(1, gen_keypair().0, gen_nonce(), 2, 3)
    );
}
