use crate:: {Keystore, LocalKeystore, CKMError};



pub enum Curve {
    Secp256k1(String),
    Secp256R1(String),
    Ed25519(String),
}

pub struct SignRequest<'a> {
    pub path: &'a str,
    pub unsigend_data: Vec<u8>,
    pub key_id: &'a str,
    pub curve: Curve
}


pub struct KeyMaster<Store = LocalKeystore> {
    inner: KeyMasterInner<Store>,
}


pub struct KeyMasterInner<Store> {
    store: Store,
}

impl<Store: Keystore> KeyMaster<Store> {
    pub fn new (store: Store) -> Self {
        Self {
            inner: KeyMasterInner {
                store
            }
        }
    }

    pub fn sign(&self, signRequest: SignRequest) -> Result<Signature, CKMError>{
        todo!()
    }

    pub fn generate_menonic() {}

    pub fn generate_save_seed(curve: Curve, menomic: String) -> Result<String, CKMError>{
        todo!()
    }

}

pub fn dispatch(signRequest: SignRequest, store: &impl Keystore) ->Result<Signature, CKMError> {
    match signRequest.curve {
        Curve::Secp256k1(_) => todo!(),
        _ => todo!()
    }

}