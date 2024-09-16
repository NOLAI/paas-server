use actix_web::{HttpResponse, Responder, HttpRequest, HttpMessage};
use actix_web::web::Bytes;
use libpep::elgamal::{ElGamal};
use libpep::primitives::rsk_from_to;
use libpep::utils::{make_decryption_factor, make_pseudonymisation_factor};
use serde::{Deserialize, Serialize};
use crate::auth_middleware::AuthenticationInfo;
use crate::domain_middleware::DomainInfo;

#[derive(Serialize, Deserialize)]
pub struct EncryptedPseudonym {
    encrypted_pseudonym: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationRequest {
    encrypted_pseudonym: String,
    pseudonym_context_from: String,
    pseudonym_context_to: String,
    enc_context: String,
    dec_context: String,
}

pub async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}
pub async fn random() -> impl Responder {
    let random = libpep::arithmetic::GroupElement::random(&mut rand::thread_rng());
    let enc = libpep::elgamal::encrypt(&random, &libpep::arithmetic::G, &mut rand::thread_rng());

    HttpResponse::Ok().json(EncryptedPseudonym {
        encrypted_pseudonym: enc.encode_to_base64(),
    })
}

fn rsk(msg_in: ElGamal, pseudonym_context_from: String, pseudonym_context_to: String, enc_context: String, dec_context: String) -> ElGamal {
    let v_from = make_pseudonymisation_factor(&"secret".to_string(), &pseudonym_context_from);
    let v_to = make_pseudonymisation_factor(&"secret".to_string(), &pseudonym_context_to);
    let k_from = make_decryption_factor(&"secret".to_string(), &enc_context);
    let k_to = make_decryption_factor(&"secret".to_string(), &dec_context);

    rsk_from_to(&msg_in, &v_from, &v_to, &k_from, &k_to)
}
// pub async fn pseudonymize(item: web::Json<PseudonymizationRequest>, auth: AuthenticationInfo, domain_info: DomainInfo) -> impl Responder {
pub async fn pseudonymize(req: HttpRequest, body: Bytes) -> impl Responder {

    // Access control alleen bij de prefix en niet postfix. Voor nu postfix loggen.
    // dec_context moet gelijk zijn aan jou sessie. 
        
    let auth = req.extensions().get::<AuthenticationInfo>().unwrap().clone();
    let domain_info = req.extensions().get::<DomainInfo>().unwrap().clone();
    let item = serde_json::from_slice::<PseudonymizationRequest>(&body);
    
    println!("{:?}", item); // <- print request body
    println!("{:?}", auth); // <- print authentication info
    println!("{:?}", domain_info); // <- print domain info
    
    let request = item.unwrap();
    
    if !(domain_info.from.contains(&request.enc_context) && domain_info.to.contains(&request.dec_context)) {
        return HttpResponse::Forbidden().body("Domain not allowed");
    }
    
    let msg_in = ElGamal::decode_from_base64(&request.encrypted_pseudonym);
    if msg_in.is_none() {
        return HttpResponse::BadRequest().body("Invalid input");
    }
    let msg_in = msg_in.unwrap();

    let msg_out = rsk(msg_in, request.pseudonym_context_from, request.pseudonym_context_to, request.enc_context, request.dec_context);

    HttpResponse::Ok().json(EncryptedPseudonym {
        encrypted_pseudonym: msg_out.encode_to_base64(),
    })
}