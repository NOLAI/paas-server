use std::sync::Arc;
use actix_web::{HttpResponse, Responder, HttpRequest, HttpMessage, web};
use actix_web::web::{Bytes, Data};
use libpep::arithmetic::ScalarTraits;
use libpep::distributed::PEPSystem;
use libpep::elgamal::{ElGamal};
use libpep::high_level::EncryptionContext;
use libpep::primitives::rsk_from_to;
use libpep::utils::{make_decryption_factor, make_pseudonymisation_factor};
use serde::{Deserialize, Serialize};
use crate::auth_middleware::AuthenticationInfo;
use crate::domain_middleware::DomainInfo;
use crate::redis_connector::RedisConnector;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct EndSessionRequest {
    session_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct StartSessionResponse {
    session_id: String,
    key_share: String,
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


fn has_access_to_context(from: Arc<Vec<String>>, to: Arc<Vec<String>>, enc_context: String, dec_context: String, user_sessions: Vec<String>) -> bool {
    user_sessions.contains(&dec_context) && from.contains(&enc_context) && to.contains(&dec_context)
}

pub async fn pseudonymize(req: HttpRequest, body: Bytes,  redis: Data<RedisConnector>) -> impl Responder {

    // Access control alleen bij de prefix en niet postfix. Voor nu postfix loggen.
    // dec_context moet gelijk zijn aan jou sessie. 
        
    let auth = req.extensions().get::<AuthenticationInfo>().unwrap().clone();
    let domain_info = req.extensions().get::<DomainInfo>().unwrap().clone();
    let item = serde_json::from_slice::<PseudonymizationRequest>(&body);
    
    println!("{:?}", item); // <- print request body
    println!("{:?}", auth); // <- print authentication info
    println!("{:?}", domain_info); // <- print domain info
    
    let request = item.unwrap();

    let mut redis_connector = redis.get_ref().clone();
    let sessions = redis_connector.get_sessions_for_user(auth.username.to_string()).expect("Failed to get sessions");
    
    if !(has_access_to_context(domain_info.from, domain_info.to, request.enc_context.clone(), request.dec_context.clone(), sessions)) {
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

pub async fn rekey() -> impl Responder {
    HttpResponse::Ok().body("Rekey")
}

pub async fn start_session(req: HttpRequest, redis: Data<RedisConnector>, pep_system: Data<PEPSystem>) -> impl Responder {
    let auth = req.extensions().get::<AuthenticationInfo>().unwrap().clone();
    let mut redis_connector = redis.get_ref().clone();
    
    let session_id = redis_connector.start_session(auth.username.to_string()).unwrap();
    
    let key_share = pep_system.session_key_share(&EncryptionContext(session_id.clone())).encode_to_hex();
    
    HttpResponse::Ok().json(StartSessionResponse {
        session_id,
        key_share
    })
}

pub async fn end_session(item: web::Json<EndSessionRequest>, req: HttpRequest, data: Data<RedisConnector>) -> impl Responder {
    let auth = req.extensions().get::<AuthenticationInfo>().unwrap().clone();
    let session_id = item.session_id.clone();
    let username_in_session = session_id.split('_').next().unwrap();
    let mut redis_connector = data.get_ref().clone();
    
    if auth.username.as_str() != username_in_session {
        return HttpResponse::Forbidden().body("Session not owned by user");
    }
    
    redis_connector.end_session(auth.username.to_string(), session_id).unwrap();
    
    HttpResponse::Ok().json({})
}