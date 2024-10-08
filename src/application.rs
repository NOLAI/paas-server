use std::env;
use std::sync::Arc;
use actix_web::{HttpResponse, Responder, HttpRequest, HttpMessage, web};
use actix_web::web::{Bytes, Data};
use libpep::arithmetic::ScalarTraits;
use libpep::distributed::PEPSystem;
use libpep::elgamal::{ElGamal};
use libpep::high_level::{EncryptedPseudonym, EncryptionContext, PseudonymizationContext};
use serde::{Deserialize, Serialize};
use crate::auth_middleware::AuthenticationInfo;
use crate::domain_middleware::DomainInfo;
use crate::redis_connector::RedisConnector;

#[derive(Serialize, Deserialize)]
pub struct EncryptedPseudonymResponse {
    encrypted_pseudonym: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationRequest {
    encrypted_pseudonym: String,
    pseudonym_context_from: PseudonymizationContext,
    pseudonym_context_to: PseudonymizationContext,
    enc_context: EncryptionContext,
    dec_context: EncryptionContext,
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

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    system_id: String,
    timestamp: String,
}

pub async fn status() -> impl Responder {
    let system_id = env::var("HOSTNAME").unwrap();
    
    HttpResponse::Ok().json(StatusResponse{
        system_id,
        timestamp: chrono::offset::Local::now().to_string()
         })
}

// fn hex_to_blindingfactor(s: &str) -> libpep::distributed::BlindingFactor {
//     let scalar = libpep::arithmetic::ScalarNonZero::decode_from_hex(s).unwrap();
//     libpep::distributed::BlindingFactor(scalar)
// }

pub async fn random() -> impl Responder {
    let random = libpep::arithmetic::GroupElement::random(&mut rand::thread_rng());
    let enc = libpep::elgamal::encrypt(&random, &libpep::arithmetic::G, &mut rand::thread_rng());
    
    // let blindingFactors = vec![hex_to_blindingfactor("7ca60a3b3b7d941625fb84a00443b533c87306b8ffdcb7b3004f3f60d3f9bb06"), hex_to_blindingfactor("aa133d0e28fb9c826d57f5feca2f0a9e812fed958622abfe259547481919e602"), hex_to_blindingfactor("1bfbcb209759d1ca52fed377daba9034b627f5a38d3c1f9b3dba114f1d656c03")];
    // let (public, secret) = libpep::high_level::make_global_keys();
    // let blinded_global = libpep::distributed::make_blinded_global_secret_key(&secret, &blindingFactors);
    // 
    // println!("blinded_global: {:?}", blinded_global.encode_to_hex());
    // println!("public: {:?}", public);
    
    HttpResponse::Ok().json(EncryptedPseudonymResponse {
        encrypted_pseudonym: enc.encode_to_base64(),
    })
}


fn has_access_to_context(from: Arc<Vec<String>>, to: Arc<Vec<String>>, enc_context: EncryptionContext, dec_context: EncryptionContext, user_sessions: Vec<String>) -> bool {
    // Access control alleen bij de prefix en niet postfix. Voor nu postfix loggen.
    // dec_context moet gelijk zijn aan jou sessie. 

    user_sessions.contains(&dec_context) && from.contains(&enc_context) && to.contains(&dec_context)
}

pub async fn pseudonymize(req: HttpRequest, body: Bytes,  redis: Data<RedisConnector>,  pep_system: Data<PEPSystem>) -> impl Responder {
    
    let auth = req.extensions().get::<AuthenticationInfo>().unwrap().clone();
    let domain_info = req.extensions().get::<DomainInfo>().unwrap().clone();
    let item = serde_json::from_slice::<PseudonymizationRequest>(&body);

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
    let msg_in = EncryptedPseudonym::new(msg_in.unwrap());
    let msg_out = pep_system.pseudonymize(&msg_in, 
                                          &pep_system.pseudonymization_info(
                                              &request.pseudonym_context_from, &request.pseudonym_context_to, 
                                              &request.enc_context, &request.dec_context));

    HttpResponse::Ok().json(EncryptedPseudonymResponse {
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