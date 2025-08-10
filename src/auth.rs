use serde::{Deserialize, Serialize};
use chrono::preliude::*;
use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use crate::{error::Error, Result, WebResult};
use std::fmt;
use warp::{
    fliters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
}

const BEARER: &str = "Bearer";
const JWT_SECRET: &[u8] = b"secret_key";

#[derive(Clone, PartialEq)]
pub enum Role {
    Admin,
    User,
}

impl Role{
    pub fn from_str(role: &str) -> Role{
        match role {
            "Admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "Admin"),
            Role::User => write!(f, "User"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims{
    sub: String,
    role: String,
    exp: usize,
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::header::headers_cloned()
        .and_then(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
}

pub fn create_token(uid: &str, role: &Role) -> Result<String> {

    let expression = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_string(),
        role: role.to_string(),
        exp: expression as usize,
    };

    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|e| Error::JWTTokenCreationError(e.to_string()));
    
}

async fn authorize(
    role: Role,
    headers: HeaderMap<HeaderValue>,
) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|e| reject::custom(Error::JWTTokenError))?;

            if role == Role::Admin && Role::from_str(&decoded.claims.role) != Role::Admin {
                return Err(reject::custom(Error::NoPermissionError));
            }
            Ok(decoded.claims.sub)
        }
        Err(e) => return Err(reject::custom(e)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String> {
    let header = match headers.get(AUTHORIZATION) {
        Some(header) => header,
        None => return Err(Error::MissingAuthorizationHeader),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(header) => header,
        Err(_) => return Err(Error::InvalidAuthorizationHeader),
    };
    if !auth_header.starts_with(BEARER) {
        return Err(Error::InvalidAuthorizationHeader);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}