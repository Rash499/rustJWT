use error::Error;
use auth::{with_auth, Role};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::{
    Filter,
    reject,
    reply,
    Rejection,
    Reply,
};

mod auth;
mod error;

#[derive(Clone)]
pub struct User{
    pub uid: String,
    pub email: String,
    pub pw: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub pw: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    let login_route = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    let users_route = warp::path!("user")
        .and(with_auth(Roles::User))
        .and_then(user_handler);

    let admin_route = warp::path!("admin")
        .and(with_auth(Roles::Admin))
        .and_then(admin_handler);

    let routes = login_route
        .or(users_route)
        .or(admin_route)
        .recover(error::handle_rejection);


    warp::serve(routes)
        .run(([127, 0, 0, 1], 8080))
        .await;
}

fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}


