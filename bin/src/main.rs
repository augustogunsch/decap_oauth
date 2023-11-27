use axum::Router;
use oauth_decap_github_lib::oauth_router;
use std::env;
use std::process::exit;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    if let Err(_) = env::var("CLIENT_ID") {
        eprintln!("error: undefined environment variable `CLIENT_ID`.");
        exit(1);
    }

    if let Err(_) = env::var("SECRET") {
        eprintln!("error: undefined environment variable `SECRET`.");
        exit(1);
    }

    if let Err(_) = env::var("ORIGIN") {
        eprintln!("error: undefined environment variable `ORIGIN`.");
        exit(1);
    }

    let app = Router::new().merge(oauth_router());

    let listener = TcpListener::bind("0.0.0.0:3005").await.unwrap();

    println!("Server listening on port 3005...");

    axum::serve(listener, app).await.unwrap();
}
