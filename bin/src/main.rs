use axum::Router;
use oauth_decap_github_lib::oauth_router;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let app = Router::new().merge(oauth_router());

    let listener = TcpListener::bind("0.0.0.0:3005").await.unwrap();

    println!("Server listening on port 3005...");

    axum::serve(listener, app).await.unwrap();
}
