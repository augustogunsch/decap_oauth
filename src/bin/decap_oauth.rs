use axum::Router;
use decap_oauth::{normalize_public_url, oauth_router};
use std::env;
use std::process::exit;
use tokio::net::TcpListener;

struct Args {
    port: usize,
}

fn usage_exit(exit_code: i32) -> ! {
    eprintln!("usage: decap_oauth [--port PORT] [--help]");
    exit(exit_code);
}

fn parse_args() -> Args {
    let mut port = 3005;

    let args: Vec<String> = env::args().skip(1).collect();
    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "--help" => usage_exit(0),
            "--port" => match args.get(i + 1) {
                Some(port_arg) => match port_arg.parse::<usize>() {
                    Ok(result) => port = result,
                    Err(_) => {
                        eprintln!("Provided port is not an integer");
                        exit(1);
                    }
                },
                None => usage_exit(1),
            },
            _ => {}
        }
    }

    Args { port }
}

fn check_var(var: &str) {
    if env::var(var).is_err() {
        eprintln!("error: undefined environment variable `{}`.", var);
        exit(1);
    }
}

/// `PUBLIC_URL` is optional, but a malformed one would produce a callback URL
/// the provider can never match. Fail at startup instead of at login time.
fn check_public_url() {
    let Ok(url) = env::var("PUBLIC_URL") else {
        return;
    };
    if url.trim().is_empty() || normalize_public_url(&url).is_some() {
        return;
    }
    eprintln!(
        "error: `PUBLIC_URL` must be an absolute http(s) origin, e.g. https://www.example.com"
    );
    exit(1);
}

#[tokio::main]
async fn main() {
    check_var("OAUTH_CLIENT_ID");
    check_var("OAUTH_SECRET");
    check_var("OAUTH_ORIGINS");
    check_public_url();

    let app = Router::new().merge(oauth_router());

    let args = parse_args();

    let address = format!("0.0.0.0:{}", args.port);
    let listener = TcpListener::bind(address).await.unwrap();

    println!("Server listening on port {}...", args.port);

    axum::serve(listener, app).await.unwrap();
}
