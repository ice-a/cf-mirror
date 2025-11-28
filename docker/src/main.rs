use std::collections::HashMap;
use std::sync::Arc;
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use reqwest::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use url::Url;
use serde_json::json;

static CUSTOM_DOMAIN: &str = "adysec.com";
static DOCKER_HUB: &str = "https://registry-1.docker.io";

fn routes() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(CUSTOM_DOMAIN.to_string(), DOCKER_HUB.to_string());
    map.insert(format!("docker.{}", CUSTOM_DOMAIN), DOCKER_HUB.to_string());
    map.insert(format!("quay.{}", CUSTOM_DOMAIN), "https://quay.io".to_string());
    map.insert(format!("gcr.{}", CUSTOM_DOMAIN), "https://gcr.io".to_string());
    map.insert(format!("k8s-gcr.{}", CUSTOM_DOMAIN), "https://k8s.gcr.io".to_string());
    map.insert(format!("k8s.{}", CUSTOM_DOMAIN), "https://registry.k8s.io".to_string());
    map.insert(format!("ghcr.{}", CUSTOM_DOMAIN), "https://ghcr.io".to_string());
    map.insert(format!("cloudsmith.{}", CUSTOM_DOMAIN), "https://docker.cloudsmith.io".to_string());
    map.insert(format!("ecr.{}", CUSTOM_DOMAIN), "https://public.ecr.aws".to_string());
    map.insert(format!("docker-staging.{}", CUSTOM_DOMAIN), DOCKER_HUB.to_string());
    map.insert("localhost".to_string(), DOCKER_HUB.to_string());
    map
}

fn route_by_host(host: &str) -> Option<String> {
    routes().get(host).cloned()
}

fn response_unauthorized(hostname: &str) -> Response<Body> {
    let mut res = Response::new(Body::from(json!({"message": "UNAUTHORIZED"}).to_string()));
    *res.status_mut() = StatusCode::UNAUTHORIZED;
    res.headers_mut().insert(
        WWW_AUTHENTICATE,
        format!(r#"Bearer realm="https://{}/v2/auth",service="cloudflare-docker-proxy""#, hostname)
            .parse()
            .unwrap(),
    );
    res
}

fn parse_authenticate(header: &str) -> Option<(String, String)> {
    let realm_start = header.find(r#"realm=""#)? + 7;
    let realm_end = header[realm_start..].find('"')? + realm_start;
    let service_start = header.find(r#"service=""#)? + 9;
    let service_end = header[service_start..].find('"')? + service_start;
    Some((header[realm_start..realm_end].to_string(), header[service_start..service_end].to_string()))
}

async fn fetch_token(
    client: Arc<reqwest::Client>,
    www_authenticate: &(String, String),
    scope: Option<&str>,
    auth_header: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut url = Url::parse(&www_authenticate.0).unwrap();
    if !www_authenticate.1.is_empty() {
        url.query_pairs_mut().append_pair("service", &www_authenticate.1);
    }
    if let Some(scope) = scope {
        url.query_pairs_mut().append_pair("scope", scope);
    }
    let mut req = client.get(url);
    if let Some(auth) = auth_header {
        req = req.header(AUTHORIZATION, auth);
    }
    req.send().await
}

async fn handle_request(client: Arc<reqwest::Client>, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    let upstream = match route_by_host(host) {
        Some(u) => u,
        None => {
            let body = serde_json::to_string(&routes()).unwrap();
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(body))
                .unwrap());
        }
    };
    let is_dockerhub = upstream == DOCKER_HUB;
    let auth_header = req.headers().get("Authorization").and_then(|v| v.to_str().ok());
    let uri_path = req.uri().path().to_string();

    // 根路径重定向
    if uri_path == "/" {
        let redirect_url = format!("http://{}/v2/", host);
        return Ok(Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", redirect_url)
            .body(Body::empty())
            .unwrap());
    }

    // /v2/ 请求
    if uri_path == "/v2/" {
        let resp = match client.get(format!("{}/v2/", upstream)).headers(req.headers().clone()).send().await {
            Ok(r) => r,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Upstream request failed"))
                    .unwrap());
            }
        };
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response_unauthorized(host));
        }
        let body_bytes = resp.bytes().await.unwrap_or_default();
        return Ok(Response::builder().status(status.as_u16()).body(Body::from(body_bytes)).unwrap());
    }

    // /v2/auth 请求
    if uri_path == "/v2/auth" {
        let resp = client.get(format!("{}/v2/", upstream)).send().await.unwrap();
        let status = resp.status();
        if status != reqwest::StatusCode::UNAUTHORIZED {
            let body_bytes = resp.bytes().await.unwrap_or_default();
            return Ok(Response::builder().status(status.as_u16()).body(Body::from(body_bytes)).unwrap());
        }
        let www_header = resp.headers().get(WWW_AUTHENTICATE).and_then(|v| v.to_str().ok());
        if let Some(www) = www_header {
            let www_authenticate = parse_authenticate(www).unwrap();
            let scope = req.uri().query().and_then(|q| q.split('&').find(|kv| kv.starts_with("scope=")).map(|kv| &kv[6..]));
            let token_resp = fetch_token(client.clone(), &www_authenticate, scope, auth_header).await.unwrap();
            let token_status = token_resp.status();
            let body_bytes = token_resp.bytes().await.unwrap_or_default();
            return Ok(Response::builder().status(token_status.as_u16()).body(Body::from(body_bytes)).unwrap());
        }
        return Ok(response_unauthorized(host));
    }

    // DockerHub library 自动补全
    if is_dockerhub {
        let mut parts: Vec<&str> = uri_path.split('/').collect();
        if parts.len() == 5 {
            parts.insert(2, "library");
            let redirect_url = format!("http://{}{}", host, parts.join("/"));
            return Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", redirect_url)
                .body(Body::empty())
                .unwrap());
        }
    }

    // 转发其他请求
    let resp = match client.request(req.method().clone(), format!("{}{}", upstream, uri_path)).headers(req.headers().clone()).send().await {
        Ok(r) => r,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Upstream request failed"))
                .unwrap());
        }
    };
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(response_unauthorized(host));
    }

    let body_bytes = resp.bytes().await.unwrap_or_default();
    Ok(Response::builder().status(status.as_u16()).body(Body::from(body_bytes)).unwrap())
}

#[tokio::main]
async fn main() {
    let client = Arc::new(reqwest::Client::builder().user_agent("docker/20.10").build().unwrap());
    let make_svc = make_service_fn(move |_conn| {
        let client = client.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| handle_request(client.clone(), req))) }
    });
    let addr = ([127, 0, 0, 1], 8080).into();
    println!("Listening on http://{}", addr);
    Server::bind(&addr).serve(make_svc).await.unwrap();
}

