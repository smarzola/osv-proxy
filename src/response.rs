use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RegistryResponse {
    pub fn json(status: u16, body: &Value) -> Result<Self, serde_json::Error> {
        Ok(Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: serde_json::to_vec(body)?,
        })
    }

    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: body.into().into_bytes(),
        }
    }

    pub fn redirect(location: String) -> Self {
        Self {
            status: 302,
            headers: vec![("location".to_string(), location)],
            body: Vec::new(),
        }
    }

    pub fn set_content_type(&mut self, content_type: &str) {
        if let Some((_, value)) = self
            .headers
            .iter_mut()
            .find(|(name, _)| name == "content-type")
        {
            *value = content_type.to_string();
        } else {
            self.headers
                .push(("content-type".to_string(), content_type.to_string()));
        }
    }

    pub fn into_http_response(self) -> Response<Body> {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::OK);
        let mut builder = Response::builder().status(status);
        let headers = builder
            .headers_mut()
            .expect("headers are available before response body is built");
        for (name, value) in self.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                headers.insert(name, value);
            }
        }
        builder
            .body(Body::from(self.body))
            .expect("registry response should convert to HTTP response")
    }
}
