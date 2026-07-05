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
}
