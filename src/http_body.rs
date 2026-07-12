use futures_util::StreamExt;
use reqwest::Response;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use std::fs::File;
use thiserror::Error;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum HttpBodyError {
    #[error("{kind} declares a body larger than the {limit}-byte limit")]
    DeclaredTooLarge { kind: &'static str, limit: usize },
    #[error("{kind} exceeds the {limit}-byte limit while streaming")]
    StreamedTooLarge { kind: &'static str, limit: usize },
    #[error("failed to read {kind}: {message}")]
    Read { kind: &'static str, message: String },
    #[error("{kind} is not valid UTF-8: {source}")]
    Utf8 {
        kind: &'static str,
        #[source]
        source: std::string::FromUtf8Error,
    },
    #[error("{kind} is not valid JSON: {source}")]
    Json {
        kind: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to store {kind} in a temporary file: {source}")]
    TempFile {
        kind: &'static str,
        #[source]
        source: std::io::Error,
    },
}

pub async fn collect_bytes(
    response: Response,
    limit: usize,
    kind: &'static str,
) -> Result<Vec<u8>, HttpBodyError> {
    ensure_content_length(response.content_length(), limit, kind)?;
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(limit);
    collect_stream_with_capacity(response.bytes_stream(), limit, kind, capacity).await
}

pub async fn collect_text(
    response: Response,
    limit: usize,
    kind: &'static str,
) -> Result<String, HttpBodyError> {
    String::from_utf8(collect_bytes(response, limit, kind).await?)
        .map_err(|source| HttpBodyError::Utf8 { kind, source })
}

pub async fn collect_json<T: DeserializeOwned>(
    response: Response,
    limit: usize,
    kind: &'static str,
) -> Result<T, HttpBodyError> {
    serde_json::from_slice(&collect_bytes(response, limit, kind).await?)
        .map_err(|source| HttpBodyError::Json { kind, source })
}

pub async fn collect_temp_file(
    response: Response,
    limit: usize,
    kind: &'static str,
) -> Result<File, HttpBodyError> {
    ensure_content_length(response.content_length(), limit, kind)?;
    let file = tempfile::tempfile().map_err(|source| HttpBodyError::TempFile { kind, source })?;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = response.bytes_stream();
    let mut written = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| HttpBodyError::Read {
            kind,
            message: source.to_string(),
        })?;
        ensure_streamed_size(written, chunk.len(), limit, kind)?;
        file.write_all(&chunk)
            .await
            .map_err(|source| HttpBodyError::TempFile { kind, source })?;
        written += chunk.len();
    }
    file.flush()
        .await
        .map_err(|source| HttpBodyError::TempFile { kind, source })?;
    file.rewind()
        .await
        .map_err(|source| HttpBodyError::TempFile { kind, source })?;
    Ok(file.into_std().await)
}

pub fn ensure_content_length(
    content_length: Option<u64>,
    limit: usize,
    kind: &'static str,
) -> Result<(), HttpBodyError> {
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(HttpBodyError::DeclaredTooLarge { kind, limit });
    }
    Ok(())
}

pub async fn collect_stream<S, T, E>(
    stream: S,
    limit: usize,
    kind: &'static str,
) -> Result<Vec<u8>, HttpBodyError>
where
    S: futures_util::Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Display,
{
    collect_stream_with_capacity(stream, limit, kind, 0).await
}

async fn collect_stream_with_capacity<S, T, E>(
    mut stream: S,
    limit: usize,
    kind: &'static str,
    capacity: usize,
) -> Result<Vec<u8>, HttpBodyError>
where
    S: futures_util::Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Display,
{
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|source| HttpBodyError::Read {
            kind,
            message: source.to_string(),
        })?;
        ensure_streamed_size(body.len(), chunk.as_ref().len(), limit, kind)?;
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

fn ensure_streamed_size(
    current: usize,
    additional: usize,
    limit: usize,
    kind: &'static str,
) -> Result<(), HttpBodyError> {
    if current.saturating_add(additional) > limit {
        return Err(HttpBodyError::StreamedTooLarge { kind, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn rejects_declared_oversize_before_reading_body() {
        let response = response_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\n0123456789",
        )
        .await;
        assert!(matches!(
            collect_bytes(response, 9, "fixture").await,
            Err(HttpBodyError::DeclaredTooLarge { limit: 9, .. })
        ));
    }

    #[tokio::test]
    async fn rejects_chunked_oversize_during_streaming() {
        let response = response_once(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n5\r\n01234\r\n5\r\n56789\r\n0\r\n\r\n",
        )
        .await;
        assert!(matches!(
            collect_bytes(response, 9, "fixture").await,
            Err(HttpBodyError::StreamedTooLarge { limit: 9, .. })
        ));
    }

    #[tokio::test]
    async fn streams_bounded_body_to_rewound_temporary_file() {
        let response = response_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\narchive!",
        )
        .await;
        let file = collect_temp_file(response, 8, "fixture").await.unwrap();
        let mut file = tokio::fs::File::from_std(file);
        let mut body = Vec::new();
        file.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"archive!");
    }

    #[tokio::test]
    async fn tempfile_rejects_declared_oversize_before_returning_file() {
        let response = response_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\n0123456789",
        )
        .await;
        assert!(matches!(
            collect_temp_file(response, 9, "archive").await,
            Err(HttpBodyError::DeclaredTooLarge { limit: 9, .. })
        ));
    }

    #[tokio::test]
    async fn tempfile_rejects_chunked_oversize_before_returning_file() {
        let response = response_once(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n5\r\n01234\r\n5\r\n56789\r\n0\r\n\r\n",
        )
        .await;
        assert!(matches!(
            collect_temp_file(response, 9, "archive").await,
            Err(HttpBodyError::StreamedTooLarge { limit: 9, .. })
        ));
    }

    async fn response_once(raw: &'static str) -> Response {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(raw.as_bytes()).await.unwrap();
        });
        reqwest::get(format!("http://{address}/body"))
            .await
            .unwrap()
    }
}
