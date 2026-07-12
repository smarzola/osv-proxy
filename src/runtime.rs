use crate::config::LimitsConfig;
use axum::body::{Body, BodyDataStream};
use axum::http::{Response, StatusCode};
use futures_util::{StreamExt, stream};
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

tokio::task_local! {
    static REQUEST_OVERLOADED: Cell<bool>;
}

#[derive(Debug, Clone)]
pub struct RuntimeBudgets {
    ingress: Arc<Semaphore>,
    install_egress: Arc<Semaphore>,
    background_egress: Arc<Semaphore>,
    queue_timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeControl {
    forced: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl RuntimeControl {
    pub fn force_shutdown(&self) {
        self.forced.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub async fn forced(&self) {
        if self.forced.load(Ordering::Acquire) {
            return;
        }
        let notified = self.notify.notified();
        if self.forced.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

impl RuntimeBudgets {
    pub fn new(config: &LimitsConfig) -> Self {
        Self {
            ingress: Arc::new(Semaphore::new(config.ingress_requests)),
            install_egress: Arc::new(Semaphore::new(config.egress_requests)),
            background_egress: Arc::new(Semaphore::new(config.background_sync_requests)),
            queue_timeout: config.queue_timeout,
        }
    }

    pub fn try_ingress(&self) -> Result<OwnedSemaphorePermit, BudgetError> {
        Arc::clone(&self.ingress)
            .try_acquire_owned()
            .map_err(|_| BudgetError::IngressSaturated)
    }

    pub async fn install_egress(&self) -> Result<OwnedSemaphorePermit, BudgetError> {
        let result = acquire_with_timeout(
            Arc::clone(&self.install_egress),
            self.queue_timeout,
            BudgetError::EgressSaturated,
        )
        .await;
        if result.is_err() {
            REQUEST_OVERLOADED.try_with(|flag| flag.set(true)).ok();
        }
        result
    }

    pub async fn background_egress(&self) -> Result<OwnedSemaphorePermit, BudgetError> {
        acquire_with_timeout(
            Arc::clone(&self.background_egress),
            self.queue_timeout,
            BudgetError::BackgroundSyncSaturated,
        )
        .await
    }
}

pub async fn track_request_overload<F: Future>(future: F) -> (F::Output, bool) {
    REQUEST_OVERLOADED
        .scope(Cell::new(false), async move {
            let output = future.await;
            let overloaded = REQUEST_OVERLOADED.with(Cell::get);
            (output, overloaded)
        })
        .await
}

async fn acquire_with_timeout(
    semaphore: Arc<Semaphore>,
    timeout: Duration,
    saturated: BudgetError,
) -> Result<OwnedSemaphorePermit, BudgetError> {
    tokio::time::timeout(timeout, semaphore.acquire_owned())
        .await
        .map_err(|_| saturated)?
        .map_err(|_| BudgetError::Closed)
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum BudgetError {
    #[error("request concurrency limit is saturated")]
    IngressSaturated,
    #[error("upstream concurrency limit is saturated")]
    EgressSaturated,
    #[error("background sync concurrency limit is saturated")]
    BackgroundSyncSaturated,
    #[error("runtime concurrency limiter is closed")]
    Closed,
}

impl BudgetError {
    pub fn response(self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "application/json")
            .header("retry-after", "1")
            .body(Body::from(format!(
                "{{\"allowed\":false,\"reason\":\"overloaded\",\"message\":{}}}",
                serde_json::to_string(&self.to_string()).expect("error message serializes")
            )))
            .expect("static overload response is valid")
    }
}

pub fn hold_permits(
    response: Response<Body>,
    permits: Vec<OwnedSemaphorePermit>,
    control: RuntimeControl,
) -> Response<Body> {
    let (parts, body) = response.into_parts();
    let stream = stream::unfold(
        (body.into_data_stream(), permits, control),
        |(mut body, permits, control): (
            BodyDataStream,
            Vec<OwnedSemaphorePermit>,
            RuntimeControl,
        )| async move {
            tokio::select! {
                item = body.next() => item.map(|result| (result, (body, permits, control))),
                _ = control.forced() => None,
            }
        },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn budgets_are_independent_and_time_bounded() {
        let budgets = RuntimeBudgets::new(&LimitsConfig {
            ingress_requests: 1,
            egress_requests: 1,
            background_sync_requests: 1,
            queue_timeout: Duration::from_millis(10),
        });
        let _ingress = budgets.try_ingress().unwrap();
        assert_eq!(
            budgets.try_ingress().unwrap_err(),
            BudgetError::IngressSaturated
        );

        let _egress = budgets.install_egress().await.unwrap();
        assert_eq!(
            budgets.install_egress().await.unwrap_err(),
            BudgetError::EgressSaturated
        );

        let _background = budgets.background_egress().await.unwrap();
        assert_eq!(
            budgets.background_egress().await.unwrap_err(),
            BudgetError::BackgroundSyncSaturated
        );
    }
}
