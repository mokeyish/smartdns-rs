use std::{future::Future, time::Duration};

use futures::future::JoinAll;
use tokio::time::{timeout, Timeout};

pub trait FutureTimeoutExt: Future + Sized {
    #[inline]
    fn timeout(self, duration: Duration) -> Timeout<Self> {
        timeout(duration, self)
    }
}

impl<T: Future + Sized> FutureTimeoutExt for T {}

pub trait FutureJoinAllExt<T: Future> {
    fn join_all(self) -> JoinAll<T>;
}

impl<T: Future, I: IntoIterator<Item = T>> FutureJoinAllExt<T> for I {
    #[inline]
    fn join_all(self) -> JoinAll<T> {
        futures::future::join_all(self)
    }
}
