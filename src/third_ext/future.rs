use std::{future::Future, time::Duration};

use tokio::time::{timeout, Timeout};

pub trait FutureTimeoutExt: Future + Sized {
    #[inline]
    fn timeout(self, duration: Duration) -> Timeout<Self> {
        timeout(duration, self)
    }
}

impl<T: Future + Sized> FutureTimeoutExt for T {}
