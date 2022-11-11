use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt};
use std::result::Result;

#[async_trait::async_trait]
pub trait Middleware<TCtx: Send, TReq: Sync, TRes, TErr>: Send + Sync {
    #[inline]
    async fn handle(
        &self,
        ctx: &mut TCtx,
        req: &TReq,
        next: Next<'_, TCtx, TReq, TRes, TErr>,
    ) -> Result<TRes, TErr> {
        next.run(ctx, req).await
    }
}

#[async_trait::async_trait]
impl<TCtx: Send, TReq: Sync, TRes, TErr, F> Middleware<TCtx, TReq, TRes, TErr> for F
where
    F: Send
        + Sync
        + for<'a> Fn(
            &mut TCtx,
            &TReq,
            Next<'a, TCtx, TReq, TRes, TErr>,
        ) -> BoxFuture<'a, Result<TRes, TErr>>,
{
    #[inline]
    async fn handle(
        &self,
        ctx: &mut TCtx,
        req: &TReq,
        next: Next<'_, TCtx, TReq, TRes, TErr>,
    ) -> Result<TRes, TErr> {
        (self)(ctx, req, next).await
    }
}

#[async_trait::async_trait]
pub trait MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr>: Send + Sync {
    async fn handle(&self, ctx: &mut TCtx, req: &TReq) -> Result<TRes, TErr>;
}

#[derive(Clone)]
pub struct Next<'a, TCtx, TReq, TRes, TErr> {
    default: &'a Arc<dyn MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr>>,
    middlewares: &'a [Arc<dyn Middleware<TCtx, TReq, TRes, TErr>>],
}

impl<'a, TCtx: Send, TReq: Sync, TRes, TErr> Next<'a, TCtx, TReq, TRes, TErr> {
    pub(crate) fn new(
        default: &'a Arc<dyn MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr>>,
        middlewares: &'a [Arc<dyn Middleware<TCtx, TReq, TRes, TErr>>],
    ) -> Self {
        Self {
            default,
            middlewares,
        }
    }

    #[inline]
    pub fn run(mut self, ctx: &'a mut TCtx, req: &'a TReq) -> BoxFuture<'a, Result<TRes, TErr>> {
        if let Some((current, rest)) = self.middlewares.split_first() {
            self.middlewares = rest;
            current.handle(ctx, req, self).boxed()
        } else {
            self.default.handle(ctx, req).boxed()
        }
    }
}

pub struct MiddlewareBuilder<TCtx, TReq, TRes, TErr> {
    default: Arc<dyn MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr>>,
    middleware_stack: Vec<Arc<dyn Middleware<TCtx, TReq, TRes, TErr>>>,
}

impl<TCtx: Send, TReq: Sync, TRes, TErr> MiddlewareBuilder<TCtx, TReq, TRes, TErr> {
    #[inline]
    pub fn new(default: impl MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr> + 'static) -> Self {
        Self {
            default: Arc::new(default),
            middleware_stack: Default::default(),
        }
    }

    /// Convenience method to attach middleware.
    ///
    /// If you need to keep a reference to the middleware after attaching, use [`with_arc`].
    ///
    /// [`with_arc`]: Self::with_arc
    #[inline]
    pub fn with<M>(self, middleware: M) -> Self
    where
        M: Middleware<TCtx, TReq, TRes, TErr> + 'static,
    {
        self.with_arc(Arc::new(middleware))
    }

    /// Add middleware to the chain. [`with`] is more ergonomic if you don't need the `Arc`.
    ///
    /// [`with`]: Self::with
    #[inline]
    pub fn with_arc(mut self, middleware: Arc<dyn Middleware<TCtx, TReq, TRes, TErr>>) -> Self {
        self.middleware_stack.push(middleware);
        self
    }

    #[inline]
    pub fn build(self) -> MiddlewareHost<TCtx, TReq, TRes, TErr> {
        MiddlewareHost {
            default: self.default,
            middleware_stack: self.middleware_stack.into_boxed_slice(),
        }
    }
}

pub struct MiddlewareHost<TCtx, TReq, TRes, TErr> {
    default: Arc<dyn MiddlewareDefaultHandler<TCtx, TReq, TRes, TErr>>,
    middleware_stack: Box<[Arc<dyn Middleware<TCtx, TReq, TRes, TErr>>]>,
}

impl<TCtx: Send, TReq: Sync, TRes, TErr> MiddlewareHost<TCtx, TReq, TRes, TErr> {
    pub async fn execute(&self, ctx: &mut TCtx, req: &TReq) -> Result<TRes, TErr> {
        let next = Next::new(&self.default, &self.middleware_stack);
        next.run(ctx, req).await
    }
}

#[cfg(test)]
mod tests {

    use tokio::runtime;

    use super::*;

    #[derive(Default)]
    struct DefaultHandler;

    #[async_trait::async_trait]
    impl MiddlewareDefaultHandler<String, String, String, String> for DefaultHandler {
        async fn handle(&self, _ctx: &mut String, req: &String) -> Result<String, String> {
            Ok(format!("Default Handler, len: {}\n", req.len()))
        }
    }

    #[derive(Default)]
    struct MiddlewareOne;

    #[derive(Default)]
    struct MiddlewareTwo;

    #[derive(Default)]
    struct MiddlewareThree;

    #[async_trait::async_trait]
    impl Middleware<String, String, String, String> for MiddlewareOne {
        async fn handle(
            &self,
            ctx: &mut String,
            req: &String,
            next: Next<'_, String, String, String, String>,
        ) -> Result<String, String> {
            let mut res = "MiddlewareOne 开始 \n".to_string();
            let nr = next.run(ctx, req).await.unwrap();

            res += nr.as_str();

            res.push_str("MiddlewareOne 结束\n");

            Ok(res)
        }
    }

    #[async_trait::async_trait]
    impl Middleware<String, String, String, String> for MiddlewareTwo {
        async fn handle(
            &self,
            ctx: &mut String,
            req: &String,
            next: Next<'_, String, String, String, String>,
        ) -> Result<String, String> {
            let mut res = "MiddlewareTwo 开始 \n".to_string();
            let nr = next.run(ctx, req).await.unwrap();

            res += nr.as_str();

            res.push_str("MiddlewareTwo 结束\n");

            Ok(res)
        }
    }

    #[async_trait::async_trait]
    impl Middleware<String, String, String, String> for MiddlewareThree {
        async fn handle(
            &self,
            ctx: &mut String,
            req: &String,
            next: Next<'_, String, String, String, String>,
        ) -> Result<String, String> {
            let mut res = "MiddlewareThree 开始 \n".to_string();
            let nr = next.run(ctx, req).await.unwrap();

            res += nr.as_str();

            res.push_str("MiddlewareThree 结束\n");

            Ok(res)
        }
    }

    #[test]
    fn test_middleware() {
        runtime::Runtime::new().unwrap().block_on(async {
            let m = MiddlewareBuilder::<String, String, String, String>::new(DefaultHandler)
            .with(MiddlewareOne)
            .with(MiddlewareTwo)
            .with(MiddlewareThree)
            .build();

            let res = m.execute(&mut "".to_string(), &"标记".to_string()).await.unwrap();
            assert_eq!(res, "MiddlewareOne 开始 \nMiddlewareTwo 开始 \nMiddlewareThree 开始 \nDefault Handler, len: 6\nMiddlewareThree 结束\nMiddlewareTwo 结束\nMiddlewareOne 结束\n");
        })
    }
}
