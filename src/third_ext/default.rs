pub trait DefaultExt: Default + Eq {
    fn is_default(&self) -> bool;
}

impl<T: Default + Eq> DefaultExt for T {
    #[inline]
    fn is_default(&self) -> bool {
        self.eq(&Default::default())
    }
}
