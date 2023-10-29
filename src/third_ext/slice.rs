pub trait AsSlice<T> {
    fn as_slice(&self) -> &[T];
}

impl<T> AsSlice<T> for Vec<T> {
    #[inline]
    fn as_slice(&self) -> &[T] {
        Vec::as_slice(self)
    }
}

impl<T> AsSlice<T> for &[T] {
    #[inline]
    fn as_slice(&self) -> &[T] {
        self
    }
}
