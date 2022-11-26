pub trait MemBytes<T: Sized> {
    fn mem_size() -> usize {
        std::mem::size_of::<T>()
    }
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                ::std::mem::size_of::<T>(),
            )
        }
    }

    fn from_bytes(bytes: &[u8]) -> T {
        unsafe { std::ptr::read(bytes.as_ptr() as *const T) }
    }
}

impl<T: Sized> MemBytes<T> for T {}

#[cfg(test)]
mod tests {
    use crate::infra::mem_bytes::MemBytes;

    #[test]
    fn test_as_bytes() {
        let a = 'a';
        assert_eq!(a.as_bytes(), &[97, 0, 0, 0]);
    }

    #[test]
    fn test_from_bytes() {
        let a = char::from_bytes(&[97, 0, 0, 0]);
        assert_eq!(a, 'a');
    }
}
