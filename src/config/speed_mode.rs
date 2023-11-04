#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum SpeedCheckMode {
    #[default]
    None,
    Ping,
    Tcp(u16),
    Http(u16),
    Https(u16),
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct SpeedCheckModeList(pub Vec<SpeedCheckMode>);

impl SpeedCheckModeList {
    pub fn push(&mut self, mode: SpeedCheckMode) -> Option<SpeedCheckMode> {
        if self.0.iter().all(|m| m != &mode) {
            self.0.push(mode);
            None
        } else {
            Some(mode)
        }
    }
}

impl From<Vec<SpeedCheckMode>> for SpeedCheckModeList {
    fn from(value: Vec<SpeedCheckMode>) -> Self {
        let mut lst = Self(Vec::with_capacity(value.len()));
        for mode in value {
            lst.push(mode);
        }
        lst
    }
}

impl std::ops::Deref for SpeedCheckModeList {
    type Target = Vec<SpeedCheckMode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SpeedCheckModeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
