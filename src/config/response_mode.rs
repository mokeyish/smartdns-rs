/// response mode
///
/// response-mode [first-ping|fastest-ip|fastest-response]
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ResponseMode {
    #[default]
    FirstPing,
    FastestIp,
    FastestResponse,
}
