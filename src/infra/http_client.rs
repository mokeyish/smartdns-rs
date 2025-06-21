pub trait HttpResponse {
    fn text(self) -> anyhow::Result<String>;
}

#[cfg(feature = "ureq")]
use ureq as http_client;

#[cfg(feature = "ureq")]
pub fn get<T>(uri: T) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>
where
    http::Uri: TryFrom<T>,
    <http::Uri as TryFrom<T>>::Error: Into<http::Error>,
{
    let res = http_client::get(uri).call()?;
    Ok(res)
}

#[cfg(feature = "ureq")]
impl HttpResponse for ureq::http::Response<ureq::Body> {
    fn text(mut self) -> anyhow::Result<String> {
        Ok(self.body_mut().read_to_string()?)
    }
}

#[cfg(feature = "reqwest")]
use reqwest::blocking as http_client;

#[cfg(feature = "reqwest")]
pub fn get<T>(uri: T) -> Result<impl HttpResponse, reqwest::Error>
where
    T: reqwest::IntoUrl,
{
    let res = http_client::get(uri)?;
    Ok(res)
}

#[cfg(feature = "reqwest")]
impl HttpResponse for reqwest::blocking::Response {
    fn text(self) -> anyhow::Result<String> {
        Ok(self.text()?)
    }
}
