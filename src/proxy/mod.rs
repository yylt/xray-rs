use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};

pub mod http;
pub mod black;
pub mod free;
pub mod socks;
pub mod trojan;
pub mod dokodemo;


#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "protocol", content = "settings")]
pub enum Settings {
    #[serde(rename = "http")]
    Http(http::Settings),

    #[serde(rename = "black")]
    Black(black::Settings),

    #[serde(rename = "free")]
    Free(free::Settings),

    #[serde(rename = "socks")]
    Socks(socks::Settings),

    #[serde(rename = "trojan")]
    Trojan(trojan::Settings),

}

impl fmt::Display for Settings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Settings::Http(ref x) => write!(f, "Http: {:?}", x),
            Settings::Black(ref x) => write!(f, "Black: {:?}", x),
            Settings::Free(ref x) => write!(f, "Free: {:?}", x),
            Settings::Socks(ref x) => write!(f, "Socks: {:?}", x),
            Settings::Trojan(ref x) => write!(f, "Trojan: {:?}", x),
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::{self, Value};
    use super::*;

    #[test]
    fn parse_trojan(){
        let trojan = r#"
            {
                "protocol": "trojan",
                "settings": {
                    "clients": [{
                         "password": "password"   
                    }]   
                }
            }"#;

        // Parse the string of data into serde_json::Value.
        let v: Settings = serde_json::from_str(trojan).unwrap();
        assert!(matches!(v, Settings::Trojan(_)), "not trojan Struct");
    }
}