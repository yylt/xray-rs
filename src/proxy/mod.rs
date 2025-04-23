use serde::{Serialize, Deserialize};

pub mod http;
pub mod black;
pub mod free;
pub mod socks;
pub mod trojan;
pub mod dokodemo;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "protocol", content = "settings")]
pub enum InboundSettings {
    #[serde(rename = "http")]
    Http(http::InSetting),

    #[serde(rename = "socks")]
    Socks(socks::InSetting),

    #[serde(rename = "trojan")]
    Trojan(trojan::InSetting),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "protocol", content = "settings")]
pub enum OutboundSettings {
    #[serde(rename = "http")]
    Http(http::OutSetting),

    #[serde(rename = "black")]
    Black(black::OutSetting),

    #[serde(rename = "free")]
    Free(free::OutSetting),

    #[serde(rename = "socks")]
    Socks(socks::OutSetting),

    #[serde(rename = "trojan")]
    Trojan(trojan::OutSetting),
}




#[cfg(test)]
mod test {
    use serde_json;
    use super::*;

    #[test]
    fn test_parse_trojan(){
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
        let v: InboundSettings = serde_json::from_str(trojan).unwrap();
        assert!(matches!(v, InboundSettings::Trojan(_)), "not trojan Struct");
    }
}