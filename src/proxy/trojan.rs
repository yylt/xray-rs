use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct InSetting {
    #[serde(rename = "clients")]
    clients: Vec<Client>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Client {
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OutSetting {
    #[serde(rename = "servers")]
    servers: Vec<Server>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Server {
    #[serde(rename = "password")]
    password: String,

    #[serde(rename = "address")]
    address: String,

    #[serde(rename = "port")]
    port: u16,
}