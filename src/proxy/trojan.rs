use serde_json::{self,Value};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings {
    clients: Vec<Client>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Client {
    password: String,
}