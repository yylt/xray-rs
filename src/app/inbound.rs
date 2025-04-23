use serde::{Serialize, Deserialize};
use crate::{common, app};
use anyhow::{Result};


pub struct Proxy {

}



pub fn new<T> (inb: app::Inbound, rt: app::Routing) -> Result<T>
where
    T: common::Inbounder+Default
{
    // TODO: implement
    Ok(T::default())
}