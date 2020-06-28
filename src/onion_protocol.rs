use std::net::IpAddr;

pub(crate) struct CreateMessage {
    pub secret: Vec<u8>,
}

pub(crate) struct CreatedMessage {
    pub peer_secret: Vec<u8>,
}

pub(crate) struct DestroyMessage {}

pub(crate) enum RelayRequest {
    Extend(RelayExtend),
    Data(RelayData),
    Truncate,
}

pub(crate) enum RelayResponse {
    Extended(RelayExtended),
    Truncated(RelayTruncated),
}

pub(crate) struct RelayExtend {
    pub(crate) dest_addr: IpAddr,
    pub(crate) dest_port: u16,
    pub(crate) secret: Vec<u8>,
}

pub(crate) struct RelayExtended {
    dest_addr: IpAddr,
    dest_port: u16,
    pub(crate) key: Vec<u8>,
    error: Option<String>,
}

pub(crate) struct RelayData {
    data: Vec<u8>,
}

pub(crate) struct RelayTruncated {
    dest_addr: IpAddr,
    dest_port: u16,
    error: Option<String>,
}
