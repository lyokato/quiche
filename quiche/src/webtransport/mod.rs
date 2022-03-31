use std::collections::HashMap;
use std::str;
use crate::h3::{self, Header, NameValue};
use crate::Connection;
use crate::stream::is_bidi;
use crate::octets;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    MissingParam(&'static str),
    InvalidParam(&'static str, Vec<u8>),
    ParamMismatch(&'static str, &'static str, Vec<u8>),
    InvalidState,
    InvalidArg(&'static str),
    InvalidConfig(&'static str),
    SessionNotFound,
    SessionNotConnected,
    StreamNotFound,
    InvalidStream,
    InvalidClientState,
    Done,
    TransportError(crate::Error),
    HTTPError(h3::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<h3::Error> for Error {
    fn from(err: h3::Error) -> Self {
        match err {
            h3::Error::Done => Error::Done,
            h3::Error::TransportError(e) => Error::TransportError(e),
            _ => Error::HTTPError(err),
        }
    }
}

impl std::convert::From<crate::Error> for Error {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::Done => Error::Done,

            _ => Error::TransportError(err),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServerEvent {
    ConnectRequest(ConnectRequest),
    StreamData(u64),
    Datagram,
    Finished,
    Reset(u64),
    GoAway,
    HTTPEvent(h3::Event),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClientEvent {
    Connected,
    Rejected,
    StreamData(u64),
    Datagram,
    Finished,
    Reset(u64),
    GoAway,
    HTTPEvent(h3::Event),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    authority: String,
    path: String,
    origin: String,
}

impl ConnectRequest {

    pub fn new(authority: String, path: String, origin: String) -> Self {
        Self {
            authority,
            path,
            origin,
        }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }
}

pub struct StreamInfo {
    stream_id: u64,
    local: bool,
    initialized: bool,
}

impl StreamInfo {

    pub fn new(stream_id: u64, local: bool) -> Self {
        Self {
            stream_id,
            local,
            initialized: false,
        }
    }

    pub fn is_bidi(&self) -> bool {
        is_bidi(self.stream_id)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn is_local(&self) -> bool {
        self.local
    }

    pub fn mark_initialized(&mut self) {
        self.initialized = true;
    }
}

pub struct Session {
    session_id: u64,
    streams: HashMap<u64, StreamInfo>,
    connected: bool,
}

impl Session {

    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            streams: HashMap::new(),
            connected: false,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn mark_connected(&mut self) {
        self.connected = true;
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn get_stream(&mut self, stream_id: u64) -> Option<&mut StreamInfo> {
        self.streams.get_mut(&stream_id)
    }

    pub fn register_stream(
        &mut self, stream_id: u64, stream: StreamInfo,
    ) -> bool {
        if self.streams.contains_key(&stream_id) {
            false
        } else {
            self.streams.insert(stream_id, stream);
            true
        }
    }

    pub fn unregister_stream(&mut self, stream_id: u64) {
        self.streams.remove(&stream_id);
    }
}

fn find_request(
    list: &[h3::Header],
) -> Result<ConnectRequest> {

    match is_webtransport_request(list) {
        Ok(()) => {
            let mut headers = list.into_iter();

            let authority = find_string_param(&mut headers, ":authority")?;
            let path = find_string_param(&mut headers, ":path")?;
            let origin = find_string_param(&mut headers, "origin")?;

            Ok(ConnectRequest::new(authority, path, origin))
        },

        Err(e) => Err(e),
    }
}

fn find_string_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str,
) -> Result<String> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            Ok(param_str)
        } else {
            Err(Error::InvalidParam(param, header.value().to_vec()))
        }
    } else {
        Err(Error::MissingParam(param))
    }
}

fn find_integer_param(
    headers: &mut std::vec::IntoIter<h3::Header>, param: &'static str,
) -> Result<i32> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            let param_int = param_str.parse::<i32>()
                .map_err(|_| Error::InvalidParam(param, header.value().to_vec()))?;
            Ok(param_int)
        } else {
            Err(Error::InvalidParam(param, header.value().to_vec()))
        }
    } else {
        Err(Error::MissingParam(param))
    }
}

fn validate_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str, expected: &'static str,
) -> Result<()> {
    if let Some(method) = headers.find(|h| h.name() == param.as_bytes()) {
        if method.value() != expected.as_bytes() {
            Err(Error::ParamMismatch(param, expected, method.value().to_vec()))
        } else {
            Ok(())
        }
    } else {
        Err(Error::MissingParam(param))
    }
}

fn is_webtransport_request(list: &[h3::Header]) -> Result<()> {
    let mut headers = list.into_iter();
    validate_param(&mut headers, ":method", "CONNECT")?;
    validate_param(&mut headers, ":protocol", "webtransport")?;
    Ok(())
}

pub struct WebTransportServer {
    server_name: String,
    h3_conn: h3::Connection,
    sessions: HashMap::<u64, Session>,
}

impl WebTransportServer {

    fn new(
        server_name: String,
        h3_conn: h3::Connection,
    ) -> Self {
        Self {
            server_name,
            h3_conn,
            sessions: HashMap::new(),
        }
    }

    pub fn with_transport(
        conn: &mut Connection,
        server_name: String,
    ) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }
        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);

        let h3_conn = match h3::Connection::with_transport(
            conn,
            &config,
         ) {
            Ok(v) => v,

            Err(e) => return Err(e.into()),
        };

        Ok(Self::new(server_name, h3_conn))
    }

    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8]
    ) -> Result<(usize, u64, usize)> {
        self.h3_conn.recv_dgram(conn, buf)
            .map_err(|e| e.into())
    }

    pub fn poll(
        &mut self,
        conn: &mut Connection,
    ) -> Result<(u64, ServerEvent)> {

        match self.h3_conn.poll(conn) {

            Ok((stream_id, h3::Event::Headers{ list, has_body })) => {
                if self.sessions.contains_key(&stream_id) {
                    Err(Error::HTTPError(h3::Error::FrameUnexpected))
                } else {
                    match find_request(&list) {
                        Ok(wt_req) => Ok((stream_id, ServerEvent::ConnectRequest(wt_req))),
                        Err(e) => {
                            info!("This is not a WebTransport connect request: {}", e);
                            Ok((stream_id, ServerEvent::HTTPEvent(h3::Event::Headers{ list, has_body })))
                        },
                    }
                }
            },

            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match self.sessions.get_mut(&session_id) {

                    Some(session) => {
                        if let None = session.get_stream(stream_id) {
                            session.register_stream(stream_id,
                                StreamInfo::new(stream_id, false));
                        }
                        Ok((stream_id, ServerEvent::StreamData(session_id)))
                    },

                    None => Err(Error::InvalidState),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                if self.sessions.contains_key(&stream_id) {
                    Err(Error::HTTPError(h3::Error::FrameUnexpected))
                } else {
                    Ok((stream_id, ServerEvent::HTTPEvent(h3::Event::Data)))
                }
            },

            Ok((stream_id, h3::Event::Finished)) => {
                match self.sessions.get_mut(&stream_id) {
                    Some(session) => {
                        session.unregister_stream(stream_id);
                        Ok((stream_id, ServerEvent::Finished))
                    },
                    None =>
                        Ok((stream_id, ServerEvent::HTTPEvent(h3::Event::Finished))),
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => {
                match self.sessions.get_mut(&stream_id) {
                    Some(session) => {
                        session.unregister_stream(stream_id);
                        Ok((stream_id, ServerEvent::Reset(e)))
                    },
                    None =>
                        Ok((stream_id, ServerEvent::HTTPEvent(h3::Event::Reset(e)))),
                }
            },

            Ok((session_id, h3::Event::Datagram)) => {
                if self.sessions.contains_key(&session_id) {
                    Ok((session_id, ServerEvent::Datagram))
                } else {
                    Ok((session_id, ServerEvent::HTTPEvent(h3::Event::Datagram)))
                }
            },

            Ok((stream_id, h3::Event::GoAway)) => {
                match self.sessions.get_mut(&stream_id) {
                    Some(_session) => {
                        Ok((stream_id, ServerEvent::GoAway))
                    },
                    None =>
                        Ok((stream_id, ServerEvent::HTTPEvent(h3::Event::GoAway))),
                }
            },

            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }

    pub fn accept_connect_request(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {

        if self.sessions.contains_key(&stream_id) {
            return Err(Error::InvalidState);
        }

        let server_name = self.server_name.clone().into_bytes();

        let mut list = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", &server_name),
            Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        ];

        if let Some(extra_headers) = extra_headers {
            list.append(&mut extra_headers.to_vec());
        }

        let _ = self.h3_conn
            .send_response(conn, stream_id, &list, false)?;

        let mut session = Session::new(stream_id);
        session.mark_connected();
        self.sessions.insert(stream_id, session);

        Ok(())
    }

    pub fn reject_connect_request(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        code: u32,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {

        if self.sessions.contains_key(&stream_id) {
            return Err(Error::InvalidState);
        }

        if code < 400 {
            return Err(Error::InvalidArg("code"));
        }

        let code = format!("{}", code).into_bytes();
        let server_name = self.server_name.clone().into_bytes();

        let mut list = vec![
            Header::new(b":status", &code),
            Header::new(b"server", &server_name),
            Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        ];

        if let Some(extra_headers) = extra_headers {
            list.append(&mut extra_headers.to_vec());
        }

        if let Err(e) = self.h3_conn.send_response(conn, stream_id, &list, true) {
            warn!("Failed to send WebTransport reject response: {}", e);
        }

        // 0x10B = REQUEST_REJECTED
        conn.close(true, 0x10B, b"")?;

        Ok(())
    }

    pub fn open_stream(
        &mut self,
        conn: &mut Connection,
        session_id: u64,
        is_bidi: bool,
    ) -> Result<u64> {
        match self.sessions.get_mut(&session_id) {
            Some(session) => {
                match self.h3_conn.open_webtransport_stream(conn, session_id, is_bidi) {
                    Ok(stream_id) => {
                        let mut stream = StreamInfo::new(stream_id, true);
                        stream.mark_initialized();
                        session.register_stream(stream_id, stream);
                        Ok(stream_id)
                    },

                    Err(e) => Err(Error::HTTPError(e)),
                }
            },
            None => Err(Error::SessionNotFound),
        }
    }

    pub fn send_stream_data(
        &mut self,
        conn: &mut Connection,
        session_id: u64,
        stream_id: u64,
        data: &[u8],
    ) -> Result<usize> {
        match self.sessions.get_mut(&session_id) {
            Some(session) => {
                match session.get_stream(stream_id) {
                    Some(stream) => {
                        match (stream.is_bidi(), stream.is_local()) {
                            // can't write to remote and unidirectional stream.
                            (false, false) => Err(Error::InvalidStream),
                            // uni-directional, local
                            (false, true) => self.send_stream_data_internal(conn, stream_id, data),
                            // bidirectional, remote
                            (true, false) => {
                                //if !stream.is_initialized() {
                                //    self.h3_conn
                                //        .send_webtransport_frame_header(conn, session_id, stream_id)?;
                                //    stream.mark_initialized();
                                //}
                                self.send_stream_data_internal(conn, stream_id, data)
                            },
                            // bidirectional, local
                            (true, true) => self.send_stream_data_internal(conn, stream_id, data),
                        }
                    },
                    None => Err(Error::StreamNotFound),
                }
            },
            None => Err(Error::SessionNotFound),
        }
    }

    pub fn send_dgram(
        &mut self,
        conn: &mut Connection,
        session_id: u64,
        data: &[u8],
    ) -> Result<()> {
        if self.sessions.contains_key(&session_id) {
                self.h3_conn
                    .send_dgram(conn, session_id, data)?;
                Ok(())
        } else {
            Err(Error::SessionNotFound)
        }
    }

    fn send_stream_data_internal(
        &self, conn: &mut Connection, stream_id: u64, data: &[u8],
    ) -> Result<usize> {
        match conn.stream_capacity(stream_id) {
            Ok(cap) => {
                let len = std::cmp::min(cap, data.len());
                let written = conn.stream_send(stream_id, &data[..len], false)?;
                Ok(written)
            },
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ClientState {
    Idle,
    LocalInitialized,
    Connected,
}

pub struct WebTransportClient {
    h3_conn: h3::Connection,
    session: Option<Session>,
    state: ClientState,
}

impl WebTransportClient {

    fn new(h3_conn: h3::Connection) -> Self {
        Self {
            h3_conn,
            session: None,
            state: ClientState::Idle,
        }
    }

    pub fn with_transport(
        conn: &mut Connection,
        authority: &[u8],
        path: &[u8],
        origin: &[u8],
        extra_headers: Option<&[Header]>,
    ) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }

        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);

        let h3_conn = match h3::Connection::with_transport(
            conn,
            &config,
         ) {
            Ok(v) => v,

            Err(e) => return Err(e.into()),
        };

        Ok(Self::new(h3_conn))
    }

    pub fn send_connect_request(
        &mut self,
        conn: &mut Connection,
        authority: &[u8],
        path: &[u8],
        origin: &[u8],
        extra_headers: Option<&[Header]>,
    ) -> Result<u64> {

        if self.state != ClientState::Idle {
            return Err(Error::InvalidClientState);
        }

        let mut req = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":scheme", b"https"),
            Header::new(b":protocol", b"webtransport"),
            Header::new(b"sec-webtransport-http3-draft02", b"1"),
            Header::new(b":authority", &authority),
            Header::new(b":path", &path),
            Header::new(b"origin", &origin),
        ];

        if let Some(extra_headers) = extra_headers {
            req.append(&mut extra_headers.to_vec());
        }

        let stream_id = self.h3_conn.send_request(conn, &req, false)?;
        self.session = Some(Session::new(stream_id));
        self.state = ClientState::LocalInitialized;

        Ok(stream_id)
    }

    pub fn poll(
        &mut self,
        conn: &mut Connection,
    ) -> Result<(u64, ClientEvent)> {

        match self.h3_conn.poll(conn) {

            Ok((stream_id, h3::Event::Headers{ list, has_body })) => {
                match &mut self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            let mut headers = list.into_iter();
                            let code = find_integer_param(&mut headers, ":status")?;
                            if code >= 200 && code < 300 {
                                session.mark_connected();
                                Ok((stream_id, ClientEvent::Connected))
                            } else {
                                Ok((stream_id, ClientEvent::Rejected))
                            }
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Headers{ list, has_body })))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Headers{ list, has_body }))),
                }
            },

            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match &mut self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            if let None = session.get_stream(stream_id) {
                                session.register_stream(stream_id,
                                    StreamInfo::new(stream_id, false));
                            }
                            Ok((stream_id, ClientEvent::StreamData(session_id)))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::WebTransportStreamData(session_id))))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::WebTransportStreamData(session_id)))),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                match &self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            Err(Error::HTTPError(h3::Error::FrameUnexpected))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Data)))
                        }
                    },
                    None => Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Data))),
                }
            },

            Ok((stream_id, h3::Event::Finished)) => {
                match &mut self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            session.unregister_stream(stream_id);
                            Ok((stream_id, ClientEvent::Finished))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Finished)))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Finished))),
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => {
                match &mut self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            session.unregister_stream(stream_id);
                            Ok((stream_id, ClientEvent::Reset(e)))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Reset(e))))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Reset(e)))),
                }
            },

            Ok((stream_id, h3::Event::Datagram)) => {
                match &self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            Ok((stream_id, ClientEvent::Datagram))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Datagram)))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::Datagram))),
                }
            },

            Ok((stream_id, h3::Event::GoAway)) => {
                match &self.session {
                    Some(session) => {
                        if session.session_id() == stream_id {
                            Ok((stream_id, ClientEvent::GoAway))
                        } else {
                            Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::GoAway)))
                        }
                    },
                    None =>
                        Ok((stream_id, ClientEvent::HTTPEvent(h3::Event::GoAway))),
                }
            },

            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }

    pub fn open_stream(
        &mut self,
        conn: &mut Connection,
        is_bidi: bool,
    ) -> Result<u64> {
        match &mut self.session {
            Some(session) => {
                if session.is_connected() {
                    match self.h3_conn.open_webtransport_stream(conn, session.session_id(), is_bidi) {
                        Ok(stream_id) => {
                            let mut stream = StreamInfo::new(stream_id, true);
                            stream.mark_initialized();
                            session.register_stream(stream_id, stream);
                            Ok(stream_id)
                        },

                        Err(e) => Err(Error::HTTPError(e)),
                    }
                } else {
                    Err(Error::SessionNotConnected)
                }
            },
            None => Err(Error::SessionNotFound),
        }
    }

    pub fn send_stream_data(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        data: &[u8],
    ) -> Result<usize> {
        match &mut self.session {
            Some(session) => {
                if session.is_connected() {
                    let session_id = session.session_id();
                    match session.get_stream(stream_id) {
                        Some(stream) => {
                            match (stream.is_bidi(), stream.is_local()) {
                                // can't write to remote and unidirectional stream.
                                (false, false) => Err(Error::InvalidStream),
                                // uni-directional, local
                                (false, true) => self.send_stream_data_internal(conn, stream_id, data),
                                // bidirectional, remote
                                (true, false) => {
                                    if !stream.is_initialized() {
                                        self.h3_conn
                                            .send_webtransport_frame_header(conn, session_id, stream_id)?;
                                        stream.mark_initialized();
                                    }
                                    self.send_stream_data_internal(conn, stream_id, data)
                                },
                                // bidirectional, local
                                (true, true) => self.send_stream_data_internal(conn, stream_id, data),
                            }
                        },
                        None => Err(Error::StreamNotFound),
                    }
                } else {
                    Err(Error::SessionNotFound)
                }
            },
            None => Err(Error::SessionNotFound),
        }
    }

    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8]
    ) -> Result<(usize, u64, usize)> {
        self.h3_conn.recv_dgram(conn, buf)
            .map_err(|e| e.into())
    }

    pub fn send_dgram(
        &mut self,
        conn: &mut Connection,
        data: &[u8],
    ) -> Result<()> {
        match &self.session {
            Some(session) => {
                if session.is_connected() {
                    self.h3_conn
                        .send_dgram(conn, session.session_id(), data)?;
                    Ok(())
                } else {
                    Err(Error::SessionNotConnected)
                }
            },
            None => Err(Error::SessionNotFound)

        }
    }

    fn send_stream_data_internal(
        &self, conn: &mut Connection, stream_id: u64, data: &[u8],
    ) -> Result<usize> {
        match conn.stream_capacity(stream_id) {
            Ok(cap) => {
                let len = std::cmp::min(cap, data.len());
                let written = conn.stream_send(stream_id, &data[..len], false)?;
                Ok(written)
            },
            Err(e) => Err(e.into()),
        }
    }
}

