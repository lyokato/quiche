// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::fs;
use std::net;

use std::collections::HashMap;
use std::pin::Pin;

use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::bn::MsbOption;
use boring::ec::EcGroup;
use boring::ec::EcKey;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::x509::extension::BasicConstraints;
use env_logger::Env;
use quiche::h3::webtransport::ServerSession;
use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;
struct Client {
    conn: Pin<Box<quiche::Connection>>,

    session: Option<ServerSession>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

// A WebTransport Server. In order to connect to this server you'll need a web frontend such
// as the example frontend provided in `webtransport-server-public/index.html`
fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .init();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 0 {
        println!("Usage: {}", cmd);
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let server_addr = "127.0.0.1:4430";
    // Create the UDP listening socket, and register it with the event loop.
    let socket = net::UdpSocket::bind(server_addr).unwrap();

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    let cert_file = "examples/webtransport_example.crt";
    let priv_file = "examples/webtransport_example.key";

    // WebTransport certs are required to be rotated such that their expiration date does not exceed 10 days into the future.
    //
    // This is equivalent to:
    // openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -sha256 -nodes -out webtransport_example.crt -keyout webtransport_example.key -days 10
    let curve =
        &EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key_pair = EcKey::generate(curve).unwrap();
    let key_pair = PKey::from_ec_key(key_pair).unwrap();

    let mut builder = boring::x509::X509Builder::new().unwrap();
    builder.set_version(0x2).unwrap();
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    };
    builder.set_serial_number(&serial_number).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(10).unwrap())
        .unwrap();

    // Build the x509 issuer and subject names. These are arbitrary.
    let mut x509_name = boring::x509::X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "US").unwrap();
    x509_name.append_entry_by_text("ST", "CA").unwrap();
    x509_name
        .append_entry_by_text("O", "Some organization")
        .unwrap();

    let x509_name = x509_name.build();
    builder.set_issuer_name(&x509_name).unwrap();
    builder.set_subject_name(&x509_name).unwrap();

    builder.set_pubkey(&key_pair).unwrap();

    builder
        .append_extension(
            BasicConstraints::new().critical().ca().build().unwrap(),
        )
        .unwrap();

    builder.sign(&key_pair, MessageDigest::sha256()).unwrap();

    // Write the new cert and private key to disk
    let cert_pem = builder.build().to_pem().unwrap();
    fs::write(cert_file, cert_pem).unwrap();
    let priv_pem = key_pair.private_key_to_pem_pkcs8().unwrap();
    fs::write(priv_file, priv_pem).unwrap();

    // Generate a SHA256 fingerprint from the cert
    let pem_serialized = fs::read_to_string(cert_file).unwrap();
    let der_serialized = pem::parse(&pem_serialized).unwrap().contents;
    let hash = ring::digest::digest(&ring::digest::SHA256, &der_serialized);

    info!("Generated fresh private key and certification (expires in no more then 10 days per WebTransport requirements)");

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.load_cert_chain_from_pem_file(cert_file).unwrap();
    config.load_priv_key_from_pem_file(priv_file).unwrap();

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    config.enable_dgram(true, 65536, 65536);

    // let mut h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    info!("Server started on {}", server_addr);
    println!(
        "Server {:?} Fingerprint:\n{}",
        hash.algorithm(),
        hash.as_ref()
            .into_iter()
            .into_iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    );

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                trace!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            trace!("got {} bytes", len);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            trace!("got packet {:?}", hdr);

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid)
                && !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, &from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("Invalid address validation token");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("Invalid destination connection ID");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn =
                    quiche::accept(&scid, odcid.as_ref(), from, &mut config)
                        .unwrap();

                clients.insert(
                    scid.clone(),
                    Client {
                        conn,
                        session: None,
                    },
                );

                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo { from };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            trace!("{} processed {} bytes", client.conn.trace_id(), read);

            // Create a new HTTP/3 connection as soon as the QUIC connection
            // is established.
            if (client.conn.is_in_early_data() || client.conn.is_established())
                && client.session.is_none()
            {
                debug!(
                    "{} QUIC handshake completed, now trying HTTP/3",
                    client.conn.trace_id()
                );

                let server_session =
                    quiche::h3::webtransport::ServerSession::with_transport(
                        &mut client.conn,
                    )
                    .unwrap();
                client.session = Some(server_session);
            }

            // The `poll` can pull out the events that occurred according to the data passed here.
            for (_, Client { conn, session }) in clients
                .iter_mut()
                .filter(|(_, client)| client.session.is_some())
            {
                let server_session = session.as_mut().unwrap();

                loop {
                    match server_session.poll(conn) {
                        Ok(quiche::h3::webtransport::ServerEvent::ConnectRequest(_req)) => {
                            // you can handle request with
                            // req.authority()
                            // req.path()
                            // and you can validate this request with req.origin()
                            server_session.accept_connect_request(conn, None).unwrap();
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::StreamData(stream_id)) => {
                            let mut buf = vec![0; 10000];
                            while let Ok(len) =
                                server_session.recv_stream_data(conn, stream_id, &mut buf)
                            {
                                let stream_data = &buf[0..len];
                                dbg!(String::from_utf8_lossy(stream_data));

                                // handle stream_data
                                if (stream_id & 0x2) == 0 {
                                    // bidirectional stream
                                    // you can send data through this stream.
                                    server_session
                                        .send_stream_data(conn, stream_id, stream_data)
                                        .unwrap();
                                } else {
                                    // you cannot send data through client-initiated-unidirectional-stream.
                                    // so, open new server-initiated-unidirectional-stream, and send data
                                    // through it.
                                    let new_stream_id =
                                        server_session.open_stream(conn, false).unwrap();
                                    server_session
                                        .send_stream_data(conn, new_stream_id, stream_data)
                                        .unwrap();
                                }
                            }
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::StreamFinished(stream_id)) => {
                            // A WebTrnasport stream finished, handle it.
                            info!("Stream finished {:?}", stream_id)
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::Datagram) => {
                            info!("Received a datagram!");
                            let mut buf = vec![0; 1500];
                            while let Ok((in_session, offset, total)) =
                                server_session.recv_dgram(conn, &mut buf)
                            {
                                if in_session {
                                    let dgram = &buf[offset..total];
                                    dbg!(std::string::String::from_utf8_lossy(dgram));
                                    // handle this dgram

                                    // for instance, you can write echo-server like following
                                    server_session.send_dgram(conn, dgram).unwrap();
                                } else {
                                    // this dgram is not related to current WebTransport session. ignore.
                                }
                            }
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionReset(_e)) => {
                            // Peer reset session stream, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionFinished) => {
                            // Peer finish session stream, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::SessionGoAway) => {
                            // Peer signalled it is going away, handle it.
                        }

                        Ok(quiche::h3::webtransport::ServerEvent::Other(_stream_id, _event)) => {
                            // Original h3::Event which is not related to WebTransport.
                        }

                        Err(quiche::h3::webtransport::Error::Done) => {
                            break;
                        }

                        Err(_e) => {
                            break;
                        }
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], &send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                trace!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, c| {
            if c.conn.is_closed() {
                // info!("{} connection collected {:?}", c.conn.trace_id(), c.conn.stats());
                info!("connection collected {}", c.conn.trace_id());
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}
