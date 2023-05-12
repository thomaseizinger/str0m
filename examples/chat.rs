#[macro_use]
extern crate tracing;

use multiaddr::{Multiaddr, Protocol};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::fingerprint::Fingerprint;
use rouille::Server;
use rouille::{Request, Response};
use str0m::change::{IceCreds, SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelData, ChannelId};
use str0m::media::MediaKind;
use str0m::media::{Direction, KeyframeRequest, MediaData, Mid, Rid};
use str0m::net::DatagramRecv;
use str0m::{net, Event};
use str0m::{net::Receive, Candidate, IceConnectionState, Input, Output, Rtc, RtcError};

mod fingerprint;
mod sdp;
mod util;

fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "chat=info,str0m=trace");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

pub fn main() {
    init_log();

    let certificate = include_bytes!("cer.pem").to_vec();
    let private_key = include_bytes!("key.pem").to_vec();

    let mut bytes = [0u8; 32];

    let keypair =
        libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes).expect("a valid keypair");

    // Figure out some public IP address, since Firefox will not accept 127.0.0.1 for WebRTC traffic.
    // let host_addr = Ipv4Addr::new(192, 168, 1, 16); // TODO: This needs to be a local address, I had two interfaces hence this is hardcoded.
    let host_addr = util::select_host_address();

    let (tx, rx) = mpsc::sync_channel(1);

    // Spin up a UDP socket for the RTC. All WebRTC traffic is going to be multiplexed over this single
    // server socket. Clients are identified via their respective remote (UDP) socket address.
    let socket = UdpSocket::bind(format!("{host_addr}:9999")).expect("binding a random UDP port");
    let addr = socket.local_addr().expect("a local socket adddress");
    info!("Bound UDP port: {}", addr);

    let fingerprint = Fingerprint::from_certificate(&certificate);

    let multiaddr = Multiaddr::empty()
        .with(Protocol::from(addr.ip()))
        .with(Protocol::Udp(addr.port()))
        .with(Protocol::WebRTC)
        .with(Protocol::Certhash(fingerprint.to_multihash()))
        .with(Protocol::P2p(keypair.public().to_peer_id().into()));

    info!("Listening on {multiaddr}");

    // The run loop is on a separate thread to the web server.
    thread::spawn(move || run(socket, rx));

    let server = Server::new_ssl(
        "0.0.0.0:3000",
        move |request| web_request(request, addr, tx.clone()),
        certificate,
        private_key,
    )
    .expect("starting the web server");

    let port = server.server_addr().port();
    info!("Connect a browser to https://{:?}:{:?}", addr.ip(), port);

    server.run();
}

// Handle a web request.
fn web_request(request: &Request, addr: SocketAddr, tx: SyncSender<Rtc>) -> Response {
    if request.method() == "GET" {
        return Response::html(include_str!("chat.html"));
    }

    // Expected POST SDP Offers.
    let mut data = request.data().expect("body to be available");

    let offer: SdpOffer = serde_json::from_reader(&mut data).expect("serialized offer");
    let mut rtc = Rtc::builder()
        // Uncomment this to see statistics
        // .set_stats_interval(Some(Duration::from_secs(1)))
        // .set_ice_lite(true)
        .build();

    // Add the shared UDP socket as a host candidate
    let candidate = Candidate::host(addr).expect("a host candidate");
    rtc.add_local_candidate(candidate);

    // Create an SDP Answer.
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .expect("offer to be accepted");

    // The Rtc instance is shipped off to the main run loop.
    tx.send(rtc).expect("to send Rtc instance");

    let body = serde_json::to_vec(&answer).expect("answer to serialize");

    Response::from_data("application/json", body)
}

/// This is the "main run loop" that handles all clients, reads and writes UdpSocket traffic,
/// and forwards media data between clients.
fn run(socket: UdpSocket, _rx: Receiver<Rtc>) -> Result<(), RtcError> {
    let mut clients: Vec<Client> = vec![];
    let mut buf = vec![0; 2000];

    loop {
        // Clean out disconnected clients
        // clients.retain(|c| c.rtc.is_alive());

        // Poll all clients, and get propagated events as a result.
        let to_propagate: Vec<_> = clients.iter_mut().map(|c| c.poll_output(&socket)).collect();
        let timeouts: Vec<_> = to_propagate.iter().filter_map(|p| p.as_timeout()).collect();

        // We keep propagating client events until all clients respond with a timeout.
        // if to_propagate.len() > timeouts.len() {
        //     propagate(&mut clients, to_propagate);
        //     // Start over to propagate more client data until all are timeouts.
        //     continue;
        // }

        // Timeout in case we have no clients. We can't wait forever since we need to keep
        // polling the spawn_new_clients to discover a client.
        fn default_timeout() -> Instant {
            Instant::now() + Duration::from_millis(100)
        }

        // All poll_output resulted in timeouts, figure out the shortest timeout.
        let timeout = timeouts.into_iter().min().unwrap_or_else(default_timeout);

        // The read timeout is not allowed to be 0. In case it is 0, we set 1 millisecond.
        let duration = (timeout - Instant::now()).max(Duration::from_millis(1));

        socket
            .set_read_timeout(Some(duration))
            .expect("setting socket read timeout");

        if let Some(input) = read_socket_input(&socket, &mut buf) {
            match input {
                Input::Timeout(_) => {}
                Input::Receive(
                    _,
                    net::Receive {
                        source,
                        destination,
                        contents: DatagramRecv::Stun(message),
                    },
                ) => {
                    if let Some((u, p)) = message.split_username() {
                        info!("Received STUN from {}:{}", u, p);

                        let mut rtc = Rtc::builder().set_ice_lite(true).build();
                        rtc.add_remote_candidate(Candidate::host(source).unwrap());
                        rtc.add_local_candidate(Candidate::host(destination).unwrap());
                        rtc.direct_api().set_remote_ice_credentials(IceCreds {
                            ufrag: u.to_owned(),
                            pass: p.to_owned(),
                        });
                        rtc.direct_api().set_remote_fingerprint("sha-256 FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF".parse().unwrap());
                        let noise_channel_id =
                            rtc.direct_api().create_data_channel(ChannelConfig {
                                label: "".to_string(),
                                ordered: false,
                                reliability: Default::default(),
                                negotiated: Some(0),
                                protocol: "".to_string(),
                            });

                        clients.push(Client::new(rtc, noise_channel_id));
                    }
                }
                other => {
                    dbg!(other);
                }
            }
        }

        // Drive time forward in all clients.
        let now = Instant::now();
        for client in &mut clients {
            client.handle_input(Input::Timeout(now));
        }
    }
}

#[test]
fn sdp_parse_test() {
    let sdp = r#"v=0
o=- 123456789 0 IN IP4 192.0.2.1
s=Example SDP Offer
t=0 0
a=ice-lite
a=rtcp-mux
m=audio 50000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
"#;

    let offer = SdpOffer::from_sdp_string(sdp).unwrap();
}

fn read_socket_input<'a>(socket: &UdpSocket, buf: &'a mut Vec<u8>) -> Option<Input<'a>> {
    buf.resize(2000, 0);

    match socket.recv_from(buf) {
        Ok((n, source)) => {
            buf.truncate(n);

            // Parse data to a DatagramRecv, which help preparse network data to
            // figure out the multiplexing of all protocols on one UDP port.
            let Ok(contents) = buf.as_slice().try_into() else {
                return None;
            };

            return Some(Input::Receive(
                Instant::now(),
                Receive {
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents,
                },
            ));
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout(). One for windows, one for the rest.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => None,
            _ => panic!("UdpSocket read failed: {e:?}"),
        },
    }
}

#[derive(Debug)]
struct Client {
    id: ClientId,
    rtc: Rtc,
    pending: Option<SdpPendingOffer>,
    cid: Option<ChannelId>,
    tracks_in: Vec<Arc<TrackIn>>,
    tracks_out: Vec<TrackOut>,
    chosen_rid: Option<Rid>,
    noise_channel_id: ChannelId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientId(u64);

impl Deref for ClientId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
struct TrackIn {
    origin: ClientId,
    mid: Mid,
    kind: MediaKind,
}

#[derive(Debug)]
struct TrackOut {
    track_in: Weak<TrackIn>,
    state: TrackOutState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackOutState {
    ToOpen,
    Negotiating(Mid),
    Open(Mid),
}

impl TrackOut {
    fn mid(&self) -> Option<Mid> {
        match self.state {
            TrackOutState::ToOpen => None,
            TrackOutState::Negotiating(m) | TrackOutState::Open(m) => Some(m),
        }
    }
}

impl Client {
    fn new(rtc: Rtc, noise_channel_id: ChannelId) -> Client {
        static ID_COUNTER: AtomicU64 = AtomicU64::new(0);
        let next_id = ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        Client {
            id: ClientId(next_id),
            noise_channel_id,
            rtc,
            pending: None,
            cid: None,
            tracks_in: vec![],
            tracks_out: vec![],
            chosen_rid: None,
        }
    }

    fn accepts(&self, input: &Input) -> bool {
        self.rtc.accepts(input)
    }

    fn handle_input(&mut self, input: Input) {
        if !self.rtc.is_alive() {
            return;
        }

        if let Err(e) = self.rtc.handle_input(input) {
            warn!("Client ({}) disconnected: {:?}", *self.id, e);
            self.rtc.disconnect();
        }
    }

    fn poll_output(&mut self, socket: &UdpSocket) -> Propagated {
        if !self.rtc.is_alive() {
            return Propagated::Noop;
        }

        match self.rtc.poll_output() {
            Ok(output) => self.handle_output(output, socket),
            Err(e) => {
                warn!("Client ({}) poll_output failed: {:?}", *self.id, e);
                self.rtc.disconnect();
                Propagated::Noop
            }
        }
    }

    fn handle_output(&mut self, output: Output, socket: &UdpSocket) -> Propagated {
        match output {
            Output::Transmit(transmit) => {
                dbg!(&transmit);

                socket
                    .send_to(&transmit.contents, transmit.destination)
                    .expect("sending UDP data");
                Propagated::Noop
            }
            Output::Timeout(t) => Propagated::Timeout(t),
            Output::Event(e) => match e {
                Event::IceConnectionStateChange(v) => {
                    if v == IceConnectionState::Disconnected {
                        // Ice disconnect could result in trying to establish a new connection,
                        // but this impl just disconnects directly.
                        self.rtc.disconnect();
                    }
                    Propagated::Noop
                }
                Event::ChannelOpen(cid, _) => {
                    self.cid = Some(cid);
                    Propagated::Noop
                }
                Event::ChannelData(data) => self.handle_channel_data(data),
                e => {
                    println!("Unhandled event: {:?}", e);
                    Propagated::Noop
                }
            },
        }
    }

    fn handle_channel_data(&mut self, d: ChannelData) -> Propagated {
        dbg!(d);

        Propagated::Noop
    }
}

/// Events propagated between client.
#[allow(clippy::large_enum_variant)]
enum Propagated {
    /// When we have nothing to propagate.
    Noop,

    /// Poll client has reached timeout.
    Timeout(Instant),

    /// A new incoming track opened.
    TrackOpen(ClientId, Weak<TrackIn>),

    /// Data to be propagated from one client to another.
    MediaData(ClientId, MediaData),

    /// A keyframe request from one client to the source.
    KeyframeRequest(ClientId, KeyframeRequest, ClientId, Mid),
}

impl Propagated {
    /// Get client id, if the propagated event has a client id.
    fn client_id(&self) -> Option<ClientId> {
        match self {
            Propagated::TrackOpen(c, _)
            | Propagated::MediaData(c, _)
            | Propagated::KeyframeRequest(c, _, _, _) => Some(*c),
            _ => None,
        }
    }

    /// If the propagated data is a timeout, returns the instant.
    fn as_timeout(&self) -> Option<Instant> {
        if let Self::Timeout(v) = self {
            Some(*v)
        } else {
            None
        }
    }
}
