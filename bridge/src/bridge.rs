use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose;
use base64::Engine;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, timeout};

use crate::encryption::encrypt_data;
use crate::network_operations::{receive_and_fetch_messages, send_encrypted_message};

pub struct Bridge {
    #[allow(dead_code)]
    irc_client: Arc<Mutex<CustomIrcClient>>,
    #[allow(dead_code)]
    tx: mpsc::Sender<(String, String)>,
    #[allow(dead_code)]
    seen_amz: Arc<Mutex<HashSet<String>>>,
    #[allow(dead_code)]
    seen_irc: Arc<Mutex<HashSet<String>>>,
}

impl Bridge {
    pub fn new(
        shared_secret: String,
        amnezichat_url: String,
        irc_url: String,
        room_id: String,
        irc_nick: String,
        irc_channel: String,
        sasl_username: Option<String>,
        sasl_password: Option<String>,
    ) -> io::Result<Self> {
        let client = CustomIrcClient::connect_and_auth(
            &irc_url,
            &irc_nick,
            &irc_channel,
            sasl_username.as_deref(),
            sasl_password.as_deref(),
        )?;
        let irc_client = Arc::new(Mutex::new(client));

        let (tx, mut rx) = mpsc::channel(100);
        let seen_amz = Arc::new(Mutex::new(HashSet::new()));
        let seen_irc = Arc::new(Mutex::new(HashSet::new()));

        {
            let polling_tx = tx.clone();
            let seen_amz_clone = Arc::clone(&seen_amz);
            let secret_poll = shared_secret.clone();
            let url_poll = amnezichat_url.clone();
            let room_poll = room_id.clone();
            let irc_chan_poll = irc_channel.clone();

            tokio::spawn(async move {
                loop {
                    match timeout(Duration::from_secs(10), receive_and_fetch_messages(&room_poll, &secret_poll, &url_poll, false)).await {
                        Ok(Ok(msgs)) => {
                            for m in msgs {
                                let mut set = seen_amz_clone.lock().await;
                                if set.contains(&m) {
                                    continue;
                                }
                                set.insert(m.clone());
                                let content = m.strip_prefix("[AMZ]").map(|s| s.to_string()).unwrap_or_else(|| m.clone());
                                if !content.starts_with("[IRC]") {
                                    let transformed = if let Some((user, msg)) = content.split_once(": ") {
                                        format!("\x02\x0311{} >\x02\x03 {}", user.trim(), msg.trim())
                                    } else {
                                        content.clone()
                                    };
                                    let _ = polling_tx.send((irc_chan_poll.clone(), transformed)).await;
                                }
                            }
                        }
                        Ok(Err(e)) => eprintln!("Amnezichat pull error: {}", e),
                        Err(_) => eprintln!("Amnezichat pull timeout"),
                    }
                    sleep(Duration::from_secs(1)).await;
                }
            });
        }

        {
            let client_recv = Arc::clone(&irc_client);
            let seen_irc_clone = Arc::clone(&seen_irc);
            let secret_recv = shared_secret.clone();
            let url_recv = amnezichat_url.clone();
            let room_recv = room_id.clone();
            let irc_url_clone = irc_url.clone();
            let irc_nick_clone = irc_nick.clone();
            let irc_chan_clone = irc_channel.clone();
            let sasl_user_clone = sasl_username.clone();
            let sasl_pass_clone = sasl_password.clone();

            tokio::spawn(async move {
                loop {
                    let mut guard = client_recv.lock().await;
                    match timeout(Duration::from_secs(35), async { guard.receive_message() }).await {
                        Ok(Ok(raw)) => {
                            if raw.starts_with("PING") {
                                let _ = guard.send_raw(&raw.replace("PING", "PONG"));
                                continue;
                            }

                            if let Some((target, msg, nick)) = parse_irc_message(&raw) {
                                let key = format!("{}:{}", nick, msg);
                                let mut set = seen_irc_clone.lock().await;
                                if set.contains(&key) {
                                    continue;
                                }
                                set.insert(key.clone());

                                if msg.trim() == ".amnezichat" {
                                    let response = format!("{}: Anti-forensic and secure messenger. Source code: https://github.com/Amnezichat/Amnezichat", nick);
                                    let _ = guard.send_message(&target, &response);
                                    continue;
                                }

                                if !msg.starts_with("[AMZ]") {
                                    let formatted = format!("[IRC]<strong>{}</strong>: {}", nick, msg);
                                    match encrypt_data(&formatted, &secret_recv) {
                                        Ok(enc) => {
                                            if let Err(e) = timeout(Duration::from_secs(5), send_encrypted_message(&enc, &room_recv, &url_recv)).await {
                                                eprintln!("Amnezichat send timeout or failure: {}", e);
                                            }
                                        }
                                        Err(e) => eprintln!("Encryption error: {}", e),
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!("Error receiving message: {:?}", e);
                            drop(guard);
                            reconnect_irc(&client_recv, &irc_url_clone, &irc_nick_clone, &irc_chan_clone, sasl_user_clone.clone(), sasl_pass_clone.clone()).await;
                        }
                        Err(_) => {
                            eprintln!("Receive message timed out. Reconnecting...");
                            drop(guard);
                            reconnect_irc(&client_recv, &irc_url_clone, &irc_nick_clone, &irc_chan_clone, sasl_user_clone.clone(), sasl_pass_clone.clone()).await;
                        }
                    }
                }
            });
        }

        {
            let client_send = Arc::clone(&irc_client);
            tokio::spawn(async move {
                while let Some((tgt, msg)) = rx.recv().await {
                    let mut guard = client_send.lock().await;
                    let _ = guard.send_message(&tgt, &msg);
                }
            });
        }

        {
            let client_ping = Arc::clone(&irc_client);
            let irc_url_clone = irc_url.clone();
            let irc_nick_clone = irc_nick.clone();
            let irc_chan_clone = irc_channel.clone();
            let sasl_user_clone = sasl_username.clone();
            let sasl_pass_clone = sasl_password.clone();

            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(60)).await;
                    let mut guard = client_ping.lock().await;
                    if let Err(e) = guard.send_raw("PING :keepalive\r\n") {
                        eprintln!("Failed to send keep-alive PING: {}", e);
                        drop(guard);
                        reconnect_irc(&client_ping, &irc_url_clone, &irc_nick_clone, &irc_chan_clone, sasl_user_clone.clone(), sasl_pass_clone.clone()).await;
                    }
                }
            });
        }

        Ok(Bridge { irc_client, tx, seen_amz, seen_irc })
    }
}

async fn reconnect_irc(
    client: &Arc<Mutex<CustomIrcClient>>,
    server: &str,
    nick: &str,
    channel: &str,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
) {
    let mut delay_secs = 5;
    loop {
        match CustomIrcClient::connect_and_auth(server, nick, channel, sasl_username.as_deref(), sasl_password.as_deref()) {
            Ok(newc) => {
                let mut guard = client.lock().await;
                *guard = newc;
                eprintln!("Reconnected to IRC.");
                break;
            }
            Err(e) => {
                eprintln!("Reconnect failed: {}. Retrying in {}s...", e, delay_secs);
                sleep(Duration::from_secs(delay_secs)).await;
                delay_secs = (delay_secs * 2).min(60);
            }
        }
    }
}

pub struct CustomIrcClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl CustomIrcClient {
    pub fn new(server_url: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(server_url)?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    pub fn connect_and_auth(
        server_url: &str,
        nick: &str,
        channel: &str,
        sasl_username: Option<&str>,
        sasl_password: Option<&str>,
    ) -> io::Result<Self> {
        let mut c = Self::new(server_url)?;

        if let (Some(user), Some(pass)) = (sasl_username, sasl_password) {
            c.send_raw("CAP REQ :sasl\r\n")?;
            loop {
                let line = c.receive_message()?;
                if line.contains("CAP") && line.contains("ACK") && line.contains("sasl") {
                    break;
                }
            }

            c.send_raw("AUTHENTICATE PLAIN\r\n")?;
            loop {
                let line = c.receive_message()?;
                if line.trim() == "AUTHENTICATE +" {
                    break;
                }
            }

            let auth_str = format!("\0{}\0{}", user, pass);
            let auth_base64 = general_purpose::STANDARD.encode(auth_str);
            c.send_raw(&format!("AUTHENTICATE {}\r\n", auth_base64))?;

            loop {
                let line = c.receive_message()?;
                if line.contains("903") {
                    break;
                } else if line.contains("904") || line.contains("905") {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "SASL authentication failed"));
                }
            }

            c.send_raw("CAP END\r\n")?;
        }

        c.send_nick(nick)?;
        c.send_user(nick, "0", "*", nick)?;

        loop {
            let line = c.receive_message()?;
            if line.contains("376") || line.contains("422") {
                break;
            }
        }

        c.join_channel(channel)?;
        Ok(c)
    }

    pub fn send_nick(&mut self, nick: &str) -> io::Result<()> {
        self.send_raw(&format!("NICK {}\r\n", nick))
    }

    pub fn send_user(&mut self, user: &str, mode: &str, host: &str, real: &str) -> io::Result<()> {
        self.send_raw(&format!("USER {} {} {} :{}\r\n", user, mode, host, real))
    }

    pub fn join_channel(&mut self, chan: &str) -> io::Result<()> {
        self.send_raw(&format!("JOIN {}\r\n", chan))
    }

    pub fn send_message(&mut self, tgt: &str, m: &str) -> io::Result<()> {
        let clean = m.replace(['\r', '\n'], " ")
            .chars().take(400).collect::<String>();
        self.send_raw(&format!("PRIVMSG {} :{}\r\n", tgt, clean))
    }

    pub fn send_raw(&mut self, data: &str) -> io::Result<()> {
        self.stream.write_all(data.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn receive_message(&mut self) -> io::Result<String> {
        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed"));
        }
        Ok(buf)
    }
}

fn parse_irc_message(raw: &str) -> Option<(String, String, String)> {
    let t = raw.trim();
    if !t.contains("PRIVMSG") {
        return None;
    }
    let parts: Vec<&str> = t.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return None;
    }
    let prefix = if t.starts_with(':') { &t[1..] } else { t };
    let nick = prefix.split('!').next()?.to_string();
    let target = parts[2].to_string();
    let msg = parts[3].trim_start_matches(':').to_string();
    Some((target, msg, nick))
}

pub fn run_bridge(
    shared_secret: String,
    amnezichat_url: String,
    irc_url: String,
    room_id: String,
    irc_nick: String,
    irc_channel: String,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
) -> io::Result<Bridge> {
    Bridge::new(
        shared_secret,
        amnezichat_url,
        irc_url,
        room_id,
        irc_nick,
        irc_channel,
        sasl_username,
        sasl_password,
    )
}
