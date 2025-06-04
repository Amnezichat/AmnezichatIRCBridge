use std::io::{self, Write};
use std::time::Duration;
use std::sync::Arc;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

mod bridge;
mod encryption;
mod network_operations;

use bridge::run_bridge;
use encryption::{derive_key, derive_salt_from_password};
use network_operations::receive_and_fetch_messages;

#[derive(Serialize, Deserialize, Debug)]
struct MessageData {
    message: String,
    room_id: String,
}

fn generate_random_room_id() -> String {
    const ID_LENGTH: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    (0..ID_LENGTH)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

#[derive(Clone)]
struct AppState {
    amnezichat_url: String,
    irc_url: String,
    username: String,
    is_group_chat: bool,
    room_id_input: String,
    room_password: String,
    irc_channel: String,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            amnezichat_url: String::new(),
            irc_url: String::new(),
            username: String::new(),
            is_group_chat: false,
            room_id_input: String::new(),
            room_password: String::new(),
            irc_channel: String::new(),
            sasl_username: None,
            sasl_password: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut state = AppState::default();

    print!("Enter Amnezichat Server URL: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut state.amnezichat_url)?;
    state.amnezichat_url = state.amnezichat_url.trim().to_owned();

    print!("Enter IRC Server URL: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut state.irc_url)?;
    state.irc_url = state.irc_url.trim().to_owned();

    print!("Enter Username (IRC nick): ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut state.username)?;
    state.username = state.username.trim().to_owned();

    print!("Is this a group chat? (yes/no): ");
    io::stdout().flush()?;
    let mut yn = String::new();
    io::stdin().read_line(&mut yn)?;
    state.is_group_chat = yn.trim().eq_ignore_ascii_case("yes");

    if state.is_group_chat {
        print!("Enter Room Password (min 8 chars): ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut state.room_password)?;
        state.room_password = state.room_password.trim().to_owned();
    }

    print!("Enter IRC Channel (e.g., #mychannel): ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut state.irc_channel)?;
    state.irc_channel = state.irc_channel.trim().to_owned();

    print!("Use SASL authentication? (yes/no): ");
    io::stdout().flush()?;
    let mut use_sasl = String::new();
    io::stdin().read_line(&mut use_sasl)?;
    if use_sasl.trim().eq_ignore_ascii_case("yes") {
        print!("Enter SASL Username: ");
        io::stdout().flush()?;
        let mut sasl_user = String::new();
        io::stdin().read_line(&mut sasl_user)?;
        state.sasl_username = Some(sasl_user.trim().to_owned());

        print!("Enter SASL Password: ");
        io::stdout().flush()?;
        let mut sasl_pass = String::new();
        io::stdin().read_line(&mut sasl_pass)?;
        state.sasl_password = Some(sasl_pass.trim().to_owned());
    }

    loop {
        println!("\n1) ➕ Create Room\n2) 🔗 Join Room");
        print!("Choice: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim() {
            "1" => {
                state.room_id_input = generate_random_room_id();
                break;
            }
            "2" => {
                print!("Enter existing Room ID: ");
                io::stdout().flush()?;
                io::stdin().read_line(&mut state.room_id_input)?;
                state.room_id_input = state.room_id_input.trim().to_owned();
                break;
            }
            _ => println!("Invalid; choose 1 or 2."),
        }
    }

    println!("Using Room ID: {}", state.room_id_input);

    validate_and_start(state.clone()).await?;
    Ok(())
}

async fn validate_and_start(state: AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if state.amnezichat_url.is_empty()
        || state.irc_url.is_empty()
        || state.username.is_empty()
        || (state.is_group_chat && state.room_password.len() < 8)
    {
        return Err("Missing or invalid inputs".into());
    }

    run_app_logic(state).await?;

    Ok(())
}

async fn run_app_logic(state: AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !state.is_group_chat {
        return Err("Group chat only".into());
    }

    let salt = derive_salt_from_password(&state.room_password);
    let key = derive_key(&state.room_password, &salt);
    let shared_secret = hex::encode(key);

    let secret = Arc::new(Mutex::new(shared_secret.clone()));
    let rid = Arc::new(Mutex::new(state.room_id_input.clone()));
    let url = Arc::new(Mutex::new(state.amnezichat_url.clone()));

    let receiver_handle = {
        let secret = Arc::clone(&secret);
        let rid = Arc::clone(&rid);
        let url = Arc::clone(&url);
        tokio::spawn(async move {
            loop {
                let rid_val = rid.lock().await.clone();
                let secret_val = secret.lock().await.clone();
                let url_val = url.lock().await.clone();
                let _ = receive_and_fetch_messages(&rid_val, &secret_val, &url_val, true).await;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        })
    };

    let _bridge = run_bridge(
        shared_secret.clone(),
        state.amnezichat_url.clone(),
        state.irc_url.clone(),
        state.room_id_input.clone(),
        state.username.clone(),
        state.irc_channel.clone(),
        state.sasl_username.clone(),
        state.sasl_password.clone(),
    )?;

    println!("[bridge] launched — IRC: {}  Amnezichat: {}", state.irc_url, state.amnezichat_url);

    receiver_handle.await?;

    Ok(())
}
