use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::error::Error;

use crate::{encryption::decrypt_data, MessageData};

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    room_id: String,
}

pub fn create_client() -> Client {

    Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap()
}

pub async fn send_encrypted_message(
    encrypted_message: &str,
    room_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {

    let client = create_client(); 

    let formatted_encrypted_message = format!(
        "-----BEGIN ENCRYPTED MESSAGE-----{}-----END ENCRYPTED MESSAGE-----",
        encrypted_message
    );

    let message_data = MessageData {
        message: formatted_encrypted_message,
        room_id: room_id.to_string(),
    };

    let send_url = format!("{}/send", server_url);

    let res = client
        .post(&send_url)
        .json(&message_data)
        .timeout(Duration::from_secs(60))
        .send()
        .await?; 

    if res.status().is_success() {

    } else {
        eprintln!("Failed to send message: {}", res.status());
    }

    Ok(())
}

pub async fn receive_and_fetch_messages(
    room_id: &str,
    shared_secret: &str,
    server_url: &str,
    gui: bool,
) -> Result<Vec<String>, Box<dyn Error + Send + Sync + 'static>> {
    let client = Client::new();
    let url = format!("{}/messages?room_id={}", server_url, room_id);

    let res = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?;

    let mut messages = Vec::new();

    if res.status().is_success() {
        let body = res.text().await?;

        let re = Regex::new(
            r"-----BEGIN ENCRYPTED MESSAGE-----\s*(.*?)\s*-----END ENCRYPTED MESSAGE-----",
        )
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)?;

        for cap in re.captures_iter(&body) {
            if let Some(encrypted_message) = cap.get(1) {
                let cleaned_message = encrypted_message.as_str().trim();

                if let Ok(decrypted_message) =
                    decrypt_data(cleaned_message, shared_secret)
                {
                    fn unpad_message(message: &str) -> String {
                        if let (Some(start), Some(end)) =
                            (message.find("<padding>"), message.find("</padding>"))
                        {
                            let (before, _) = message.split_at(start);
                            let (_, after) = message.split_at(end + "</padding>".len());
                            return format!("{}{}", before, after);
                        }
                        message.to_string()
                    }

                    let unpadded = unpad_message(&decrypted_message);

                    let mut cleaned = unpadded
                        .replace("<strong>", "")
                        .replace("</strong>", "");

                    let re_pfp: Regex = Regex::new(r#"<pfp>.*?</pfp>"#)
                        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)?;
                    let re_media: Regex = Regex::new(r#"<media>.*?</media>"#)
                        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync + 'static>)?;

                    cleaned = re_pfp.replace_all(&cleaned, "").to_string();
                    cleaned = re_media.replace_all(&cleaned, "").to_string();

                    if cleaned.contains("[DUMMY_DATA]:") {
                        continue;
                    }

                    messages.push(if gui { cleaned.clone() } else { cleaned });
                }
            }
        }
    } else {
        eprintln!(
            "Failed to fetch messages: {} - {}",
            res.status(),
            res.text().await?
        );
    }

    Ok(messages)
}