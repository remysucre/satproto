use gloo_net::http::Request;
use satproto_core::crypto;
use satproto_core::schema::{FollowList, KeyEnvelope, Post, Profile};
use wasm_bindgen::JsValue;

/// Fetch a user's follow list.
pub async fn fetch_follow_list(domain: &str) -> Result<FollowList, JsValue> {
    let url = format!("https://{}/sat/follows/index.json", domain);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch follows: {}", e)))?;
    resp.json::<FollowList>()
        .await
        .map_err(|e| JsValue::from_str(&format!("parse follows: {}", e)))
}

/// Fetch a user's profile/discovery document.
pub async fn fetch_profile(domain: &str) -> Result<Profile, JsValue> {
    let url = format!("https://{}/.well-known/satproto.json", domain);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch profile: {}", e)))?;
    resp.json::<Profile>()
        .await
        .map_err(|e| JsValue::from_str(&format!("parse profile: {}", e)))
}

/// Fetch the current epoch number for a user.
pub async fn fetch_current_epoch(domain: &str) -> Result<u32, JsValue> {
    let url = format!("https://{}/sat/current_epoch", domain);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch epoch: {}", e)))?;
    let text = resp
        .text()
        .await
        .map_err(|e| JsValue::from_str(&format!("read epoch: {}", e)))?;
    text.trim()
        .parse::<u32>()
        .map_err(|e| JsValue::from_str(&format!("parse epoch: {}", e)))
}

/// Fetch and decrypt the key envelope for us from a given user and epoch.
async fn fetch_key_envelope(
    domain: &str,
    epoch: u32,
    my_domain: &str,
    my_secret: &[u8; 32],
) -> Result<[u8; 32], JsValue> {
    let url = format!(
        "https://{}/sat/epochs/{}/keys/{}.json",
        domain, epoch, my_domain
    );
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch key: {}", e)))?;
    let envelope: KeyEnvelope = resp
        .json()
        .await
        .map_err(|e| JsValue::from_str(&format!("parse key: {}", e)))?;
    let sealed_bytes = crypto::from_base64(&envelope.encrypted_key)
        .map_err(|e| JsValue::from_str(&format!("decode key: {}", e)))?;
    crypto::open_content_key(&sealed_bytes, my_secret)
        .map_err(|e| JsValue::from_str(&format!("decrypt key: {}", e)))
}

/// Fetch and decrypt the encrypted data store for a given user and epoch.
async fn fetch_encrypted_store(domain: &str, epoch: u32) -> Result<Vec<u8>, JsValue> {
    let url = format!("https://{}/sat/epochs/{}/data.json.enc", domain, epoch);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch store: {}", e)))?;
    resp.binary()
        .await
        .map_err(|e| JsValue::from_str(&format!("read store: {}", e)))
}

/// Fetch all posts from a user across all their epochs that we have access to.
pub async fn fetch_user_posts(
    domain: &str,
    my_domain: &str,
    my_secret: &[u8; 32],
) -> Result<Vec<Post>, JsValue> {
    let current_epoch = fetch_current_epoch(domain).await?;
    let mut all_posts = Vec::new();

    for epoch in 0..=current_epoch {
        // Try to get our key for this epoch — we may not have access to all epochs
        let content_key =
            match fetch_key_envelope(domain, epoch, my_domain, my_secret).await {
                Ok(key) => key,
                Err(_) => continue, // no access to this epoch
            };

        let encrypted = fetch_encrypted_store(domain, epoch).await?;
        let store = satproto_core::db::decrypt_store(&encrypted, &content_key)
            .map_err(|e| JsValue::from_str(&format!("decrypt store: {}", e)))?;
        all_posts.extend(store.get_all_posts());
    }

    Ok(all_posts)
}
