use gloo_net::http::Request;
use satproto_core::crypto;
use satproto_core::schema::{FollowList, KeyEnvelope, Post, PostIndex, Profile};
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

/// Fetch the post index for a user.
pub async fn fetch_post_index(domain: &str) -> Result<PostIndex, JsValue> {
    let url = format!("https://{}/sat/posts/index.json", domain);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch post index: {}", e)))?;
    resp.json::<PostIndex>()
        .await
        .map_err(|e| JsValue::from_str(&format!("parse post index: {}", e)))
}

/// Fetch and decrypt the key envelope for us from a given user.
async fn fetch_key_envelope(
    domain: &str,
    my_domain: &str,
    my_secret: &[u8; 32],
) -> Result<[u8; 32], JsValue> {
    let url = format!("https://{}/sat/keys/{}.json", domain, my_domain);
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

/// Fetch and decrypt a single post.
async fn fetch_post(
    domain: &str,
    post_id: &str,
    content_key: &[u8; 32],
) -> Result<Post, JsValue> {
    let url = format!("https://{}/sat/posts/{}.json.enc", domain, post_id);
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch post: {}", e)))?;
    let encrypted = resp
        .binary()
        .await
        .map_err(|e| JsValue::from_str(&format!("read post: {}", e)))?;
    let decrypted = crypto::decrypt_data(&encrypted, content_key)
        .map_err(|e| JsValue::from_str(&format!("decrypt post: {}", e)))?;
    serde_json::from_slice(&decrypted)
        .map_err(|e| JsValue::from_str(&format!("parse post: {}", e)))
}

/// Fetch recent posts from a user (up to `limit`).
pub async fn fetch_user_posts(
    domain: &str,
    my_domain: &str,
    my_secret: &[u8; 32],
    limit: usize,
) -> Result<Vec<Post>, JsValue> {
    let content_key = fetch_key_envelope(domain, my_domain, my_secret).await?;
    let index = fetch_post_index(domain).await?;

    let mut posts = Vec::new();
    for post_id in index.posts.iter().take(limit) {
        match fetch_post(domain, post_id, &content_key).await {
            Ok(post) => posts.push(post),
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("Failed to fetch post {} from {}: {:?}", post_id, domain, e).into(),
                );
            }
        }
    }

    Ok(posts)
}
