use wasm_bindgen::prelude::*;

mod fetch;
mod publish;

use satproto_core::schema::Post;

/// Initialize the client. Call once on page load.
#[wasm_bindgen]
pub async fn init() -> Result<(), JsValue> {
    // Check if we have a keypair in localStorage, generate one if not
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    if storage.get_item("satproto_secret_key").map_err(|_| "storage error")?.is_none() {
        let (sk, pk) = satproto_core::crypto::generate_keypair();
        storage
            .set_item("satproto_secret_key", &satproto_core::crypto::to_base64(&sk))
            .map_err(|_| "failed to store secret key")?;
        storage
            .set_item("satproto_public_key", &satproto_core::crypto::to_base64(&pk))
            .map_err(|_| "failed to store public key")?;
        web_sys::console::log_1(&"Generated new keypair".into());
    }

    Ok(())
}

/// Get our public key from localStorage.
#[wasm_bindgen]
pub fn get_public_key() -> Result<String, JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;
    storage
        .get_item("satproto_public_key")
        .map_err(|_| "storage error")?
        .ok_or_else(|| "no public key - call init() first".into())
}

/// Load the aggregated feed for a user. Returns JSON array of posts.
#[wasm_bindgen]
pub async fn load_feed(my_domain: &str) -> Result<JsValue, JsValue> {
    let follow_list = fetch::fetch_follow_list(my_domain).await?;
    let mut all_posts: Vec<Vec<Post>> = Vec::new();

    let (sk, _pk) = get_keypair()?;

    for domain in &follow_list.follows {
        match fetch::fetch_user_posts(domain, my_domain, &sk).await {
            Ok(posts) => all_posts.push(posts),
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("Failed to fetch from {}: {:?}", domain, e).into(),
                );
            }
        }
    }

    let feed = satproto_core::feed::merge_feeds(all_posts);
    serde_wasm_bindgen::to_value(&feed).map_err(|e| e.into())
}

/// Load replies to a specific post. Returns JSON array of posts.
#[wasm_bindgen]
pub async fn load_replies(
    my_domain: &str,
    post_id: &str,
    post_author: &str,
) -> Result<JsValue, JsValue> {
    let follow_list = fetch::fetch_follow_list(my_domain).await?;
    let mut all_posts: Vec<Post> = Vec::new();

    let (sk, _pk) = get_keypair()?;

    for domain in &follow_list.follows {
        match fetch::fetch_user_posts(domain, my_domain, &sk).await {
            Ok(posts) => {
                let replies = satproto_core::feed::filter_replies(&posts, post_id, post_author);
                all_posts.extend(replies);
            }
            Err(_) => {}
        }
    }

    all_posts.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    serde_wasm_bindgen::to_value(&all_posts).map_err(|e| e.into())
}

/// Create a new post. Returns the new post as JSON.
#[wasm_bindgen]
pub async fn create_post(
    author_domain: &str,
    text: &str,
    reply_to: Option<String>,
    reply_to_author: Option<String>,
    repost_of: Option<String>,
    repost_of_author: Option<String>,
) -> Result<JsValue, JsValue> {
    let post = publish::create_and_publish_post(
        author_domain,
        text,
        reply_to,
        reply_to_author,
        repost_of,
        repost_of_author,
    )
    .await?;

    serde_wasm_bindgen::to_value(&post).map_err(|e| e.into())
}

/// Follow a user. Encrypts our content key for them and updates follows list.
#[wasm_bindgen]
pub async fn follow_user(my_domain: &str, target_domain: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    let github_token = storage
        .get_item("satproto_github_token")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub token")?;
    let github_repo = storage
        .get_item("satproto_github_repo")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub repo")?;

    // Fetch target's profile to get their public key
    let profile = fetch::fetch_profile(target_domain).await?;
    let target_pk_bytes = satproto_core::crypto::from_base64(&profile.public_key)
        .map_err(|e| JsValue::from_str(&format!("decode public key: {}", e)))?;
    let target_pk: [u8; 32] = target_pk_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid public key length"))?;

    // Get current epoch and content key
    let epoch = fetch::fetch_current_epoch(my_domain).await?;
    let content_key = get_content_key(&storage, epoch)?;

    // Encrypt our content key for the target user
    let sealed = satproto_core::crypto::seal_content_key(&content_key, &target_pk);
    let envelope = satproto_core::schema::KeyEnvelope {
        recipient: target_domain.to_string(),
        encrypted_key: satproto_core::crypto::to_base64(&sealed),
    };

    // Push key envelope
    let envelope_json = serde_json::to_string(&envelope)
        .map_err(|e| JsValue::from_str(&format!("serialize envelope: {}", e)))?;
    publish::push_text_file(
        &github_token,
        &github_repo,
        &format!("sat/epochs/{}/keys/{}.json", epoch, target_domain),
        &envelope_json,
    )
    .await?;

    // Update follows list
    let mut follow_list = fetch::fetch_follow_list(my_domain).await?;
    if !follow_list.follows.contains(&target_domain.to_string()) {
        follow_list.follows.push(target_domain.to_string());
    }
    let follows_json = serde_json::to_string(&follow_list)
        .map_err(|e| JsValue::from_str(&format!("serialize follows: {}", e)))?;
    publish::push_text_file(
        &github_token,
        &github_repo,
        "sat/follows/index.json",
        &follows_json,
    )
    .await?;

    web_sys::console::log_1(&format!("Followed {}", target_domain).into());
    Ok(())
}

/// Unfollow a user. Bumps epoch, generates new content key, re-creates
/// key envelopes for remaining followers only.
#[wasm_bindgen]
pub async fn unfollow_user(my_domain: &str, target_domain: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    let github_token = storage
        .get_item("satproto_github_token")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub token")?;
    let github_repo = storage
        .get_item("satproto_github_repo")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub repo")?;

    // Get current epoch
    let old_epoch = fetch::fetch_current_epoch(my_domain).await?;
    let new_epoch = old_epoch + 1;

    // Update follows list (remove target)
    let mut follow_list = fetch::fetch_follow_list(my_domain).await?;
    follow_list.follows.retain(|d| d != target_domain);
    let follows_json = serde_json::to_string(&follow_list)
        .map_err(|e| JsValue::from_str(&format!("serialize follows: {}", e)))?;

    // Generate new content key for new epoch
    let new_content_key = satproto_core::crypto::generate_content_key();
    storage
        .set_item(
            &format!("satproto_content_key_{}", new_epoch),
            &satproto_core::crypto::to_base64(&new_content_key),
        )
        .map_err(|_| "failed to store content key")?;

    // Create empty encrypted store for new epoch
    let store = satproto_core::db::PostStore::new();
    let encrypted = satproto_core::db::encrypt_store(&store, &new_content_key)
        .map_err(|e| JsValue::from_str(&format!("encrypt: {}", e)))?;

    // Push new epoch store
    publish::push_binary_file(
        &github_token,
        &github_repo,
        &format!("sat/epochs/{}/data.json.enc", new_epoch),
        &encrypted,
    )
    .await?;

    // Create key envelopes for remaining followers
    for follower_domain in &follow_list.follows {
        match fetch::fetch_profile(follower_domain).await {
            Ok(profile) => {
                let pk_bytes = match satproto_core::crypto::from_base64(&profile.public_key) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let pk: [u8; 32] = match pk_bytes.try_into() {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                let sealed = satproto_core::crypto::seal_content_key(&new_content_key, &pk);
                let envelope = satproto_core::schema::KeyEnvelope {
                    recipient: follower_domain.to_string(),
                    encrypted_key: satproto_core::crypto::to_base64(&sealed),
                };
                let envelope_json = serde_json::to_string(&envelope).unwrap_or_default();
                let _ = publish::push_text_file(
                    &github_token,
                    &github_repo,
                    &format!("sat/epochs/{}/keys/{}.json", new_epoch, follower_domain),
                    &envelope_json,
                )
                .await;
            }
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("Failed to fetch profile for {}: {:?}", follower_domain, e).into(),
                );
            }
        }
    }

    // Update epoch number and follows list
    publish::push_text_file(
        &github_token,
        &github_repo,
        "sat/current_epoch",
        &new_epoch.to_string(),
    )
    .await?;
    publish::push_text_file(
        &github_token,
        &github_repo,
        "sat/follows/index.json",
        &follows_json,
    )
    .await?;

    web_sys::console::log_1(&format!("Unfollowed {} — epoch bumped to {}", target_domain, new_epoch).into());
    Ok(())
}

/// Get follows list for display. Returns JSON array of domain strings.
#[wasm_bindgen]
pub async fn get_follows(my_domain: &str) -> Result<JsValue, JsValue> {
    let follow_list = fetch::fetch_follow_list(my_domain).await?;
    serde_wasm_bindgen::to_value(&follow_list.follows).map_err(|e| e.into())
}

/// Bootstrap a new Satellite site. Generates content key for epoch 0,
/// creates empty encrypted store, and pushes initial files to GitHub.
#[wasm_bindgen]
pub async fn bootstrap(domain: &str) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    let github_token = storage
        .get_item("satproto_github_token")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub token")?;
    let github_repo = storage
        .get_item("satproto_github_repo")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub repo")?;

    let pk_b64 = storage
        .get_item("satproto_public_key")
        .map_err(|_| "storage error")?
        .ok_or("no public key - call init() first")?;

    // Generate content key for epoch 0
    let content_key = satproto_core::crypto::generate_content_key();
    let content_key_b64 = satproto_core::crypto::to_base64(&content_key);
    storage
        .set_item("satproto_content_key_0", &content_key_b64)
        .map_err(|_| "failed to store content key")?;

    // Create empty encrypted store
    let store = satproto_core::db::PostStore::new();
    let encrypted = satproto_core::db::encrypt_store(&store, &content_key)
        .map_err(|e| JsValue::from_str(&format!("encrypt: {}", e)))?;

    // Push files to GitHub
    let files: Vec<(&str, String)> = vec![
        (
            ".well-known/satproto.json",
            serde_json::json!({
                "satproto_version": "0.1.0",
                "handle": domain,
                "display_name": domain,
                "bio": "",
                "public_key": pk_b64,
                "sat_root": "/sat/"
            })
            .to_string(),
        ),
        ("sat/current_epoch", "0".to_string()),
        (
            "sat/follows/index.json",
            serde_json::json!({ "follows": [] }).to_string(),
        ),
    ];

    for (path, content) in &files {
        publish::push_text_file(&github_token, &github_repo, path, content).await?;
    }

    // Push the encrypted store as binary
    publish::push_binary_file(
        &github_token,
        &github_repo,
        "sat/epochs/0/data.json.enc",
        &encrypted,
    )
    .await?;

    web_sys::console::log_1(&"Satellite site bootstrapped!".into());
    Ok(())
}

fn get_content_key(storage: &web_sys::Storage, epoch: u32) -> Result<[u8; 32], JsValue> {
    let b64 = storage
        .get_item(&format!("satproto_content_key_{}", epoch))
        .map_err(|_| "storage error")?
        .ok_or_else(|| JsValue::from_str(&format!("no content key for epoch {}", epoch)))?;
    let bytes = satproto_core::crypto::from_base64(&b64)
        .map_err(|e| JsValue::from_str(&format!("decode content key: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid content key length"))
}

fn get_keypair() -> Result<([u8; 32], [u8; 32]), JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    let sk_b64 = storage
        .get_item("satproto_secret_key")
        .map_err(|_| "storage error")?
        .ok_or("no secret key")?;
    let pk_b64 = storage
        .get_item("satproto_public_key")
        .map_err(|_| "storage error")?
        .ok_or("no public key")?;

    let sk_bytes = satproto_core::crypto::from_base64(&sk_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk_bytes = satproto_core::crypto::from_base64(&pk_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let sk: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid secret key length"))?;
    let pk: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid public key length"))?;

    Ok((sk, pk))
}
