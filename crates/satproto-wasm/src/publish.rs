use gloo_net::http::Request;
use satproto_core::crypto;
use satproto_core::db::{self, PostStore};
use satproto_core::post_id;
use satproto_core::schema::Post;
use wasm_bindgen::JsValue;

/// Create a new post and publish it to the user's GitHub repository.
pub async fn create_and_publish_post(
    author_domain: &str,
    text: &str,
    reply_to: Option<String>,
    reply_to_author: Option<String>,
    repost_of: Option<String>,
    repost_of_author: Option<String>,
) -> Result<Post, JsValue> {
    let window = web_sys::window().ok_or("no window")?;
    let storage = window
        .local_storage()
        .map_err(|_| "no localStorage")?
        .ok_or("no localStorage")?;

    let github_token = storage
        .get_item("satproto_github_token")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub token - set satproto_github_token in localStorage")?;
    let github_repo = storage
        .get_item("satproto_github_repo")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub repo - set satproto_github_repo in localStorage")?;

    // Generate post ID from current time
    let now = js_sys::Date::new_0();
    let iso = now.to_iso_string().as_string().ok_or("date error")?;
    let compact = post_id::compact_timestamp(&iso);
    // Trim milliseconds: "20260309T141500.000Z" -> "20260309T141500Z"
    let compact = compact.split('.').next().unwrap_or(&compact).to_string() + "Z";
    let id = post_id::generate_post_id(&compact);

    let post = Post {
        id: id.clone(),
        author: author_domain.to_string(),
        created_at: iso,
        text: text.to_string(),
        reply_to,
        reply_to_author,
        repost_of,
        repost_of_author,
    };

    // Fetch current epoch
    let epoch_url = format!("https://{}/sat/current_epoch", author_domain);
    let epoch_resp = Request::get(&epoch_url)
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("fetch epoch: {}", e)))?;
    let epoch_text = epoch_resp
        .text()
        .await
        .map_err(|e| JsValue::from_str(&format!("read epoch: {}", e)))?;
    let epoch: u32 = epoch_text
        .trim()
        .parse()
        .map_err(|e| JsValue::from_str(&format!("parse epoch: {}", e)))?;

    // Get content key from localStorage
    let content_key_b64 = storage
        .get_item(&format!("satproto_content_key_{}", epoch))
        .map_err(|_| "storage error")?
        .ok_or("no content key for current epoch")?;
    let content_key_bytes = crypto::from_base64(&content_key_b64)
        .map_err(|e| JsValue::from_str(&format!("decode content key: {}", e)))?;
    let content_key: [u8; 32] = content_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid content key length"))?;

    // Try to fetch existing store, or create new one
    let store_url = format!(
        "https://{}/sat/epochs/{}/data.json.enc",
        author_domain, epoch
    );
    let mut store = match Request::get(&store_url).send().await {
        Ok(resp) if resp.ok() => {
            let encrypted = resp
                .binary()
                .await
                .map_err(|e| JsValue::from_str(&format!("read store: {}", e)))?;
            db::decrypt_store(&encrypted, &content_key)
                .map_err(|e| JsValue::from_str(&format!("decrypt store: {}", e)))?
        }
        _ => PostStore::new(),
    };

    store.insert(post.clone());

    let encrypted = db::encrypt_store(&store, &content_key)
        .map_err(|e| JsValue::from_str(&format!("encrypt store: {}", e)))?;

    // Push via GitHub Contents API
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);
    let path = format!("sat/epochs/{}/data.json.enc", epoch);

    // Get current file SHA if it exists (needed for updates)
    let sha = get_file_sha(&github_token, &github_repo, &path).await?;

    let mut body = serde_json::json!({
        "message": format!("post: {}", id),
        "content": encoded,
    });
    if let Some(sha) = sha {
        body["sha"] = serde_json::Value::String(sha);
    }

    let api_url = format!(
        "https://api.github.com/repos/{}/contents/{}",
        github_repo, path
    );
    let resp = Request::put(&api_url)
        .header("Authorization", &format!("Bearer {}", github_token))
        .header("Accept", "application/vnd.github+json")
        .json(&body)
        .map_err(|e| JsValue::from_str(&format!("json body: {}", e)))?
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("push: {}", e)))?;

    if !resp.ok() {
        let text = resp.text().await.unwrap_or_default();
        return Err(JsValue::from_str(&format!("GitHub API error: {}", text)));
    }

    Ok(post)
}

/// Push a text file to a GitHub repo via Contents API.
pub async fn push_text_file(
    token: &str,
    repo: &str,
    path: &str,
    content: &str,
) -> Result<(), JsValue> {
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        content.as_bytes(),
    );
    push_encoded_file(token, repo, path, &encoded, &format!("init: {}", path)).await
}

/// Push a binary file to a GitHub repo via Contents API.
pub async fn push_binary_file(
    token: &str,
    repo: &str,
    path: &str,
    data: &[u8],
) -> Result<(), JsValue> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
    push_encoded_file(token, repo, path, &encoded, &format!("init: {}", path)).await
}

/// Push a base64-encoded file to GitHub.
async fn push_encoded_file(
    token: &str,
    repo: &str,
    path: &str,
    encoded_content: &str,
    message: &str,
) -> Result<(), JsValue> {
    let sha = get_file_sha(token, repo, path).await?;

    let mut body = serde_json::json!({
        "message": message,
        "content": encoded_content,
    });
    if let Some(sha) = sha {
        body["sha"] = serde_json::Value::String(sha);
    }

    let api_url = format!("https://api.github.com/repos/{}/contents/{}", repo, path);
    let resp = Request::put(&api_url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .json(&body)
        .map_err(|e| JsValue::from_str(&format!("json body: {}", e)))?
        .send()
        .await
        .map_err(|e| JsValue::from_str(&format!("push: {}", e)))?;

    if !resp.ok() {
        let text = resp.text().await.unwrap_or_default();
        return Err(JsValue::from_str(&format!(
            "GitHub API error for {}: {}",
            path, text
        )));
    }

    Ok(())
}

/// Get the SHA of an existing file in the repo (needed for updates).
async fn get_file_sha(
    token: &str,
    repo: &str,
    path: &str,
) -> Result<Option<String>, JsValue> {
    let url = format!(
        "https://api.github.com/repos/{}/contents/{}",
        repo, path
    );
    let resp = Request::get(&url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await;

    match resp {
        Ok(r) if r.ok() => {
            let json: serde_json::Value = r
                .json()
                .await
                .map_err(|e| JsValue::from_str(&format!("parse sha: {}", e)))?;
            Ok(json.get("sha").and_then(|s| s.as_str()).map(String::from))
        }
        _ => Ok(None),
    }
}
