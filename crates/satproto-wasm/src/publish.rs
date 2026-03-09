use gloo_net::http::Request;
use satproto_core::crypto;
use satproto_core::post_id;
use satproto_core::schema::{Post, PostIndex};
use wasm_bindgen::JsValue;

use crate::fetch;

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
        .ok_or("no GitHub token")?;
    let github_repo = storage
        .get_item("satproto_github_repo")
        .map_err(|_| "storage error")?
        .ok_or("no GitHub repo")?;

    // Generate post ID from current time
    let now = js_sys::Date::new_0();
    let iso = now.to_iso_string().as_string().ok_or("date error")?;
    let compact = post_id::compact_timestamp(&iso);
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

    // Get content key from localStorage
    let content_key_b64 = storage
        .get_item("satproto_content_key")
        .map_err(|_| "storage error")?
        .ok_or("no content key")?;
    let content_key_bytes = crypto::from_base64(&content_key_b64)
        .map_err(|e| JsValue::from_str(&format!("decode content key: {}", e)))?;
    let content_key: [u8; 32] = content_key_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("invalid content key length"))?;

    // Encrypt the post
    let post_json = serde_json::to_vec(&post)
        .map_err(|e| JsValue::from_str(&format!("serialize post: {}", e)))?;
    let encrypted = crypto::encrypt_data(&post_json, &content_key)
        .map_err(|e| JsValue::from_str(&format!("encrypt post: {}", e)))?;

    // Push encrypted post file
    push_binary_file(
        &github_token,
        &github_repo,
        &format!("sat/posts/{}.json.enc", id),
        &encrypted,
    )
    .await?;

    // Update post index (prepend new ID)
    let mut index = fetch::fetch_post_index(author_domain)
        .await
        .unwrap_or(PostIndex { posts: Vec::new() });
    index.posts.insert(0, id);
    let index_json = serde_json::to_string(&index)
        .map_err(|e| JsValue::from_str(&format!("serialize index: {}", e)))?;
    push_text_file(
        &github_token,
        &github_repo,
        "sat/posts/index.json",
        &index_json,
    )
    .await?;

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
    push_encoded_file(token, repo, path, &encoded, &format!("update: {}", path)).await
}

/// Push a binary file to a GitHub repo via Contents API.
pub async fn push_binary_file(
    token: &str,
    repo: &str,
    path: &str,
    data: &[u8],
) -> Result<(), JsValue> {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
    push_encoded_file(token, repo, path, &encoded, &format!("update: {}", path)).await
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
pub async fn get_file_sha(token: &str, repo: &str, path: &str) -> Result<Option<String>, JsValue> {
    let url = format!("https://api.github.com/repos/{}/contents/{}", repo, path);
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
