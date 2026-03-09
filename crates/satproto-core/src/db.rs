use crate::crypto;
use crate::schema::Post;

/// An in-memory post store backed by a Vec, serialized as JSON.
#[derive(Default)]
pub struct PostStore {
    pub posts: Vec<Post>,
}

impl PostStore {
    pub fn new() -> Self {
        Self { posts: Vec::new() }
    }

    /// Deserialize a store from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let posts: Vec<Post> = serde_json::from_slice(bytes)?;
        Ok(Self { posts })
    }

    /// Serialize the store to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(&self.posts).map_err(StoreError::from)
    }

    /// Insert a post.
    pub fn insert(&mut self, post: Post) {
        self.posts.push(post);
    }

    /// Get all posts, sorted by created_at descending.
    pub fn get_all_posts(&self) -> Vec<Post> {
        let mut posts = self.posts.clone();
        posts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        posts
    }

    /// Get replies to a specific post.
    pub fn get_replies(&self, post_id: &str, post_author: &str) -> Vec<Post> {
        let mut replies: Vec<Post> = self
            .posts
            .iter()
            .filter(|p| {
                p.reply_to.as_deref() == Some(post_id)
                    && p.reply_to_author.as_deref() == Some(post_author)
            })
            .cloned()
            .collect();
        replies.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        replies
    }
}

/// Encrypt a post store with a content key. Returns nonce || ciphertext.
pub fn encrypt_store(store: &PostStore, content_key: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
    let bytes = store.to_bytes()?;
    crypto::encrypt_data(&bytes, content_key).map_err(|e| StoreError::Crypto(e.to_string()))
}

/// Decrypt an encrypted post store. Input: nonce || ciphertext.
pub fn decrypt_store(encrypted: &[u8], content_key: &[u8; 32]) -> Result<PostStore, StoreError> {
    let bytes =
        crypto::decrypt_data(encrypted, content_key).map_err(|e| StoreError::Crypto(e.to_string()))?;
    PostStore::from_bytes(&bytes)
}

#[derive(Debug)]
pub enum StoreError {
    Json(serde_json::Error),
    Crypto(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Json(e) => write!(f, "json: {}", e),
            StoreError::Crypto(e) => write!(f, "crypto: {}", e),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_content_key;

    fn sample_post() -> Post {
        Post {
            id: "20260309T141500Z-a1b2".to_string(),
            author: "alice.example.com".to_string(),
            created_at: "2026-03-09T14:15:00Z".to_string(),
            text: "Hello Satellite!".to_string(),
            reply_to: None,
            reply_to_author: None,
            repost_of: None,
            repost_of_author: None,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let mut store = PostStore::new();
        store.insert(sample_post());
        let posts = store.get_all_posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].text, "Hello Satellite!");
    }

    #[test]
    fn test_serialize_roundtrip() {
        let mut store = PostStore::new();
        store.insert(sample_post());
        let bytes = store.to_bytes().unwrap();
        let store2 = PostStore::from_bytes(&bytes).unwrap();
        assert_eq!(store2.posts.len(), 1);
        assert_eq!(store2.posts[0].id, "20260309T141500Z-a1b2");
    }

    #[test]
    fn test_encrypt_decrypt_store() {
        let mut store = PostStore::new();
        store.insert(sample_post());

        let key = generate_content_key();
        let encrypted = encrypt_store(&store, &key).unwrap();
        let store2 = decrypt_store(&encrypted, &key).unwrap();
        let posts = store2.get_all_posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].id, "20260309T141500Z-a1b2");
    }

    #[test]
    fn test_get_replies() {
        let mut store = PostStore::new();
        store.insert(sample_post());
        store.insert(Post {
            id: "20260309T150000Z-c3d4".to_string(),
            author: "bob.example.com".to_string(),
            created_at: "2026-03-09T15:00:00Z".to_string(),
            text: "Welcome!".to_string(),
            reply_to: Some("20260309T141500Z-a1b2".to_string()),
            reply_to_author: Some("alice.example.com".to_string()),
            repost_of: None,
            repost_of_author: None,
        });

        let replies = store.get_replies("20260309T141500Z-a1b2", "alice.example.com");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].author, "bob.example.com");
    }
}
