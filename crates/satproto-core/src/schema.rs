use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub satproto_version: String,
    pub handle: String,
    pub display_name: String,
    pub bio: String,
    pub public_key: String, // base64-encoded X25519 public key
    pub sat_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowList {
    pub follows: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub id: String,
    pub author: String,
    pub created_at: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repost_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repost_of_author: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub recipient: String,      // domain of the recipient
    pub encrypted_key: String,  // base64-encoded sealed box
}
