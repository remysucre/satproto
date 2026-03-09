use crate::schema::Post;

/// Merge posts from multiple sources and sort by created_at descending.
pub fn merge_feeds(feeds: Vec<Vec<Post>>) -> Vec<Post> {
    let mut all: Vec<Post> = feeds.into_iter().flatten().collect();
    all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    all
}

/// Filter posts that are replies to a specific post.
pub fn filter_replies(posts: &[Post], post_id: &str, post_author: &str) -> Vec<Post> {
    posts
        .iter()
        .filter(|p| {
            p.reply_to.as_deref() == Some(post_id)
                && p.reply_to_author.as_deref() == Some(post_author)
        })
        .cloned()
        .collect()
}

/// Filter posts that are top-level (not replies, not reposts).
pub fn filter_top_level(posts: &[Post]) -> Vec<Post> {
    posts
        .iter()
        .filter(|p| p.reply_to.is_none())
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_post(id: &str, author: &str, time: &str, text: &str) -> Post {
        Post {
            id: id.to_string(),
            author: author.to_string(),
            created_at: time.to_string(),
            text: text.to_string(),
            reply_to: None,
            reply_to_author: None,
            repost_of: None,
            repost_of_author: None,
        }
    }

    #[test]
    fn test_merge_feeds_sorted() {
        let feed1 = vec![
            make_post("1", "alice", "2026-03-09T14:00:00Z", "first"),
            make_post("3", "alice", "2026-03-09T16:00:00Z", "third"),
        ];
        let feed2 = vec![make_post("2", "bob", "2026-03-09T15:00:00Z", "second")];

        let merged = merge_feeds(vec![feed1, feed2]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].id, "3");
        assert_eq!(merged[1].id, "2");
        assert_eq!(merged[2].id, "1");
    }

    #[test]
    fn test_filter_replies() {
        let posts = vec![
            make_post("1", "alice", "2026-03-09T14:00:00Z", "hello"),
            Post {
                id: "2".to_string(),
                author: "bob".to_string(),
                created_at: "2026-03-09T15:00:00Z".to_string(),
                text: "reply!".to_string(),
                reply_to: Some("1".to_string()),
                reply_to_author: Some("alice".to_string()),
                repost_of: None,
                repost_of_author: None,
            },
            make_post("3", "carol", "2026-03-09T16:00:00Z", "unrelated"),
        ];

        let replies = filter_replies(&posts, "1", "alice");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].id, "2");
    }
}
