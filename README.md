# sAT Protocol Specification v0.1.0

sAT Protocol (satproto) is a decentralized social networking protocol based on static sites.
Each user owns a static website storing all their data in encrypted JSON stores.
A WASM client running in the browser aggregates feeds and publishes posts.
It does not rely on any servers or relays.

See [Setup](#setup) to deploy a sample implementation using GitHub Pages.

## Identity

A user's identity is their domain name.
Identity is authenticated by HTTPS/TLS - fetching content from a domain proves
the domain owner published it.

## Discovery

A satproto-enabled site exposes a discovery document at:

```
GET https://{domain}/.well-known/satproto.json
```

```json
{
  "satproto_version": "0.1.0",
  "handle": "alice.com",
  "display_name": "Alice",
  "bio": "Hello world",
  "public_key": "<base64-encoded X25519 public key>",
  "sat_root": "/sat/"
}
```

## Encryption Model

All user data is stored in an encrypted JSON store. 
Only users in the owner's follow list can decrypt it.

### Keys

- Each user generates an **X25519 keypair**. 
  The public key is published in the discovery document. 
  The private key is stored in the browser's localStorage.
- Each epoch has a random **content key** (256-bit symmetric key) used to
  encrypt the data store with XChaCha20-Poly1305.
- The content key is encrypted per-follower using libsodium sealed boxes
  (`crypto_box_seal` with the follower's X25519 public key).

### Epochs

An epoch is a period between follow list changes. Each epoch has its own
content key.

```
sat/
  current_epoch        # plain text file containing the current epoch number
  epochs/
    0/
      data.json.enc      # Encrypted data store with epoch 0's content key
      keys/
        bob.example.com.json    # epoch 0 content key encrypted for Bob
        carol.example.com.json  # epoch 0 content key encrypted for Carol
    1/
      data.json.enc      # Encrypted data store with epoch 1's content key
      keys/
        bob.example.com.json    # Carol unfollowed — no key for her
```

When the user unfollows someone:
1. Increment epoch number
2. Generate new content key
3. New posts go into the new epoch's database
4. Encrypt the new content key for all remaining followers
5. The unfollowed user retains access to old epoch data but cannot read new content

### Decryption Flow

When Bob visits Alice's site:
1. Fetch Alice's `/.well-known/satproto.json` to get her public key and sat_root
2. Fetch `sat/current_epoch` to find the latest epoch
3. For each epoch, fetch `sat/epochs/{n}/keys/bob.example.com.json`
4. Decrypt the content key using Bob's private key
5. Fetch `sat/epochs/{n}/data.json.enc`
6. Decrypt the file using the content key

## Data Schema

Each epoch's encrypted store contains a JSON array of post objects:

```json
[
  {
    "id": "20260309T141500Z-a1b2",
    "author": "alice.com",
    "created_at": "2026-03-09T14:15:00Z",
    "text": "Hello, decentralized world!",
    "reply_to": null,
    "reply_to_author": null,
    "repost_of": null,
    "repost_of_author": null
  }
]
```

Post IDs are `{ISO8601-compact-UTC}-{4-hex-random}`, e.g. `20260309T141500Z-a1b2`.
The timestamp prefix gives natural sort order; the random suffix prevents collisions.

### Reposts

A repost is a post with `repost_of` and `repost_of_author` set. The `text`
field may be empty (pure repost) or contain commentary (quote repost).

When a client encounters a repost, it fetches and decrypts the original post
from the original author's site. This means:
- The original content is always authenticated by the original author's TLS
  and encryption — reposters cannot forge content.
- If the original author deletes or edits the post, the repost reflects that.
- If the viewer doesn't have access to the original author's data (the original
  author doesn't follow them), they see the repost attribution without content.

## Follow List

The follow list is stored as a plain JSON file (unencrypted, since the key
envelopes already reveal follows):

```
GET https://{domain}/sat/follows/index.json
```

```json
{
  "follows": ["bob.example.com", "carol.example.com"]
}
```

## Feed Aggregation

The WASM client builds a feed by:
1. Reading the user's follow list
2. For each followed user, fetching their discovery document
3. For each followed user, decrypting their database (using the key envelope
   the followed user published for this user)
4. Merging all posts, sorted by `created_at` descending

## Replies

A reply is a post with `reply_to` and `reply_to_author` set. Replies are
aggregated the same way as regular posts. A user only sees replies from people
they follow — this is the spam prevention mechanism.

When viewing a post, the client scans followed users' posts for entries where
`reply_to` matches the post ID and `reply_to_author` matches the post's author.

## Publishing

The WASM client publishes posts by:
1. Creating a new post record
2. Adding it to the current epoch's post database
3. Re-encrypting the database with the current epoch's content key
4. Pushing the updated `data.json.enc` via the GitHub Contents API
   (or equivalent for other git hosts)

The GitHub personal access token is stored in localStorage alongside the
private key.

## Static Site Structure

```
{domain}/
  .well-known/
    satproto.json           # Discovery + profile + public key
  sat/
    current_epoch           # Current epoch number (plain text)
    follows/
      index.json            # Follow list (unencrypted)
    epochs/
      {n}/
        data.json.enc         # Encrypted JSON data store
        keys/
          {domain}.json     # Encrypted content key per follower
  app/
    index.html              # WASM client shell
    satproto_bg.wasm        # Compiled WASM module
    satproto.js             # wasm-bindgen glue
    style.css               # Minimal styling
```

## Setup

Below are steps to set up a sample implementation of satproto using GitHub.
The protocol itself is agnostic to how the site is hosted,
 and there is plan to support other hosts in the future.

### Prerequisites

- [Rust](https://rustup.rs/)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- A GitHub repo with [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site) enabled (e.g. `username/username.github.io`)
- A GitHub [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) with `Contents: Read and write` permission on your repo

### Build

```bash
git clone https://github.com/user/satproto.git
cd satproto
wasm-pack build crates/satproto-wasm --target web --out-dir ../../site-template/app/pkg
```

### Deploy

Copy the client files to your GitHub Pages repo:

```bash
cp -r site-template/.well-known site-template/app /path/to/your-github-pages-repo/
cd /path/to/your-github-pages-repo
git add .well-known app
git commit -m "Add Satellite client"
git push
```

### First run

1. Visit `https://yourdomain/app/`
2. The WASM client generates your X25519 keypair automatically
3. Enter your domain, GitHub repo (`owner/repo`), and token
4. Click **Save & Initialize** — this pushes your profile, follow list, and empty encrypted store to your repo
5. Start posting!

### Following someone

Enter their domain in the follow input and click **Follow**. This:
- Fetches their public key from their `/.well-known/satproto.json`
- Encrypts your content key for them (so they can read your posts)
- Updates your follow list

After GitHub Pages propagates (~1 min), refresh to see their posts in your feed.

### Running tests

```bash
cargo test -p satproto-core
```