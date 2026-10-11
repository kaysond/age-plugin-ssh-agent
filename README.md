# age-plugin-ssh-agent

An [age](https://age-encryption.org) plugin that derives keys from an ssh agent signature.

## How it works

The [SSH Agent Protocol](https://datatracker.ietf.org/doc/rfc9987/) does not have a "message"
to encrypt a blob. Though such functionality could be implemented via "Extensions", the most common
agents still have no such support. The plugin works around this limitation by using signatures
from Ed25519 keys. Ed25519 signatures, unlike other key types, are deterministic (i.e. the signature
is always the same for the same blob). During key generation, the plugin creates a random salt and
asks the agent to sign a blob containing a namespace string and the salt. (The salt prevents an
attacker with brief access to your agent from generating the same signature).The signature is then
run through HKDF-SHA256 expansion to get an X25519 secret key. Its public key is a normal X25519
public key just like age's native key type, so the plugin's "recipient" is a regular age recipient
and doesn't require anything special (even the plugin!) for encryption.

For additional security, the plugin also supports encrypting using the identity (as opposed to the 
X25519 public key recipient). When encrypting using the identity, the plugin will generate an
additional random salt per file, and request the agent sign the namespace, identity salt, and file
salt. This signature is then used as an AEAD key to wrap the file key. Because the agent is required
for encryption, this is only suitable for encrypting to oneself (e.g. for [sops](https://getsops.io/)).
The benefit is that without the per-file salt, an attacker who gains access to your agent and
identity file simultaneously can derive your secret key once and forever decrypt anything you've used
that key for - in the past or in the future! The additional salt requires the attacker to have access
to all three and doesn't enable them to decrypt other files.

## Installation

### From Release

Download the correct binary from the [Latest Release](https://github.com/kaysond/age-plugin-ssh-agent/releases),
and save it somewhere in your `PATH`.

### From Source

Requires a Rust toolchain with edition 2024 support (1.85+).

```sh
cargo install --path .
```

Make sure the binary is available on your `PATH`.

## Usage

The plugin will automatically connect to the ssh agent over the socket specified in `SSH_AUTH_SOCK`. Override the socket path with `--agent-socket <path>`.

List usable (Ed25519) ssh agent identities:

```sh
age-plugin-ssh-agent --list-identities
```

Generate an identity for one of them, by fingerprint or comment:
(Print the identity to stdout by omitting `-o`)

```sh
age-plugin-ssh-agent --key-gen --identity [SHA256:... | 'my comment'] -o /path/to/identity.txt
```

Decrypt a file (requires plugin and agent present):

```sh
age -d -i /path/to/identity.txt secret.age
```

Encrypt a file to the recipient (no plugin or agent needed):

```sh
age -r age1... -o secret.age secret.txt
```

Encrypt a file to the identity (enables per-file salting; requires plugin and agent present):

```sh
age -e -i key.txt -o secret.age secret.txt
```