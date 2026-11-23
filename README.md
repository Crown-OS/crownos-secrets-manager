# crownos-secrets-manager

The CrownOS secrets manager keeps your passwords, API keys and tokens. AI agents use a secret by
its name. They do not get its value.

Agents are Claude Code (through MCP), the suja assistant and computer-use agents. An agent asks
the daemon to use the secret `github_token`. The daemon does the work. No method and no tool
returns a value to a caller.

## The promise

**A secret value never enters a model's context through CrownOS tools.**

This is not a promise that a secret is unreadable by same-user code. The daemon runs as your
user. A program that runs as your user and searches on purpose can find a value. See
[Threat model](#threat-model).

## Crates

| Crate | Binary | What it is |
| --- | --- | --- |
| `crates/secrets-core` | | Secret names and kinds, bindings, use outcomes, the `secrets.ron` schema, the streaming scrubber |
| `crates/secrets-vault` | | The encrypted vault file, lock and unlock |
| `crates/secrets-protocol` | | The crownos-ipc contract and the pipe that carries a value to the daemon |
| `crates/daemon` | `crownos-secretsd` | The daemon: one per session, as the `crownos-secretsd` user service |
| `crates/cli` | `crownos-secrets` | The CLI for you |
| `crates/mcp` | `crownos-secrets-mcp` | The stdio MCP server for agents |

## Use

Start the daemon:

```sh
systemctl --user enable --now crownos-secretsd
```

Make the vault and add a secret. The CLI asks for the value at a hidden prompt. The value does not
go into the arguments or into your shell history.

```sh
crownos-secrets unlock                       # the first time, this makes the vault
crownos-secrets add github_token --kind token
crownos-secrets bind github_token \
    --agent /usr/bin/crownos-secrets-mcp \
    --origin 'https://*.github.com' \
    --confirm session:15 \
    --http-host api.github.com --http-header Authorization --http-format 'Bearer {value}'
crownos-secrets list
crownos-secrets status                       # lock state and the requests from agents
crownos-secrets lock
crownos-secrets remove github_token
crownos-secrets audit --follow               # the audit trail from the journal
```

Secret names have 1 to 64 characters from `a-z`, `0-9`, `_`, `.` and `-`. The kinds are
`password`, `api-key`, `token`, `env` and `note`. A value can have up to 32 KiB.

Give an agent the MCP server:

```sh
claude mcp add crownos-secrets -- crownos-secrets-mcp
```

The agent gets these tools:

| Tool | What it does |
| --- | --- |
| `secrets_list` | Names, kinds and rules of the secrets |
| `secrets_status` | Lock state and the open requests |
| `secrets_request` | Asks you to add a secret that the agent needs |
| `secrets_type` | Types a secret into a window (S4; now it answers "not available yet") |
| `secrets_fill_login` | Fills a login form (S4; not available yet) |
| `secrets_run` | Runs a registered command with secrets in its environment (S3; not available yet) |
| `secrets_http_session` | Adds API keys to HTTPS requests through a proxy (S2; not available yet) |

There is no `get` tool. Each tool description tells the model that no value comes back. The
tool names use `_`, not `.`, because the Anthropic API refuses a tool name with a dot.

## The rules file

`~/.config/crownos/secrets.ron` holds names and rules. It never holds a value. The daemon reads
it again for each call, so a change applies at once.

```ron
(
    unlock: (lock_after_minutes: 15),
    default_confirm: EveryUse,
    rate_limit: (uses_per_minute: 6, requests_per_hour: 10),
    admin_executables: ["/usr/bin/crownos-secrets", "/usr/bin/crownos-settings"],
    secrets: {
        "github_token": (
            kind: Token,
            binding: (
                agents: ["/usr/bin/crownos-secrets-mcp"],
                targets: [AppId("org.mozilla.*"), Origin("https://*.github.com")],
                require_password_field: false,
                confirm: Some(PerSession(15)),
                http: [(host: "api.github.com", header: "Authorization", format: "Bearer {value}")],
            ),
        ),
    },
    run_templates: {
        "gh-pr-list": (
            command: ["gh", "pr", "list"],
            environment: {"GH_TOKEN": "github_token"},
            network: ["api.github.com"],
        ),
    },
)
```

The default binding allows nothing. An agent can use a secret only when `agents` names it.

## Who may call what

The daemon finds the caller from the peer credentials of the socket. It reads
`/proc/<pid>/exe` of the peer while the pidfd shows that the same process still runs. The
executable path is the key for `agents` and `admin_executables`.

| Calls | Who may call |
| --- | --- |
| `status`, `list`, `request` | Any process of your user |
| `type_into`, `fill_login`, `run`, `proxy_session` | Agents that the binding of each secret names |
| `add`, `remove`, `bind`, `lock`, `unlock` | Only `admin_executables` |

`add`, `remove` and `bind` also need an unlocked vault. Each decision writes one line to the
`crownos::audit::secrets` tracing target. A line has the caller, the secret names, the target
and the outcome. It never has a value. Subscribers also get a `Used` event for each refused use.

In S1, the use calls do all the checks (rate limit, known name, binding, lock, stored value).
When all checks pass, they answer `UNAVAILABLE` (error code 100).

## The vault

The vault is `$XDG_DATA_HOME/crownos/secrets.vault`, mode 0600, in a directory with mode 0700.

```text
header, 57 bytes, also the AEAD associated data:
  "CRSV" | version 1 | Argon2id memory KiB, iterations, parallelism (u32 LE) | salt[16] | nonce[24]
body: XChaCha20-Poly1305 over all records, then the 16-byte tag
record: name length u8 | name | value length u32 LE | value
```

- Argon2id derives the 32-byte key from the master password. The default cost is 64 MiB and
  3 passes. The header keeps the parameters, so a later release can raise them. The daemon refuses
  parameters above 1 GiB, 16 passes or 8 lanes.
- One seal covers the whole body. The vault is small, and each change writes the full file
  atomically. A single seal also hides the names and the number of secrets in the file. An
  attacker cannot remove, reorder or roll back one record alone.
- Each write uses a new random nonce. The write goes to a temporary file with mode 0600, then
  `fsync`, `rename` and `fsync` of the directory.
- The vault does not open when the group or other users can read or write it, or when another
  user owns it.
- A wrong password and a changed salt, nonce, body or tag give the same error.
- In memory, values and the key are in `secrecy::SecretBox` types. These types zero the memory
  when they are dropped. `lock`, and the end of the unlock time, drop them.

## Hardening

- The daemon sets `PR_SET_DUMPABLE=0` at start. There is no core dump. A process of your user
  cannot attach with ptrace or read `/proc/<pid>/mem` of the daemon.
- The daemon locks the pages of the key and of each value with `mlock`. It never unlocks them:
  `mlock` works on full pages, and a page can hold other data too. When `RLIMIT_MEMLOCK` stops a
  lock, the daemon logs this one time.
- The user unit sets `LimitCORE=0`, `MemorySwapMax=0`, `NoNewPrivileges=yes`, `UMask=0077`,
  `RestrictAddressFamilies=AF_UNIX`, `RestrictNamespaces=yes`, `LockPersonality=yes`,
  `MemoryDenyWriteExecute=yes` and `SystemCallFilter=@system-service`.
- The unit does not use `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=` or `ReadWritePaths=`. In a
  user unit, each of these puts the daemon in its own user namespace. The kernel then refuses to
  let the daemon read `/proc/<pid>/exe` of a caller, and each caller becomes unidentified.
- A value goes from the CLI to the daemon through a pipe. The CLI writes the value and closes the
  pipe, then sends the read end with the message. Thus the value does not go into the message
  buffers of crownos-ipc, which are not zeroed. The master password uses the same path.

## Threat model

The secrets manager stops these:

- A model reads a value through a CrownOS tool. No tool and no method returns a value.
- A value goes into a log, an audit line, an event or an error message. Tests plant a value and
  search all of these for it, and for its base64 and hex forms.
- An agent uses a secret that its binding does not allow.
- An agent sends too many uses or requests. Rate limits apply to each caller.
- A copy of the vault file is read on another computer. Without the master password it is
  ciphertext.
- A changed vault file. The AEAD tag finds the change.

The secrets manager does not stop these:

- Code that runs as your user and searches on purpose. Examples: it reads the memory of a command
  child through `/proc/<pid>/environ` (S3), or it reads a filled field back. The Playwright MCP
  server from crownos-setup can read `input.value`.
- An agent with a shell. It can run `crownos-secrets bind` itself, or edit `secrets.ron`, because
  the admin check uses the executable path only. `add`, `remove` and `bind` need an unlocked vault,
  and the CLI reads the master password only from a terminal. This makes the attack harder, but it
  does not stop it.
- Root, the kernel, or a person at the unlocked computer.
- Values on disk in a hibernation image.

Use the Claude Code sandbox with `failIfUnavailable` to make an agent shell less powerful.

### Known limits of S1

- All MCP agents connect through `crownos-secrets-mcp`, so they have one identity. A binding cannot
  tell two agents apart until crownos-ipc gives a pidfd from `SO_PEERPIDFD` and crownos-config an
  `AppKey`. The `IdentifyCaller` trait in `crates/daemon/src/identity.rs` is the one place that
  changes then.
- `last_used` stays empty, because S1 does not use a secret yet. The daemon keeps it in memory
  only.
- `rpassword` reads the prompt into a `String` that can grow. A grown buffer is not zeroed.
- TODO: seal the vault key with `systemd-creds --user` (and TPM2 when present), so the vault can
  unlock at login without a typed master password.

## The scrubber

`secrets_core::Scrubber` replaces a value in a stream with `[secret:<name>]`. It also replaces
these forms of the value:

- base64, standard and URL-safe, at the 3 byte alignments
- hex, lower case and upper case
- percent encoding (RFC 3986 with both hex cases, and form encoding)
- JSON string escapes (the default form, `\/`, ASCII-only `\uXXXX`, and the HTML-safe form)

It keeps the last `longest pattern - 1` bytes of a chunk, so a value that crosses two chunks is
found. Property tests plant a value in random data, encode the full stream, cut it into random
chunks and show that the value never comes through. Encoded forms shorter than 4 bytes are not
used, so a short secret does not remove normal text. The scrubber is a second protection. The
first protection is that no tool returns a value. S3 runs command output through it.

## Plan

- **S2: HTTPS key proxy.** `proxy_session` starts a local HTTPS proxy in the daemon (hyper,
  rustls, a local CA from rcgen). The proxy adds the header from the `http` binding only for the
  bound host. It scrubs the response. The agent never has the key.
- **S3: sandboxed run templates.** `run` starts a registered template in bubblewrap with its own
  pid namespace. The environment comes from the vault, the network from the allow list. The
  scrubber cleans the output.
- **S4: typing through the compositor.** A new `crownos_secret_input_v1` protocol in
  crownos-protocols, which only `crownos-secretsd` can bind. The compositor shows a confirmation
  that names the agent, the secret, the window and the origin, and ignores synthetic input on it.
  It checks the focused surface and the `text_input_v3` password purpose, marks the window
  sensitive, and types the value. Terminals are refused; use `run` for them.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The sibling checkouts `../crownos-config` and `../crownos-ipc` must be next to this repository.

## License

MIT OR Apache-2.0
