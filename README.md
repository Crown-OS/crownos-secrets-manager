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
| `crates/secrets-core` | | Secret names and kinds, bindings, rules, use outcomes, the streaming scrubber |
| `crates/secrets-vault` | | The encrypted vault file with values and rules, lock and unlock |
| `crates/secrets-protocol` | | The crownos-ipc contract and the pipe that carries a value to the daemon |
| `crates/secrets-proxy` | | The HTTPS proxy that adds API keys to requests and scrubs the responses |
| `crates/secrets-run` | | Runs a registered template in bubblewrap and scrubs its output |
| `crates/daemon` | `crownos-secretsd` | The daemon: one per session, as the `crownos-secretsd` user service |
| `crates/cli` | `crownos-secrets` | The CLI for you |
| `crates/mcp` | `crownos-secrets-mcp` | The stdio MCP server for agents |

## Use

Start the daemon:

```sh
systemctl --user enable --now crownos-secretsd
```

Make the vault, then add a secret. Each command that changes the vault asks for the master
password. The CLI reads the password and the value at a hidden prompt. They do not go into the
arguments or into your shell history.

```sh
crownos-secrets init                         # makes the vault and unlocks it
crownos-secrets add github_token --kind token
crownos-secrets bind github_token \
    --agent /usr/bin/crownos-secrets-mcp \
    --origin 'https://*.github.com' \
    --confirm session:15 \
    --http-host api.github.com --http-header Authorization --http-format 'Bearer {value}' \
    --http-method GET --http-path '/repos/*'
crownos-secrets template-set gh-prs --env GH_TOKEN=github_token --host api.github.com \
    --cwd-glob "$HOME/code/*" -- gh pr list
crownos-secrets configure --lock-after-minutes 30 --uses-per-minute 10
crownos-secrets list
crownos-secrets templates
crownos-secrets status                       # lock state and the requests from agents
crownos-secrets lock
crownos-secrets unlock
crownos-secrets remove github_token
crownos-secrets audit --follow               # the audit trail from the journal
```

Secret and template names have 1 to 64 characters from `a-z`, `0-9`, `_`, `.` and `-`. The kinds
are `password`, `api-key`, `token`, `env` and `note`. A value can have up to 32 KiB.

Give an agent the MCP server:

```sh
claude mcp add crownos-secrets -- crownos-secrets-mcp
```

The agent gets these tools:

| Tool | What it does |
| --- | --- |
| `secrets_list` | Names, kinds and rules of the secrets |
| `secrets_templates` | The registered command templates |
| `secrets_status` | Lock state and the agent's own open requests |
| `secrets_request` | Asks you to add a secret that the agent needs |
| `secrets_run` | Runs a registered template in a sandbox with secrets in its environment (S3) |
| `secrets_http_session` | Adds API keys to HTTPS requests through a local proxy (S2) |
| `secrets_type` | Types a secret into a window (S4; now it answers "not available yet") |
| `secrets_fill_login` | Fills a login form (S4; not available yet) |

There is no `get` tool. Each tool description tells the model that no value comes back. The
tool names use `_`, not `.`, because some clients and model APIs do not accept a dot in a tool
name.

## The rules

The rules are sealed in the vault next to the values:

- for each secret: its kind and its binding (`agents`, `targets`, `require_password_field`,
  `confirm`, `http`)
- the run templates
- the settings: `lock_after_minutes`, `default_confirm` and the rate limits

The daemon reads them only from the unlocked vault. Only an admin call with the master password
can change them, so a program that writes files cannot give itself access. While the vault is
locked, `list` and `templates` answer "locked".

The default binding allows nothing. An agent can use a secret only when `agents` names it.

Not all rules apply yet:

- `confirm`, `targets` and `require_password_field` apply from S4 (typing through the
  compositor). `run` and `proxy_session` use a secret without a confirmation on screen, also when
  `confirm` is `EveryUse`.
- `uses_per_minute` counts calls (`run`, `proxy_session` and the others), not the requests that
  go through one proxy session.

## Who may call what

The daemon finds the caller from the peer credentials of the socket. It reads
`/proc/<pid>/exe` of the peer while the pidfd shows that the process that connected still runs.
This names the program that the peer runs now. It does not stop a process that connects and then
runs `exec`, or that gives its socket to another process. The executable path is the key for
`agents`.

| Calls | Who may call |
| --- | --- |
| `status`, `request` | Any process of your user. `status` shows only the caller's own requests; an admin sees all |
| `list`, `templates` | Any process of your user, while the vault is unlocked |
| `type_into`, `fill_login`, `run`, `proxy_session` | Agents that the binding of each secret names |
| `init`, `unlock`, `add`, `remove`, `bind`, `set_template`, `configure` | Admin executables, with the master password |
| `lock` | Admin executables |

The admin executables are `/usr/bin/crownos-secrets` and `/usr/bin/crownos-settings`. They are
compiled in. A debug build also accepts the paths in `CROWNOS_SECRETS_DEBUG_ADMIN_EXECUTABLES`,
separated by `:`. The executable check is the second layer; the master password is the first.
The daemon checks the executable before it reads the password pipe, and the password before it
reads the value pipe.

Each decision writes one line to the `crownos::audit::secrets` tracing target. A line has the
caller, the secret names, the target and the outcome. It never has a value. Caller text (window
names, `purpose`) loses its control characters and is cut to a fixed length before it goes into
a line or an event. Subscribers get a `Used` event for each refused use. After the first
rate-limit refusal of a caller, further refusals write no line and send no event until a call is
allowed again. A caller can have at most 4 open requests, and all callers together 64.

## The vault

The vault is `$XDG_DATA_HOME/crownos/secrets.vault`, mode 0600. Each write sets mode 0700 on its
directory.

```text
header, 57 bytes, also the AEAD associated data:
  "CRSV" | version 1 | Argon2id memory KiB, iterations, parallelism (u32 LE) | salt[16] | nonce[24]
body: XChaCha20-Poly1305 over (rules length u32 | rules | records), then the 16-byte tag
rules: postcard encoding of SecretRules
record: kind u8 (0 secret, 1 internal) | name length u8 | name | value length u32 LE | value
```

- Argon2id derives the 32-byte key from the master password. The default cost is 64 MiB and
  3 passes. The header keeps the parameters, so a later release can raise them. The daemon refuses
  parameters above 256 MiB, 8 passes or 8 lanes.
- One seal covers the whole body. The vault is small, and each change writes the full file
  atomically. A single seal also hides the names and the number of secrets. An attacker cannot
  remove, reorder or roll back one record alone.
- Each write uses a new random nonce. The write goes to a temporary file with mode 0600, then
  `fsync`, `rename` and `fsync` of the directory.
- The daemon opens the file with `O_NOFOLLOW` and `O_NONBLOCK`. It refuses a file that is not a
  regular file, is larger than 64 MiB, belongs to another user, or that the group or other users
  can read or write.
- `unlock` never makes a vault. `init` does, and it refuses when a file is there.
- A wrong password and a changed salt, nonce, body or tag give the same error.
- In memory, values and the key are in `secrecy::SecretBox` types. These types zero the memory
  when they are dropped. `lock`, and the end of the unlock time, drop them. A new
  `lock_after_minutes` counts from the next unlock.

### Whole-file rollback

The seal stops changes to single records, but not a swap of the whole file. A program of your
user can keep a copy of an old vault and put it back later. The old file opens with the old
master password. Because the rules are in the vault, the old file also brings back old bindings:
an agent access that you removed is there again. Keep this in mind when you remove access after an
incident. Change the master password (planned) or remove the secret at its provider too.

## The HTTPS proxy (S2)

`secrets_http_session` (the `proxy_session` call) gives an agent a proxy for the secrets that it
names. Each secret must allow the agent and must have an `http` binding. The answer has:

- `proxy_url`: `http://crownos:<token>@127.0.0.1:<port>`. The token is 32 random bytes. Put the
  URL in `HTTPS_PROXY`.
- `ca_path`: `$XDG_DATA_HOME/crownos/secrets-ca.pem`, the certificate of the local CA. Trust it for
  this client only (`curl --cacert`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`).
  Do not add it to the system store.
- `placeholders`: `crown-secret://<name>` for each secret.
- `expires_in_seconds`: the session ends after `ttl_minutes`, at most 60.

The proxy works like this:

1. It accepts only `CONNECT`, with the session token in `Proxy-Authorization`. A wrong or old
   token gets 407. A host that no `http` binding of the session names gets 403.
2. It ends TLS with a certificate for the host from the local CA, and opens TLS to the real host.
   It checks the real host against the system CA store.
3. For each request, it adds the bound header (for example `Authorization: Bearer <value>`) only
   when the host, the method and the path match the binding. It replaces a placeholder in any
   request header with the value, but only for a secret that is bound to this request; another
   placeholder gets 403.
4. It asks for `Accept-Encoding: identity`, and refuses a compressed response, because the
   scrubber cannot read compressed bytes.
5. It scrubs the response headers and, as it streams, the response body. It drops trailers.
6. It writes an audit line for each request with the secret names, the host, the method, the path
   and the status. It never writes a value.

The CA key is made at the first session. It lives only in the vault (as an internal record) and in
memory. Only the certificate goes to disk. When the vault locks, the daemon stops the proxy: the
sessions, their values and the CA key go from memory. `revoke_session` ends one session early.

Limits: the request body goes to the host unchanged, so a placeholder in a body is not replaced.
A value that the host echoes in an encoding that the scrubber does not know reaches the agent (see
[The scrubber](#the-scrubber)). HTTP/2 is not offered; clients fall back to HTTP/1.1.

## Run templates (S3)

`secrets_run` (the `run` call) starts a template that the user registered with
`crownos-secrets template-set`. A template has a command, the environment variables that it gets
from secrets (at least one), the hosts it needs, a `cwd_glob`, and limits. The daemon refuses:

- a template that does not exist (`Unknown`), or a caller that a secret's binding does not name
  (`Denied`)
- extra arguments, unless `allow_arguments` is set
- a working directory that does not match `cwd_glob`. The check uses the canonical path, so `..`
  and symbolic links cannot leave the pattern. Without a `cwd_glob`, the command runs in an empty
  `/tmp` and the caller gives no directory.
- any run when `/usr/bin/bwrap` is not installed (`SandboxMissing`)

The sandbox is bubblewrap with:

- new pid, ipc, uts and cgroup namespaces, `--die-with-parent` and `--new-session`
- a read-only `/usr` and `/etc`, a new `/proc`, `/dev` and `/tmp`, and nothing of your home
  except the working directory (read-only unless `cwd_writable`)
- no network when the template names no hosts (`--unshare-net`). When it names hosts, the command
  shares the full network of the daemon: the host list is not an allow list yet. A template with
  hosts and `allow_arguments` lets the caller send a value to any host, so register such a
  template only for a command that you trust with the caller's arguments.
- an empty environment except `PATH`, `HOME=/tmp`, `LANG` and the template variables
- `/usr/bin/sh` in the sandbox (it puts `/dev/null` on standard input)

bwrap reads its options, with the values, from a pipe on its standard input (`--args 0`), so no
value shows in `/proc/<pid>/cmdline`. A pipe, not an inherited file, keeps the values of one run
away from a command of another run. A shell in the sandbox gives the command `/dev/null` as its
standard input; the command and the arguments stay separate words, not shell text. The command
itself gets the values in its environment, so a process of your user can read them from
`/proc/<pid>/environ` while it runs.

stdout and stderr go through a scrubber with every value in the vault, as they stream. A run stops
at `timeout_seconds` (at most 600) and at `max_output_bytes` (at most 512 KiB), and the reply
says so. The scrubbed text in the reply is cut to 640 KiB of stdout and 128 KiB of stderr, so it
fits one IPC frame. While a run goes on, the daemon answers no other request, and the vault does
not lock on time until the run ends.

The sandboxed command is in the cgroup of the daemon, so `MemoryMax=384M` and `MemorySwapMax=0`
also apply to it. A command that uses too much memory can make the kernel stop the daemon too.

## Hardening

- The daemon sets `PR_SET_DUMPABLE=0` at start. There is no core dump. A process of your user
  cannot attach with ptrace or read `/proc/<pid>/mem` of the daemon. The CLI does the same only
  while it reads the master password or a value. Then it is dumpable again, because the daemon
  must read `/proc/<pid>/exe` of the CLI, and the kernel refuses that for a non-dumpable process.
  Until the request goes out, the pipe read ends are open in the CLI, and a process of your user
  can read them through `/proc/<pid>/fd`. A later caller identity from `SO_PEERPIDFD` has the same
  limit if it also reads `/proc/<pid>/exe`.
- The daemon locks the pages of the key and of each value with `mlock`. It never unlocks them:
  `mlock` works on full pages, and a page can hold other data too. When `RLIMIT_MEMLOCK` stops a
  lock, the daemon logs this one time.
- The user unit sets `LimitCORE=0`, `MemorySwapMax=0`, `MemoryMax=384M`, `NoNewPrivileges=yes`,
  `UMask=0077`, `LockPersonality=yes`, `SystemCallArchitectures=native` and limits on address
  families (Unix, IP for the proxy, netlink for bwrap), namespaces (only those that bwrap makes)
  and system calls (`@system-service @mount`). `MemoryDenyWriteExecute=` stays off, because
  sandboxed commands get it too and JIT runtimes need it off.
- The unit does not use `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=` or `ReadWritePaths=`. In a
  user unit, each of these puts the daemon in a new user namespace. Reading `/proc/<pid>/exe` of a
  caller is a ptrace-read check, and the kernel refuses it across user namespaces. Also, your user
  owns that namespace, so any of your processes outside it could attach to the daemon in spite of
  `PR_SET_DUMPABLE=0`.
- A value goes from the CLI to the daemon through a pipe. The CLI writes the value and closes the
  pipe, then sends the read end with the message. Thus the value does not go into the message
  buffers of crownos-ipc, which are not zeroed. The master password uses the same path.

## Threat model

The secrets manager stops these:

- A model reads a value through a CrownOS tool. No tool and no method returns a value.
- A value goes into a log, an audit line, an event or an error message. Tests plant a value and
  search all of these for it, and for its base64 and hex forms.
- An agent uses a secret that its binding does not allow.
- A program of your user changes the rules by a file edit. The rules are sealed.
- An agent sends too many uses or requests. Rate limits and request caps apply to each caller.
- A copy of the vault file is read on another computer. Without the master password it is
  ciphertext.
- A change to the vault file. The AEAD tag finds it.

The secrets manager does not stop these:

- Code that runs as your user and searches on purpose. Examples: it reads `/proc/<pid>/environ`
  of a sandboxed command child (S3), or it reads a filled field back. The Playwright MCP server
  from crownos-setup can read `input.value`.
- A program that knows the master password, for example from a key logger.
- A whole-file rollback (see above).
- Root, the kernel, or a person at the unlocked computer.
- Values on disk in a hibernation image.

Use the Claude Code sandbox with `failIfUnavailable` to make an agent shell less powerful.

### Known limits

- All MCP agents connect through `crownos-secrets-mcp`, so they have one identity. A binding cannot
  tell two agents apart until crownos-ipc gives a pidfd from `SO_PEERPIDFD` and crownos-config an
  `AppKey`. The `IdentifyCaller` trait in `crates/daemon/src/identity.rs` is the one place that
  changes then.
- The daemon keeps `last_used` in memory only.
- Open requests do not expire. Because all MCP agents share one identity, four open requests
  block `request` for every agent until the user answers them with `add`.
- The sandbox tests skip when bwrap is missing, but fail where unprivileged user namespaces are
  off.
- `rpassword` reads the prompt into a `String` that can grow. A grown buffer is not zeroed.
- TODO: seal the vault key with `systemd-creds --user` (and TPM2 when present), so the vault can
  unlock at login without a typed master password.
- TODO: change the master password.

## The scrubber

`secrets_core::Scrubber` replaces a value in a stream with `[secret:<name>]`. It also replaces
these forms of the value:

- base64, standard and URL-safe, at the 3 byte alignments, also when the encoder wraps lines with
  LF or CRLF (MIME wraps at 76 columns)
- hex, lower case and upper case
- percent encoding with the safe sets of RFC 3986, JavaScript `encodeURIComponent`, Python
  `quote` and the WHATWG form encoder, with both hex cases, with and without `+` for a space
- JSON string escapes in each combination of `\/`, ASCII-only `\uXXXX`, the HTML-safe form and
  upper-case or lower-case hex

It keeps the last `longest match - 1` bytes of a chunk, so a value that crosses two chunks is
found. Property tests plant a value in random data, encode the full stream, cut it into random
chunks and show that the value never comes through. Encoded forms shorter than 4 bytes are not
used, so a short secret does not remove normal text.

The scrubber is a second protection. The first protection is that no tool returns a value. It does
not find these:

- UTF-16 and other text encodings, rot13, reversed text, characters with separators between them,
  base32, base85, compression, encryption
- double encoding, for example base64 of hex, or percent encoding of base64
- a part of a value, or a value that overlaps a second secret in a way that the first match hides
- a label as an equality oracle: a program can print a guess and see whether the output shows
  `[secret:<name>]`, so it can test guesses. Rate limits slow this; they do not stop it.

## Plan

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

The sibling checkout `../crownos-ipc` must be next to this repository.

## License

MIT OR Apache-2.0
