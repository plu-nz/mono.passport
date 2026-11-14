# Plan: simple onboarding with GitHub and a master password

Goal: someone who has never heard of GPG or Git creates or restores a Passage vault with only two things: **Sign in with GitHub** and a **master password**. The vault stays a standard GNU `pass` store (`.gpg-id`, one `*.gpg` per entry, Git on `main`), readable by `pass`, browserpass and Android Password Store.

The current flows (choose directory, existing GPG key, any Git remote, `gh`, manual commit/pull/push) move to a collapsed **Advanced** section. They are not removed.

## 1. User journeys

### A. Create a vault (first run, no vault configured)

1. **Welcome**: two buttons, *Create my vault* and *I already have a vault*.
2. **GitHub**: Passage starts the OAuth device flow, shows the 8-character code with a *Copy code and open GitHub* button, and waits. On success it shows "Connected as @login". If the account already has a Passage vault repository, the screen offers to restore it instead.
3. **Master password**: password and confirmation, strength meter, *Suggest a passphrase* button (diceware), and a required checkbox: "I understand Passage cannot recover this password". The screen recommends enabling 2FA on GitHub.
4. **Progress**: a checklist that fills in as each step finishes: create key → create vault → create private repository → save encrypted recovery copy → sync.
5. **Done**: "Your vault is ready". Optional *Print emergency kit*, a page with the GitHub account, the repository URL and a blank line to write the password by hand. It contains no secrets.

### B. Restore on another computer

1. Welcome → *I already have a vault*.
2. GitHub sign-in. Passage lists the account's vault repositories and preselects the only one, if there is just one.
3. Master password.
4. Progress: clone → fetch recovery copy → unwrap → import key → mark trusted → unlock.
5. Done.

### C. Daily use

- **Unlock screen** when the key is not cached: master password typed in Passage. Passage unlocks gpg-agent for this key, so the desktop, the browser extension and `pass` in the terminal all work until the cache expires.
- **Lock** clears only this key's passphrase from gpg-agent. That is a real lock, unlike the current browser-only lock.
- **Invisible sync**:
  - fetch and fast-forward on start and on every list refresh;
  - push in the background after every save;
  - a status pill shows *Synced*, *Offline (will retry)* or *Needs attention*. *Needs attention* opens the existing "preserve both versions" flow.

### D. Account and maintenance (later phase)

- Change master password.
- Sign out of GitHub.
- Export the key for another `pass` app.
- Print the emergency kit again.

## 2. How it works

### 2.1 GitHub sign-in without `gh`: OAuth device flow

- Register an OAuth App named "Passage" under `plu-nz` with *Enable Device Flow* turned on. Device flow needs only the public `client_id`; there is no client secret.
- Flow:
  1. `POST https://github.com/login/device/code` with `client_id` and `scope=repo`. The response has `device_code`, `user_code`, `verification_uri`, `expires_in` (900 s) and `interval` (5 s).
  2. Poll `POST https://github.com/login/oauth/access_token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Handle `authorization_pending`, `slow_down` (+5 s), `expired_token` (offer a new code), `access_denied` and `device_flow_disabled`.
- OAuth App tokens do not expire by default. This is the same `repo` scope `gh` uses today, so the trust level does not change.
- API calls:
  - `GET /user`: login, id and name.
  - `GET /user/repos?affiliation=owner`: find vault repositories.
  - `POST /user/repos` with `{"name":"passage-vault","private":true}`.
- **Token storage**: Secret Service over D-Bus. `godbus` is already a dependency. The attributes are `service=nz.plu.passage` and `account=github.com/<login>`. If no Secret Service is available, fall back to a `0600` file in `XDG_CONFIG_HOME/passage/` and show a warning, the same behaviour as `gh`.
- **Git authentication**: the vault's local `.git/config` gets `credential.https://github.com.helper=!<abs path>/passage git-credential`.
  - `passage git-credential get` answers before Wails starts. It reads the token and prints `username=x-access-token` and `password=<token>`.
  - `pass git push` in a terminal works through the same helper.
  - The repository also gets local `user.name` and `user.email` from GitHub (`<id>+<login>@users.noreply.github.com`), which removes today's "configure user.email" failure.

### 2.2 The master password is the GPG passphrase

- **Key generation**: `gpg --batch --pinentry-mode loopback --passphrase-fd 3 --quick-generate-key "<name> <noreply email>" default default never`.
  - The password goes through an inherited pipe (`cmd.ExtraFiles`), never through argv, env or a file.
  - Byte slices are zeroed after use, best effort.
- **Vault**: `pass init <fingerprint>` creates it, as today. Encrypting entries needs only the public key, so no password is involved.
- **Unlock**: encrypt a random sentinel to the vault recipient in memory, then decrypt it with `--pinentry-mode loopback --passphrase-fd 3`. A success puts the passphrase in the gpg-agent cache; a wrong password returns `Bad passphrase`.
  - **Verified on GnuPG 2.4.9 in a disposable `GNUPGHOME`**: after the loopback decrypt, `--pinentry-mode error` decrypts from the cache, which is what `pass show` and the native host rely on.
- **Is it unlocked?**: `gpg-connect-agent "KEYINFO <keygrip>" /bye`. The cached flag is in the reply.
- **Lock**: `gpg-connect-agent "CLEAR_PASSPHRASE --mode=normal <keygrip>" /bye` for the encryption subkey's keygrip. This leaves other GPG keys (for example, Git signing keys) cached.
- Pinentry still works for terminal use after the cache expires. Nothing in `pass` changes.

### 2.3 Encrypted recovery copy in the repository

- **Content**: the output of `gpg --export-secret-keys --armor <fpr>` (loopback). It is already protected by GPG's S2K with the same password.
- **Second layer**: Passage wraps the export with **Argon2id + XChaCha20-Poly1305** (`golang.org/x/crypto`), keyed by the same master password. GPG's S2K is much cheaper to brute-force than Argon2. With this layer, an attacker who copies the repository faces a modern KDF, as with Bitwarden.
- **Format v1**: a JSON header and ciphertext.
  ```json
  {"v":1,"kdf":"argon2id","m":262144,"t":3,"p":4,"salt":"…","nonce":"…","fpr":"…","ct":"…"}
  ```
  - The canonical header without `ct` is the AEAD additional data.
  - When opening, parameters are bounded (for example, `m ≤ 1 GiB` and `t ≤ 10`) so a hostile file cannot exhaust memory.
  - Parameters are stored per file so they can be raised later.
- **Location**: an orphan branch `passage-recovery`, holding a single commit with one file `recovery-key`.
  - The branch is written with plumbing (`hash-object`, `mktree`, `commit-tree`) and `push --force origin <sha>:refs/heads/passage-recovery`, so the working tree is never touched.
  - Why not `main`:
    1. `main` keeps its invariant of only `.gpg` and `.gpg-id`, which the commit and publish validation already enforces.
    2. `pass`, browserpass and Android Password Store never see the file.
    3. Changing the password replaces the single commit, so the old blob is not kept in the branch history.
- **Restore**:
  1. `git fetch origin passage-recovery`, then `git show FETCH_HEAD:recovery-key`.
  2. Unwrap with Argon2id.
  3. `gpg --import` (loopback).
  4. `gpg --import-ownertrust` with `<fpr>:6:`.
  5. Unlock.

### 2.4 Automatic sync

| Trigger | Action |
|---|---|
| App start, list refresh | `fetch`, then fast-forward if the tree is clean. Divergence → *Needs attention*. |
| After create, update or remove | `pass` already commits. Passage pushes in the background, coalescing bursts. If the remote moved: fetch, fast-forward, push again. |
| Offline or auth error | Keep local commits, show *Offline*, retry on the next trigger. Auth error → *Sign in again*. |

The existing safety rules stay: `main` uses fast-forward only, there is no force on `main`, the "preserve both versions" merge remains, and `.gpg-id` conflicts are manual.

## 3. Code changes

| Area | Change |
|---|---|
| `internal/recovery` (new) | `Seal(password, armored) → blob` and `Open(password, blob) → armored`; versioned format; parameter bounds. |
| `internal/gpgkey` (new) | Generate, export, import, trust, unlock, lock and is-unlocked with loopback and fd-passed passwords; keygrip lookup. Some logic moves out of `internal/setup`. |
| `internal/ghauth` (new) | Device flow client (context-cancellable, interval and `slow_down` handling), small REST client, token store (Secret Service with file fallback). Replaces `internal/github` (`gh`), which stays only for Advanced. |
| `internal/gitvault` | `PublishRecovery(blob)`, `FetchRecovery()`, a background push queue, fetch-and-fast-forward helper, credential helper config pointing at Passage. |
| `internal/setup` | `CreateWithGitHub(password)` and `RestoreFromGitHub(repo, password)`. Both are resumable step machines; progress (fingerprint, repo, last step, never secrets) is saved in `settings.json`, so a retry continues instead of creating a second key or repository. |
| `desktop/main.go` | `passage git-credential <op>` subcommand, handled before the Wails app starts. |
| `desktop/service.go` + `service.ts` | `GitHubDeviceStart`, `GitHubDeviceWait` (cancellable), `GitHubAccount`, `GitHubSignOut`, `FindVaultRepos`, `CreateVaultWithGitHub`, `RestoreVaultFromGitHub`, `Unlock`, `Lock`, `KeyUnlocked`, `SyncStatus`; progress through Wails events. |
| `desktop/src` | `Onboarding` (full window, shown before the tabs when no vault is configured), `Unlock` screen, sync status pill, Settings reorganised into *Account*, *Security* (lock, change password, emergency kit) and a collapsed *Advanced* section (current Vault and Git cards). |
| `scripts/install.sh` | Check `pass`, `gpg` and `git` and print the distro install command when missing. `gh` is no longer needed. |
| Docs | `decisions.md` and `security-review.md`: record the reversal of "the private key is never in Git" and the new trust boundaries (section 4). |

The native host needs no change. It benefits from the agent cache filled by the in-app unlock, and the new Lock now covers it too.

## 4. Security model changes

The current documents say that Passage never receives the GPG passphrase and that private key backups never go into the repository. This plan changes both, on purpose:

1. **The encrypted private key lives in the vault repository.** Anyone who gets the repository (a GitHub account compromise, a leaked token, a GitHub insider) can attempt an offline attack on the master password. Mitigations:
   - Argon2id with 256 MiB of memory, on top of S2K;
   - a minimum password strength;
   - a 2FA recommendation at sign-in.

   This is the same model as Bitwarden's: an encrypted vault on a server, protected by a password.
2. **Passage handles the master password in memory** during create, restore, unlock and password change. Mitigations:
   - fd-passing only, never argv, env, files, logs or JS storage;
   - zeroing in Go (best effort; the WebView's JS strings cannot be zeroed).
3. **The OAuth token has the `repo` scope**: read and write on all of the user's repositories, the same as `gh`. It is stored in Secret Service. Sign-out deletes it locally and links to GitHub's *Authorized OAuth Apps* page to revoke it, because revoking through the API needs the client secret.
4. **Password change is not retroactive.** A recovery blob copied before the change still opens with the old password. A force-push also leaves the old object on GitHub until garbage collection. The documentation says so: if the old password leaked, rotate the GPG key, not just the password.
5. **Forgotten password = lost vault.** There is no recovery path, and the UI says so before creation.

Unchanged: entry names stay visible in the private repository, and commits on `main` stay limited to `.gpg` and `.gpg-id`.

## 5. Phases

| # | Phase | Contents | Estimate |
|---|---|---|---|
| 0 | Spikes | See section 6. Everything that can invalidate the design. | 1 day |
| 1 | Crypto core | `internal/recovery` and `internal/gpgkey`, with tests in a disposable `GNUPGHOME`. | 2–3 days |
| 2 | GitHub | `internal/ghauth` (device flow against an `httptest` server, REST, token store) and the `passage git-credential` subcommand. | 2–3 days |
| 3 | Git | Recovery branch, background push queue, fetch-and-fast-forward, sync status. | 2 days |
| 4 | Orchestration | Resumable create and restore, service methods, progress events. | 2 days |
| 5 | UI | Onboarding wizard, unlock screen, lock, sync pill, Settings reorganisation with Advanced. | 3 days |
| 6 | Account | Change password, sign out, emergency kit, export key for other apps. | 2 days |
| 7 | Release | Installer dependency check, docs, security review update, end-to-end test, release. | 1–2 days |

Each phase is one or more commits on `main`, following the repository's usual flow. Phases 1–3 do not change the UI and can ship without anyone noticing.

## 6. Spikes before implementation

| Spike | Question | Status |
|---|---|---|
| S1 | Does a loopback decrypt fill the gpg-agent cache for later non-interactive use? | **Confirmed** on GnuPG 2.4.9 |
| S2 | Do `--export-secret-keys` and `--import` of a protected secret key work non-interactively with loopback and `--passphrase-fd`? | **Confirmed**, with two catches. A failed export still writes a partial armour header (247 bytes), so success must be judged by the exit code (`2` on a bad passphrase), never by the output. `--import` does **not** check the passphrase and does not fill the cache, so restore must verify the password with the Argon2id unwrap first and unlock after the import. |
| S3 | Do `CLEAR_PASSPHRASE --mode=normal <keygrip>` and `KEYINFO` clear and report only this key? | **Confirmed**. The decrypting key is the `ssb` with capability `e`; its `KEYINFO` line has `1` in the seventh field while cached and `-` after `CLEAR_PASSPHRASE`. A later decrypt needs pinentry again. |
| S4 | Real OAuth App: device flow, `POST /user/repos`, then clone and push through the `passage git-credential` helper. | **Confirmed** with the `plu-nz` OAuth App:<br>• device code → approval in the browser → token with `scope=repo`;<br>• token stored in Secret Service (`go-keyring`);<br>• `GET /user`;<br>• `POST /user/repos` created a private repository;<br>• commit with the noreply identity, then push and clone, all authenticated only by a `!<exe> git-credential` helper in the local config. |
| S5 | Argon2id timing and memory at 256 MiB / t=3 / p=4 on a modest laptop. Target about 1 s. | **Confirmed**: 0.48 s on a Ryzen 5 PRO 3500U (64 MiB: 0.10 s; 128 MiB: 0.27 s). Keep 256 MiB / t=3 / p=4. |
| S6 | Secret Service availability (Omarchy, GNOME, KDE, a bare window manager) and the fallback path. | **Omarchy**: `org.freedesktop.secrets` is provided by `gnome-keyring-daemon`. Other desktops are still to check; the fallback remains necessary. |
| S7 | Changing the passphrase non-interactively (`--passwd` with loopback), or a fallback via pinentry. | **Confirmed**: `--pinentry-mode loopback --command-fd 0 --passwd` reads the old and then the new passphrase from stdin and re-protects the primary key and the subkeys; a wrong old passphrase reports `GPG_ERR_BAD_PASSPHRASE`. Re-importing a key whose passphrase changed elsewhere keeps the old protection, so the local secret key must be deleted before the import (ownertrust survives). |

## 7. Acceptance

- In a disposable HOME, with a test GitHub account and a throwaway repository, *Create my vault* asks only for GitHub approval and a password. It ends with a private repository holding `main` (`.gpg-id`) and `passage-recovery` (`recovery-key`), and nothing else.
- In a second disposable HOME, *I already have a vault* with the same account and password opens the entries. A wrong password fails clearly and changes nothing.
- An entry saved on machine A appears on machine B after a refresh, with no clicks.
- Interop: `git clone` of the repository, plus the exported key, plus `pass show` in a terminal, reads the same entries. `pass insert` in a terminal is pushed by the helper.
- After the in-app unlock, the browser extension fills without a pinentry prompt. After Lock it cannot until the next unlock.
- No password or token appears in argv (`/proc/*/cmdline`), environment, logs, `settings.json` or the repository's `main`.
- The existing Advanced flows still work: an existing key, any Git remote, `gh`.

## 8. Open decisions

| # | Decision | Recommendation |
|---|---|---|
| D1 | OAuth App (`repo` scope) or GitHub App (fine-grained, but needs an installation step and has 8-hour tokens with refresh) | **OAuth App** now; reconsider a GitHub App as hardening later. |
| D2 | Recovery copy on an orphan branch or in `.passage/` on `main` | **Orphan branch** (section 2.3). |
| D3 | Unlock in the app (loopback) or always through pinentry | **In the app**; pinentry remains for the terminal. |
| D4 | Minimum password strength | **zxcvbn score ≥ 3 and ≥ 12 characters**, with the diceware suggestion one click away. |
| D5 | No Secret Service available | **Fallback to a `0600` file with a warning**, like `gh`. |
| D6 | Auto-lock | Use gpg-agent's cache TTL; add a Passage *Lock after N minutes* setting that calls Lock. |
| D7 | Repository name | `passage-vault`; on a clash, ask for another name. |
| D8 | Who registers the OAuth App | **Done**: OAuth App "Passage" under `plu-nz`, device flow enabled, no client secret. Client ID `Ov23liE8ep7OS2M8Hfsy` (public; it goes into the code). |
