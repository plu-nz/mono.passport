# MVP decisions for review

## Wails 3 and Go Migration

The desktop now uses Solid/Vite and Wails 3.0.0 with Go. The Native Messaging host has also been ported to Go and shares the core at `internal/`. The desktop uses Wails' default GTK4/WebKitGTK 6.0 backend. It replaced the GTK3/WebKit2GTK 4.1 backend used through `v0.2.1`, which was kept only so the release could build on Ubuntu 22.04. CI and releases now build on Ubuntu 24.04, so the published binary needs a distribution that ships WebKitGTK 6.0. The desktop UI follows the GTK theme instead of a palette of its own: Go reads the theme's named colors (`theme_bg_color`, `theme_selected_bg_color`, `borders`, and their libadwaita equivalents) and the interface font from GTK, and updates the UI when the theme, color scheme, or font changes. Passport's green palette remains only as a fallback when the theme does not provide those colors. The v1 protocol, configuration paths, extension ID, and executable names have been maintained. The UI uses explicit Go services, with no generic bridge to execute external commands.


## Rename from Passage to Passport

The product, binaries (`passport`, `passport-native-host`), application ID (`nz.plu.passport`), native messaging host (`com.plunz.passport`), configuration and data directories, packages, domain (`passport.plu.nz`) and repository (`plu-nz/mono.passport`) use the name Passport. The extension ID did not change, because it comes from the public key in `extension/identity.json`.

**Migration:** Passport and the installers move `~/.config/passage` and `~/.local/share/passage` (or their `XDG_*` equivalents) to the `passport` names when the new ones do not exist yet, keeping the vault selection, extension pairings, the unpacked extension and the extension signing key. The installers remove the old `passage` binaries, menu entry, icon and `com.plunz.passage` browser manifests. The extension must be reloaded once in each browser to talk to the new host name. The keyring service, recovery branch and default repository name were renamed without compatibility, because the GitHub onboarding had no users yet.

## Onboarding with GitHub and a master password

**Implemented:** with no vault, the desktop opens a wizard whose only inputs are a GitHub sign-in and a master password. Passport signs in through the OAuth device flow of the `plu-nz` "Passport" OAuth App (public client ID, no secret, scope `repo`) and stores the account in Secret Service, or in a `0600` file with a visible warning when no keyring exists. It generates the GPG key with the master password as passphrase (loopback pinentry, password through a pipe), runs `pass init` at `~/.password-store`, creates the private repository `passport-vault`, publishes `main`, and pushes the recovery copy: the armored secret key sealed with Argon2id (256 MiB, 3 passes, 4 lanes) and XChaCha20-Poly1305 under the same password, as the single commit of the orphan branch `passport-recovery`. Restore clones, opens the copy, checks it belongs to the vault, imports and unlocks the key. Both flows save their progress (never secrets) and resume after an interruption. `passport git-credential` answers Git for `https://github.com` from the stored token. Sync becomes automatic for these vaults; the manual flows move to **Settings → Advanced**. Details, spikes and acceptance criteria are in [the onboarding plan](simple-onboarding-plan.md).

**Reason:** a person who has never used GPG or Git cannot finish the manual setup, and losing the private key loses the vault. Carrying the sealed key in the repository gives the same model as Bitwarden: an encrypted vault on a server, opened with one password, on any computer with the account.

**This reverses two earlier choices**, recorded below as they were: that Passport never receives the GPG passphrase, and that the private key is never stored in Git. Both still hold for vaults set up through **Advanced**. For managed vaults, the security of the vault depends on the master password and on the GitHub account; see the [security review](security-review.md#onboarding-with-github-and-a-master-password).

This record separates what has already been implemented from choices that are still provisional. It can be changed after the first test with a sample vault.

## 1. Repository structure

The pnpm workspace lists `desktop/`, `extension/`, and `core/` explicitly at the repository root. `desktop/` contains the Wails/Go application and its Solid UI in `desktop/src/`; `extension/` contains the Chromium extension; `core/` remains the shared `@passport/core` TypeScript package. The Go module stays at the root, with the Native Messaging binary in `native-host/` and shared Go code in `internal/`. `web/`, `docs/`, and `scripts/` retain their existing roles.

Placing each application and package at the root removes the generic `src/` and `packages/` containers. Explicit workspace entries make package discovery independent of directory naming and keep paths in build scripts, CI, and documentation short. The `internal/` layout follows Go's shared-code convention; the desktop UI's own `src/` remains inside `desktop/`. This layout does not change the vault format or introduce an OpenPGP implementation.

## 2. Reading from vault in Linux

**Implemented:** the desktop allows you to choose an existing vault or create a new one with a private GPG key present in the system. It also offers to generate a key through GPG and initialize the vault in the same flow; the passphrase is collected by `pinentry`, outside of the Passport interface. The selection is at `XDG_CONFIG_HOME/passport/settings.json` (or `~/.config/passport/settings.json`); `PASSWORD_STORE_DIR` has priority, followed by selection and `~/.password-store`. Creation calls `pass init` and refuses to overwrite an initialized vault. The desktop lists the `.gpg` files without entering `.git` or following symbolic links and calls `pass show` to open an entry. The full content is only requested when the user selects the entry. The first line is treated as a password; the rest are in “Other fields”. The interface clears the displayed content after 30 seconds. The Go core interprets `login`/`username` and `url`; the UI creates and edits entries by `pass` and preserves the other lines. Update and removal require hashing of the previously read cipher file, but there is a race window with external changes between the check and the `pass` subprocess.

**Reason:** delegating decryption and vault rules to GNU `pass` and GPG preserves interoperability with the terminal and Android Password Store. No secrets are written by the application at this step.

**Important limit:** finding the directory does not mean the key is unlocked. `pass show` can request the password via `pinentry`, and `gpg-agent` can keep it in cache after the interface clears the text. The state `available` only means “vault present”, never “key unlocked”. The interface process can also keep sensitive data in memory until garbage collection; a short viewing session is not the equivalent of a guaranteed memory erase.

**Recovery:** The private key is not saved in Git or automatically exported by Passport. After generation, the interface shows the fingerprint and advises you to backup the key and passphrase. If the vault initialization fails after GPG creates the key, the key remains in the local keychain; the error tells you how to resume without generating another one.

**Key validity:** the generated key does not expire automatically. Without a renewal flow in the interface, an expiration date would stop the creation of new entries in `pass` without warning. This does not replace rotation when necessary; user can adjust the validity by GPG.

## 3. Browser connector

**Implemented prototype:** Native Messaging host with pairing by approved code on the desktop or terminal, token per installation linked to the vault directory, revocation via the interface or CLI and reading limited to the HTTPS origin associated with a `url` field of the entry. Changing vaults requires new pairing. The extension consults the host and fills in after the user's choice. GPG state is shared across the system. Direct integration tests passed. On Brave Origin and Chrome Stable disposable profiles, the actual popup paired, listed, and filled HTTPS forms with the original manifest; also refused completion after browsing the same tab to another URL. The matrix included common login, separate user and password steps, `autocomplete=off`, ambiguous fields, invisible password, registration with new password, iframe and page without login. The real GitHub login form passed in both browsers with dummy data, without submission. Stable Chrome was tested in a normal window with debugging protocol loading, as the `--load-extension` flag was removed. There is still a need to validate other sites and manually install them on already used profiles.

**Identity and Installation:** The manifest now includes a fixed public key and produces the ID `edmjpcolampgjbnmldchmnkinmhakjgm` on Brave Origin and Chrome Stable, regardless of the staging temp folder. The corresponding private key is outside the repository. The package includes the ID and validates that it matches the compiled public key; the installer automatically registers this ID in the Brave and Chrome manifests. Public installation of `v0.2.1` verified both manifests and installed extension without checkout. Running the installer twice preserved the pairing file and ID. The extension still needs to be manually loaded once in each browser, and each installation must be paired. Store publishing may require its own strategy to maintain the ID.

To complete, the extension will need to request access to the current tab's domain and only inject credentials after a user action. The protocol must associate the response with the tab and the origin that initiated the request; never send secrets to an arbitrary page or accept a domain provided by the page itself.

## Git sync on branch `main`

The desktop shows the status of the vault repository and offers pull/push when there is an upstream branch. `pull` requires clean tree, fetches changes and only accepts fast-forward updates. `push` fetches the remote before sending and refuses if it has advanced. **Record changes** creates commits only with `.gpg` and `.gpg-id`, rejects other files and requires OpenPGP packages encrypted in `.gpg`. Mismatch can be resolved by explicit action that keeps the local version of `.gpg` conflicting and saves the remote one as another encrypted entry, without merging ciphertext as text. Conflicts in `.gpg-id`, removals and renames require manual Git. Before merging, Passport stores both commits in `refs/passport/backup/`; an error aborts the merge. There is a window of concurrency if another process modifies the vault during fetch, merge, or push. The publish, clone, push, and pull cycle was validated with a temporary private repository on GitHub and dummy data.

### GitHub Authentication

The desktop uses the GitHub CLI (`gh`) for browser authentication. Passport only displays the active account, opens the CLI flow in the default terminal, and does not receive the token. For a vault that is already a Git repository, configure the `github.com` credential helper only on the local `.git/config`; does not alter remotes or create repositories. Token storage follows the behavior of `gh`, including its fallback to a local file when the keyring does not work. The integration does not replace authentication from SSH or other Git servers.

The desktop can launch Git in the vault directory and add `origin` when it doesn't exist. For an empty remote, **Publish New Vault** creates the first commit with `.gpg-id` and `.gpg`, rejects extra or already staged files in the index, and configures the upstream without `force`. If there is already a clean local commit, publish that commit; therefore, the content of commits created outside of Passport remains the responsibility of the user. A remote with history requires manual connection. Tests with disposable remotes cover initial publishing, plaintext file refusal, and divergence between clones. A temporary private repository on GitHub was also used to validate publish, clone, push, and pull with dummy files. Removing this repository requires scope `delete_repo`, which is missing from the current `gh` session.

**Clone Existing Vault** uses `git clone` for a non-existent directory, requires branch `main`, and validates `.gpg-id` before selecting it. The GPG private key does not come from Git and must be imported separately. A failure after the clone leaves the created directory for inspection without selecting the vault. Authentication uses the Git helpers already available in the system; integration with `gh` still depends on the local/global Git configuration used in the environment.

### Extension locking and TOTP

The host maintains a persistent `locked` state. The interface can block/allow extensions access; the host checks the status before and after reading. This does not block `pass` in the terminal or clear `gpg-agent`'s cache. There is a residual window for a request already in progress between the last check and the sending of the response; That's why the interface describes the control as blocking access to extensions, not as cryptographically blocking the vault.

The desktop reads URI `otpauth://totp/...` on its own line, as in `pass-otp`, and `otpauth: URI`. Generates code only in memory and validates algorithm, digits and period. The tests include the RFC 6238 vectors for SHA-1, SHA-256, and SHA-512. There is no TOTP generation by the extension at this stage.

## 4. Recommended next steps

1. Exercise reading and writing with disposable GPG vault, including `PASSWORD_STORE_DIR`, GPG failure and external change by the terminal.
2. Validate manual installation on already used Brave and Chrome profiles and more real websites.
3. Reduce the editing run window before recommending real data.
4. Monitor the use of release `v0.2.1` and repeat tests after changes to the host protocol or extension permissions.
5. Design biometrics and lock considering the GPG key and cache of the `gpg-agent`, before promising fingerprint unlocking on first access.

## 5. Decisions still open

- Store publishing channel and how to preserve the ID already fixed in the unzipped extension.
- How to authenticate localhost against the desktop and store authorizations per installation.
- URL and user metadata convention within `pass` entries.
- Concurrent editing policy and Git conflict resolution.
- Biometric unlock design that effectively protects the private key.
- Future web client without connector and eventual own Android app.

## 6. Installer's address

The public code is at `github.com/plu-nz/mono.passport`. The repository was first named `plu-nz/passage`, then `plu-nz/mono.passage` to follow the organization's `type.name` convention (`mono`, because it holds the desktop app, extension, host, shared contracts, and website), and became `plu-nz/mono.passport` when the product was renamed from Passage to Passport. GitHub redirects the old addresses. Root `https://passport.plu.nz/` publishes `web/index.html`'s landing page through Cloudflare Worker `passport-landing`, associated with the subdomain as Worker Custom Domain. The Worker also answers `https://passport.plu.nz/install.sh` with an HTTP 302 redirect to `https://raw.githubusercontent.com/plu-nz/mono.passport/main/scripts/install.sh`. The former domain `passage.plu.nz` is served by Worker `passage-landing`, which now redirects every path to `passport.plu.nz` with HTTP 301; its older Single Redirect Rule for `/install.sh` still points at the first repository name, which GitHub redirects to the current script. The installer remains versioned in this repository; the shortcut does not host a second copy.

To rebuild the Worker, run `node web/build-worker.mjs`; the result is `web/dist/worker.js`. The deployment is manual: `wrangler deploy` of `web/dist/worker.js` as Worker `passport-landing` on the Plunz Cloudflare account, with `passport.plu.nz` as custom domain. Changes to the page require generating and republishing the Worker; a push to GitHub, by itself, does not update the site. Worker also implements the `/install.sh` redirect as a fallback in case the Cloudflare rule is removed.

The short command runs the script from the `main` branch. The script downloads the latest release x86_64 Linux package, checks its SHA-256, and installs without cloning or compiling the repository. The checksum file protects against corrupt transfer, but both come from the same release. Fixed releases and signing artifacts can be added before a stable release.
