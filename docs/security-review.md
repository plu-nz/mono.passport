# Prototype Security Review

## Wails 3/Solid/Go Migration

The Go core calls GNU `pass`, GPG, Git, and `gh` as processes with separate arguments. The host maintains the v1 protocol and still reads the JSON state created by the earlier Rust host, preserving tokens tied to the vault. Go tests cover read/write with disposable GPG vault, concurrent edit hash, symlinks, TOTP RFC 6238, legacy pairing state and Git publish flow, divergence, and preservation of two encrypted versions. The host's Python test and actual completion in Brave and Chrome passed again with the Go host and disposable profiles. The frontend is built into the Wails binary; no remote sites are loaded in the WebView.

The desktop exposes JavaScript-specific Go methods, mapped to `desktop/src/service.ts`. The UI clears the displayed secrets after 30 seconds, as before. The Linux backend uses GTK4/WebKitGTK 6.0. After the switch from GTK3/WebKit2GTK 4.1, the cycle was repeated on 2026-11-12 before `v0.3.0`: Go tests with a disposable GPG vault, the host's Python test, and the browser matrix (all local scenarios plus `githubLive`) in Brave Origin and stable Chrome, all with the expected outcome. The desktop follows the GTK theme and allows a single running instance; both were checked by hand on GTK 4.24.1 and WebKitGTK 2.54.1. Wails version `v3.0.0` is fixed to `go.mod`.


Review carried out with code and disposable vault. On temporary profiles on Brave Origin and stable Chrome, the actual popup paired, listed entries, and filled username and password on a local HTTPS page and on the actual GitHub login, without submitting the form. The test repeated the click after browsing the tab and confirmed that the filling was rejected. No personal profiles or real credentials were used.

## Onboarding with GitHub and a master password

The wizard changes the trust boundaries for vaults Passport creates or restores (see [decisions](decisions.md#onboarding-with-github-and-a-master-password)).

**What protects the vault:** the master password, and the GitHub account that holds the repository. Anyone who obtains the repository (an account takeover, a leaked token, the host) can run an offline guess against the recovery copy. Each guess costs one Argon2id derivation with 256 MiB of memory, about half a second on a laptop, before the GPG S2K layer. Passport requires at least 12 characters and a zxcvbn score of 3, suggests a six-word EFF passphrase (about 77 bits), and recommends two-factor authentication on GitHub.

**Verified controls:**
- The master password reaches gpg only through an inherited pipe (`--passphrase-fd 3`, or stdin for `--command-fd` when changing it), never through argv, the environment or a file. Passwords with line breaks are refused, because `--passphrase-fd` would truncate them at the first one.
- Wrong passwords are detected from `GPG_ERR_BAD_PASSPHRASE` status lines, independent of the locale. Unlock clears the key's cache first, so a cached passphrase cannot make a wrong password pass; export verifies the password the same way before writing the key.
- The recovery header (version, costs, salt, nonce, fingerprint) is authenticated; costs outside fixed bounds are refused before any derivation, so a hostile file cannot exhaust memory. Restore refuses a copy whose key is not a recipient of the vault, and import refuses a key whose fingerprint differs from the expected one or that has no secret part.
- Lock clears only the vault key's encryption keygrips in gpg-agent, which now also stops the browser connector and `pass` until the next unlock.
- The GitHub token never reaches the WebView. The device code stays in Go; the UI receives only the user code. The credential helper answers only `https`/`github.com` requests, and the repository's helper list is reset before Passport's is added.
- `main` keeps its rules (only `.gpg` and `.gpg-id`, fast-forward or explicit merge, no force). Only `passport-recovery` is force-pushed, by an explicit refspec.
- Changing the password undoes itself when the new recovery copy cannot be uploaded, so the local key and the copy never disagree.
- Go tests exercise all of this with disposable GnuPG homes, a fake GitHub API and local bare remotes: create on one computer, restore on another, a wrong password then a resumed restore, a password change followed on the second computer, an offline change that is undone, and export.

**Known limitations:**
- The OAuth scope `repo` grants access to every repository of the account, as `gh` does. A GitHub App limited to the vault repository would be narrower but needs an installation step.
- Passport holds the master password in memory during create, restore, unlock and password change. Go buffers are cleared after use; JavaScript strings in the WebView cannot be.
- A password change is not retroactive. A recovery copy fetched before the change still opens with the old password, and GitHub may keep the replaced commit until garbage collection. Other computers keep the old protection on their local key until the new password is typed there. If the old password leaked, rotate the key rather than only the password.
- A forgotten master password cannot be recovered.

## Verified controls

- The host requires pairing per installation, binds the token to the vault and extension origin, and only accepts HTTPS URLs that match the `url` field of the entry.
- Revocation and persistent blocking prevent new orders; the host rechecks authorization after reading the secret. Integration tests cover two isolated installations, similar domain, revocation, and blocking while reading.
- The extension obtains the origin of the tab via the browser's API, links the list to the tab and the URL, checks both again before filling in and only injects it after the user clicks. Passwords are not saved on `browser.storage.local`; There is only the pairing token.
- Git refuses dirty tree and divergence before synchronizing. An explicit action preserves both conflict-encrypted versions of `.gpg`, with backup refs to the original commits. Conflicts in `.gpg-id` are rejected and aborted without changing the HEAD. New commits are limited to `.gpg-id` and `.gpg`; `.gpg` files must contain encrypted OpenPGP packets.
- For vaults set up through **Advanced**, the interface does not receive the GitHub token; authentication is delegated to `gh`, and the GPG key and its passphrase remain under the control of GPG and `pinentry`.

## Known limitations

- The autofill was validated in 11 controlled scenarios in the temporary profiles of Brave Origin and stable Chrome with the distributed manifest: common login, user and password in separate steps, `autocomplete=off`, ambiguous passwords or users, hidden or transparent field, new password field, iframe and page without login. Ambiguous cases without an appropriate field left the fields empty. The actual GitHub login passed in both browsers; A second external form passed in Chrome stable, but did not load in Brave in this environment. Stable Chrome was automated in normal window with `Extensions.loadUnpacked`; There still needs to be an installation test using the folder selector in an already used profile.
- Locking the host does not clear the `gpg-agent` cache or terminal access. A request that has already passed the last check may respond before the block is applied.
- Updating or removing an entry checks the hash of the encrypted file, but there is a window between the check and the `pass` subprocess.
- OpenPGP verification confirms the presence of encrypted packets, but does not authenticate the content or prove that a local private key can open it. Remotes and commits created by other tools continue to require trust in the operator.
- The host is the user's own process. Another process from that user may invoke it; The token and approval limit access, but do not protect against a local process that already controls the user or their keychain.
- The package has SHA-256 in the same release, still without an independent signature. The manifest uses a fixed public key to hold the unpacked extension ID in Brave and Chrome; the private key does not go into the repository or the package. The installer registers this ID with the host. Store publishing and eventual ID migration still need to be decided.
- Git entry names and commit history are visible to anyone accessing the private repository. Never include clear text files in this repository; the only key it may hold is the sealed recovery copy on `passport-recovery`.

## Criteria for publishing

The Brave/Chrome matrix, installation and update without local checkout, clone with private remote, and conflict tests were performed with disposable data. Release `v0.2.1` workflow passed; The public installer installed desktop, host, `0.2.1` extension, and manifests for both browsers on a disposable HOME and local user.
