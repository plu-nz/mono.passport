// Account maintenance for a Passport-managed vault: change the master
// password, export the key for other pass apps, print an emergency kit.

import { createEffect, createSignal, onCleanup, type JSX } from 'solid-js';
import { Button, TextField } from '@plunz/storybook';
import { invoke } from './service';
import { backdropClose } from './modal';
import { checkStrength, minScore, strengthLabels, suggestPassphrase, type Strength } from './strength';

const message = (cause: unknown) => String(cause).replace(/^Error:\s*/, '');

// Modal opens as a native dialog; Escape, the close button or a click on the
// backdrop dismiss it, except while it is busy.
function Modal(props: { title: string; onClose: () => void; busy?: boolean; class?: string; children: JSX.Element }) {
  const open = (dialog: HTMLDialogElement) => queueMicrotask(() => {
    if (!dialog.isConnected || dialog.open) return;
    dialog.showModal();
    dialog.querySelector<HTMLInputElement>('input')?.focus();
  });
  const backdrop = backdropClose(() => { if (!props.busy) props.onClose(); });
  return <dialog class={`modal ${props.class || ''}`} ref={open} aria-label={props.title} {...backdrop} onCancel={event => { event.preventDefault(); if (!props.busy) props.onClose(); }}>
    <div class="modal-heading"><h2>{props.title}</h2><button class="icon-button" aria-label="Close" disabled={props.busy} onClick={props.onClose}><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg></button></div>
    {props.children}
  </dialog>;
}

export function ChangePasswordDialog(props: { login: string; minPassword: number; onClose: () => void }) {
  const [current, setCurrent] = createSignal('');
  const [next, setNext] = createSignal('');
  const [confirm, setConfirm] = createSignal('');
  const [show, setShow] = createSignal(false);
  const [strength, setStrength] = createSignal<Strength | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [done, setDone] = createSignal(false);
  createEffect(() => {
    const value = next();
    let live = true;
    void checkStrength(value, [props.login, 'passport', 'github']).then(result => { if (live) setStrength(result); });
    onCleanup(() => { live = false; });
  });
  const ok = () => !!current() && [...next()].length >= props.minPassword && (strength()?.score ?? 0) >= minScore && next() === confirm() && next() !== current();
  async function save() {
    setBusy(true);
    setError('');
    try {
      await invoke('change_master_password', { current: current(), next: next() });
      setCurrent(''); setNext(''); setConfirm('');
      setDone(true);
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  function suggest() { const phrase = suggestPassphrase(); setNext(phrase); setConfirm(phrase); setShow(true); }
  return <Modal title="Change master password" onClose={props.onClose} busy={busy()}>
    {done() ? <>
      <p>Your master password changed here and in the recovery copy on GitHub. Other computers ask for the new password the next time they unlock.</p>
      <div class="form-actions"><Button onClick={props.onClose}>Done</Button></div>
    </> : <div class="entry-form">
      <TextField id="current-password" label="Current master password" type="password" value={current()} onInput={event => setCurrent(event.currentTarget.value)} autocomplete="current-password" disabled={busy()} />
      <TextField id="new-password" label="New master password" type={show() ? 'text' : 'password'} value={next()} onInput={event => setNext(event.currentTarget.value)} autocomplete="new-password" disabled={busy()} />
      <TextField id="confirm-password" label="Repeat it" type={show() ? 'text' : 'password'} value={confirm()} onInput={event => setConfirm(event.currentTarget.value)} autocomplete="new-password" disabled={busy()} />
      <div class="strength" data-score={next() ? strength()?.score ?? 0 : -1}><div class="strength-bar"><span /><span /><span /><span /></div><span>{next() ? strengthLabels[strength()?.score ?? 0] : ' '}</span></div>
      <div class="panel-actions"><Button variant="outline" size="sm" onClick={suggest}>Suggest a passphrase</Button><Button variant="ghost" size="sm" onClick={() => setShow(!show())}>{show() ? 'Hide' : 'Show'}</Button></div>
      <p class="hint">A copy of the vault made before the change still opens with the old password. If you think the old one leaked, ask for help rotating the key.</p>
      <div class="form-actions"><Button disabled={!ok() || busy()} onClick={() => void save()}>{busy() ? 'Changing…' : 'Change password'}</Button><Button variant="ghost" disabled={busy()} onClick={props.onClose}>Cancel</Button></div>
      {error() && <p class="panel-error" role="alert">{error()}</p>}
    </div>}
  </Modal>;
}

export function ExportKeyDialog(props: { onClose: () => void }) {
  const [password, setPassword] = createSignal('');
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  const [saved, setSaved] = createSignal('');
  async function exportKey() {
    setBusy(true);
    setError('');
    try {
      const path = await invoke<string>('export_key', { password: password() });
      setPassword('');
      if (path) setSaved(path);
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  return <Modal title="Use your vault in other apps" onClose={props.onClose} busy={busy()}>
    {saved() ? <>
      <p>Saved to <code>{saved()}</code>. It stays protected by your master password.</p>
      <p class="hint">On another device, import it with <code>gpg --import</code> (or in Android Password Store / OpenKeychain), then clone the vault repository. Delete the file once it is imported.</p>
      <div class="form-actions"><Button onClick={props.onClose}>Done</Button></div>
    </> : <div class="entry-form">
      <p>Passport saves your private key to a file so <code>pass</code>, browserpass or Android Password Store can open the same vault. The file stays protected by your master password.</p>
      <TextField id="export-password" label="Master password" type="password" value={password()} onInput={event => setPassword(event.currentTarget.value)} onKeyDown={event => { if (event.key === 'Enter' && password()) void exportKey(); }} autocomplete="current-password" disabled={busy()} />
      <div class="form-actions"><Button disabled={!password() || busy()} onClick={() => void exportKey()}>{busy() ? 'Saving…' : 'Choose where to save'}</Button><Button variant="ghost" disabled={busy()} onClick={props.onClose}>Cancel</Button></div>
      {error() && <p class="panel-error" role="alert">{error()}</p>}
    </div>}
  </Modal>;
}

export function EmergencyKit(props: { login: string; repo: string; onClose: () => void }) {
  const today = new Date().toLocaleDateString();
  return <Modal title="Emergency kit" class="kit-modal" onClose={props.onClose}>
    <article class="kit print-area">
      <h1>Passport emergency kit</h1>
      <p class="kit-date">Printed {today}</p>
      <dl>
        <dt>GitHub account</dt><dd>@{props.login}</dd>
        <dt>Vault repository</dt><dd>github.com/{props.repo}</dd>
        <dt>Master password</dt><dd class="kit-blank" />
      </dl>
      <h2>Open your vault on a new computer</h2>
      <ol>
        <li>Install Passport: <code>curl -LsSf https://passport.plu.nz/install.sh | sh</code></li>
        <li>Open Passport and choose <strong>I already have a vault</strong>.</li>
        <li>Sign in to GitHub as <strong>@{props.login}</strong>.</li>
        <li>Enter your master password.</li>
      </ol>
      <p>Nobody can recover the master password, not even Passport. Keep this page somewhere safe, away from your computer.</p>
    </article>
    <div class="form-actions"><Button onClick={() => window.print()}>Print</Button><Button variant="ghost" onClick={props.onClose}>Close</Button></div>
  </Modal>;
}
