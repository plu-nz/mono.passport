// First-run setup with only a GitHub sign-in and a master password, plus the
// screen that unlocks a Passage-managed vault.

import { createEffect, createSignal, onCleanup, onMount, type JSX } from 'solid-js';
import { Clipboard, Events } from '@wailsio/runtime';
import { Button, Card, TextField } from '@plunz/storybook';
import { invoke } from './service';
import { checkStrength, minScore, strengthLabels, suggestPassphrase, type Strength } from './strength';

export type GitHubAccount = { signedIn: boolean; login: string; name: string; insecure: boolean; revokeUrl: string };
export type OnboardingStatus = { pending: '' | 'create' | 'restore'; minPassword: number; vaultPath: string; managedRepo: string };
type Device = { userCode: string; verificationUri: string; expires: string };
type Repo = { name: string; fullName: string; cloneUrl: string; private: boolean };
type Mode = 'create' | 'restore';
type Screen = 'welcome' | 'github' | 'choose' | 'password' | 'progress' | 'done';

const steps: Record<Mode, [string, string][]> = {
  create: [['key', 'Creating your key'], ['vault', 'Creating the vault'], ['repository', 'Creating a private repository on GitHub'], ['publish', 'Uploading the vault'], ['recovery', 'Saving the encrypted recovery copy'], ['unlock', 'Unlocking']],
  restore: [['clone', 'Downloading the vault'], ['recovery', 'Opening the recovery copy'], ['import', 'Adding your key to this computer'], ['unlock', 'Unlocking']],
};

const message = (cause: unknown) => String(cause).replace(/^Error:\s*/, '');

function Shell(props: { title: string; children: JSX.Element; back?: () => void }) {
  return <main class="onboarding"><Card class="onboarding-card">
    {props.back && <button class="onboarding-back" onClick={props.back}>‹ Back</button>}
    <h1>{props.title}</h1>
    {props.children}
  </Card></main>;
}

// GitHubSignIn runs the device flow: it shows the code, copies it, opens
// GitHub and waits for approval.
export function GitHubSignIn(props: { onSignedIn: (account: GitHubAccount) => void; label?: string }) {
  const [device, setDevice] = createSignal<Device | null>(null);
  const [copied, setCopied] = createSignal(false);
  const [error, setError] = createSignal('');
  onCleanup(() => { if (device()) void invoke('github_cancel_sign_in'); });

  async function signIn() {
    setError('');
    try {
      setDevice(await invoke<Device>('github_start_sign_in'));
      setCopied(false);
      const signed = await invoke<GitHubAccount>('github_finish_sign_in');
      setDevice(null);
      props.onSignedIn(signed);
    } catch (cause) {
      setDevice(null);
      setError(message(cause));
    }
  }

  async function copyAndOpen() {
    const code = device()?.userCode;
    if (!code) return;
    try { await Clipboard.SetText(code); setCopied(true); } catch { /* the code stays visible */ }
    try { await invoke('github_open_verification'); } catch (cause) { setError(message(cause)); }
  }

  async function cancel() {
    await invoke('github_cancel_sign_in');
    setDevice(null);
  }

  return <>
    {device() ? <div class="device">
      <p>Enter this code on GitHub:</p>
      <code class="device-code">{device()!.userCode}</code>
      <div class="onboarding-actions">
        <Button onClick={() => void copyAndOpen()}>{copied() ? 'Code copied · Open GitHub again' : 'Copy code and open GitHub'}</Button>
        <Button variant="ghost" onClick={() => void cancel()}>Cancel</Button>
      </div>
      <p class="hint" role="status">Waiting for approval on GitHub…</p>
    </div> : <div class="onboarding-actions"><Button onClick={() => void signIn()}>{props.label || 'Sign in with GitHub'}</Button></div>}
    {error() && <p class="panel-error" role="alert">{error()}</p>}
  </>;
}

export function Onboarding(props: { status: OnboardingStatus; onDone: () => void; onAdvanced: () => void }) {
  const [mode, setMode] = createSignal<Mode>(props.status.pending || 'create');
  const [screen, setScreen] = createSignal<Screen>(props.status.pending ? 'github' : 'welcome');
  const [account, setAccount] = createSignal<GitHubAccount | null>(null);
  const [busy, setBusy] = createSignal('');
  const [error, setError] = createSignal('');
  const [vaults, setVaults] = createSignal<Repo[]>([]);
  const [repo, setRepo] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirm, setConfirm] = createSignal('');
  const [show, setShow] = createSignal(false);
  const [understood, setUnderstood] = createSignal(false);
  const [strength, setStrength] = createSignal<Strength | null>(null);
  const [step, setStep] = createSignal('');
  const [doneRepo, setDoneRepo] = createSignal('');

  const loadAccount = async () => {
    try { setAccount(await invoke<GitHubAccount>('github_account')); }
    catch (cause) { setError(message(cause)); }
  };
  onMount(() => { void loadAccount(); });
  onCleanup(Events.On('passage:onboarding-step', event => setStep(String(event.data))));

  const start = (next: Mode) => { setMode(next); setError(''); setScreen('github'); };

  async function switchAccount() {
    setError('');
    try { await invoke('github_sign_out'); await loadAccount(); } catch (cause) { setError(message(cause)); }
  }

  async function afterSignIn() {
    setBusy('Looking for your vault on GitHub…');
    setError('');
    try {
      const found = await invoke<Repo[]>('find_github_vaults');
      setVaults(found);
      setRepo(found[0]?.fullName || '');
      if (props.status.pending === 'create' && mode() === 'create') setScreen('password');
      else if (mode() === 'restore' && found.length === 1) setScreen('password');
      else if (mode() === 'create' && found.length === 0) setScreen('password');
      else setScreen('choose');
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(''); }
  }

  // Rate the password as it is typed, ignoring results for older input.
  createEffect(() => {
    const value = password();
    if (mode() !== 'create') return;
    let current = true;
    void checkStrength(value, [account()?.login || '', account()?.name || '', 'passage', 'github']).then(result => { if (current) setStrength(result); });
    onCleanup(() => { current = false; });
  });

  const longEnough = () => [...password()].length >= props.status.minPassword;
  const strongEnough = () => (strength()?.score ?? 0) >= minScore;
  const canCreate = () => longEnough() && strongEnough() && password() === confirm() && understood() && !/[\r\n]/.test(password());

  function suggest() {
    const phrase = suggestPassphrase();
    setPassword(phrase);
    setConfirm(phrase);
    setShow(true);
  }

  async function submit() {
    setError('');
    setStep('');
    setScreen('progress');
    try {
      if (mode() === 'create') await invoke('create_vault_with_github', { password: password() });
      else await invoke('restore_vault_from_github', { fullName: repo(), password: password() });
      const status = await invoke<OnboardingStatus>('onboarding_status');
      setDoneRepo(status.managedRepo);
      setPassword('');
      setConfirm('');
      setScreen('done');
    } catch (cause) {
      setError(message(cause));
      setScreen('password');
    }
  }

  async function startOver() {
    try { await invoke('abandon_onboarding'); } catch (cause) { setError(message(cause)); return; }
    setScreen('welcome');
  }

  const errorLine = () => error() && <p class="panel-error" role="alert">{error()}</p>;

  return <>
    {screen() === 'welcome' && <Shell title="Welcome to Passage">
      <p>Your passwords stay encrypted on this computer and sync to a private GitHub repository that only you can open.</p>
      <div class="onboarding-actions">
        <Button onClick={() => start('create')}>Create my vault</Button>
        <Button variant="outline" onClick={() => start('restore')}>I already have a vault</Button>
      </div>
      <button class="link" onClick={props.onAdvanced}>Advanced setup: existing GPG key, folder or another Git server</button>
    </Shell>}

    {screen() === 'github' && <Shell title={mode() === 'create' ? 'Connect GitHub' : 'Find your vault'} back={() => setScreen('welcome')}>
      {props.status.pending && <p class="hint">Continuing the setup that was interrupted. <button class="link" onClick={() => void startOver()}>Start over</button></p>}
      <p>{mode() === 'create' ? 'Passage keeps an encrypted copy of your vault in a new private repository on your GitHub account.' : 'Sign in to the GitHub account that holds your vault.'}</p>
      {busy() ? <p role="status">{busy()}</p> : account()?.signedIn ? <>
        <p class="status-line"><span class="status-dot ready" />Connected as <strong>@{account()!.login}</strong></p>
        <div class="onboarding-actions">
          <Button onClick={() => void afterSignIn()}>Continue</Button>
          <Button variant="ghost" onClick={() => void switchAccount()}>Use another account</Button>
        </div>
      </> : <GitHubSignIn onSignedIn={signed => { setAccount(signed); void afterSignIn(); }} />}
      {errorLine()}
    </Shell>}

    {screen() === 'choose' && <Shell title={mode() === 'create' ? 'You already have a vault' : vaults().length ? 'Choose your vault' : 'No vault found'} back={() => setScreen('github')}>
      {mode() === 'create' && <>
        <p><strong>{vaults().map(v => v.fullName).join(', ')}</strong> already holds a Passage vault. Restore it to use the same passwords here.</p>
        <div class="onboarding-actions">
          <Button onClick={() => { setMode('restore'); setScreen(vaults().length === 1 ? 'password' : 'choose'); }}>Restore it</Button>
          <Button variant="outline" onClick={() => setScreen('password')}>Create a new vault</Button>
        </div>
      </>}
      {mode() === 'restore' && (vaults().length ? <>
        <div class="choices">{vaults().map(v => <label class="choice"><input type="radio" name="vault" checked={repo() === v.fullName} onChange={() => setRepo(v.fullName)} />{v.fullName}</label>)}</div>
        <div class="onboarding-actions"><Button disabled={!repo()} onClick={() => setScreen('password')}>Continue</Button></div>
      </> : <>
        <p>@{account()?.login} has no repository with a Passage vault.</p>
        <div class="onboarding-actions">
          <Button onClick={() => { setMode('create'); setScreen('password'); }}>Create a new vault</Button>
          <Button variant="ghost" onClick={() => void switchAccount().then(() => setScreen('github'))}>Use another account</Button>
        </div>
      </>)}
    </Shell>}

    {screen() === 'password' && mode() === 'create' && <Shell title="Create your master password" back={() => setScreen('github')}>
      <p>It is the only password you will need to remember. It opens your vault on every computer.</p>
      <TextField id="master-password" label="Master password" type={show() ? 'text' : 'password'} value={password()} onInput={event => setPassword(event.currentTarget.value)} autocomplete="new-password" />
      <TextField id="master-confirm" label="Repeat it" type={show() ? 'text' : 'password'} value={confirm()} onInput={event => setConfirm(event.currentTarget.value)} autocomplete="new-password" />
      <div class="strength" data-score={password() ? strength()?.score ?? 0 : -1}>
        <div class="strength-bar"><span /><span /><span /><span /></div>
        <span>{password() ? `${strengthLabels[strength()?.score ?? 0]}${!longEnough() ? ` · at least ${props.status.minPassword} characters` : ''}` : ' '}</span>
      </div>
      {password() && !strongEnough() && (strength()?.warning || strength()?.suggestions[0]) && <p class="hint">{strength()?.warning || strength()?.suggestions[0]}</p>}
      {password() && confirm() && password() !== confirm() && <p class="hint">The passwords do not match.</p>}
      <div class="onboarding-actions">
        <Button variant="outline" size="sm" onClick={suggest}>Suggest a passphrase</Button>
        <Button variant="ghost" size="sm" onClick={() => setShow(!show())}>{show() ? 'Hide' : 'Show'}</Button>
      </div>
      {show() && password() && <p class="hint">Write it down somewhere safe until you know it by heart.</p>}
      <label class="check"><input type="checkbox" checked={understood()} onChange={event => setUnderstood(event.currentTarget.checked)} />I understand that nobody can recover this password if I forget it, not even Passage.</label>
      <p class="hint">Turn on two-factor authentication on GitHub: your encrypted vault lives there.</p>
      <div class="onboarding-actions"><Button disabled={!canCreate()} onClick={() => void submit()}>Create vault</Button></div>
      {errorLine()}
    </Shell>}

    {screen() === 'password' && mode() === 'restore' && <Shell title="Enter your master password" back={() => setScreen(vaults().length > 1 ? 'choose' : 'github')}>
      <p>The password you created for <strong>{repo()}</strong>.</p>
      <TextField id="master-password" label="Master password" type="password" value={password()} onInput={event => setPassword(event.currentTarget.value)} onKeyDown={event => { if (event.key === 'Enter' && password()) void submit(); }} autocomplete="current-password" />
      <div class="onboarding-actions"><Button disabled={!password()} onClick={() => void submit()}>Open my vault</Button></div>
      {errorLine()}
    </Shell>}

    {screen() === 'progress' && <Shell title={mode() === 'create' ? 'Creating your vault' : 'Restoring your vault'}>
      <ol class="progress-steps">{steps[mode()].map(([id, label], index) => {
        const current = steps[mode()].findIndex(([s]) => s === step());
        const state = index < current ? 'done' : index === current ? 'active' : '';
        return <li class={state}><span class="progress-mark" aria-hidden="true">{state === 'done' ? '✓' : ''}</span>{label}</li>;
      })}</ol>
      <p class="hint">This can take a minute. Keep Passage open.</p>
    </Shell>}

    {screen() === 'done' && <Shell title="Your vault is ready">
      {mode() === 'create'
        ? <p>Your passwords sync to the private repository <strong>{doneRepo()}</strong>. To use them on another computer, install Passage, choose “I already have a vault”, sign in with GitHub and enter your master password.</p>
        : <p>Your passwords from <strong>{doneRepo()}</strong> are on this computer and stay in sync.</p>}
      <div class="onboarding-actions"><Button onClick={props.onDone}>Open my vault</Button></div>
    </Shell>}
  </>;
}

export function UnlockScreen(props: { repo: string; onUnlocked: () => void }) {
  const [password, setPassword] = createSignal('');
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal('');
  async function unlock() {
    if (!password() || busy()) return;
    setBusy(true);
    setError('');
    try {
      await invoke('unlock', { password: password() });
      setPassword('');
      props.onUnlocked();
    } catch (cause) { setError(message(cause)); }
    finally { setBusy(false); }
  }
  return <Shell title="Passage is locked">
    <p>Enter your master password to open <strong>{props.repo}</strong>.</p>
    <TextField id="unlock-password" label="Master password" type="password" value={password()} onInput={event => setPassword(event.currentTarget.value)} onKeyDown={event => { if (event.key === 'Enter') void unlock(); }} autocomplete="current-password" autofocus />
    <div class="onboarding-actions"><Button disabled={!password() || busy()} onClick={() => void unlock()}>{busy() ? 'Unlocking…' : 'Unlock'}</Button></div>
    {error() && <p class="panel-error" role="alert">{error()}</p>}
    <p class="hint">The browser extension and <code>pass</code> in the terminal use the same unlock.</p>
  </Shell>;
}
