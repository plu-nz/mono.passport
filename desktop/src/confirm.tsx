// Confirmation for destructive or disruptive actions, as an in-app dialog.
// confirmAction() resolves to true when the user confirms; ConfirmHost renders
// the pending request and is mounted once at the app root.

import { createSignal } from 'solid-js';
import { Button } from '@plunz/storybook';
import { Modal } from './account';

type Request = { title: string; message: string; confirm: string; resolve: (ok: boolean) => void };

const [request, setRequest] = createSignal<Request | null>(null);

export function confirmAction(options: { title: string; message: string; confirm: string }): Promise<boolean> {
  request()?.resolve(false);
  return new Promise(resolve => setRequest({ ...options, resolve }));
}

export function ConfirmHost() {
  const answer = (ok: boolean) => {
    const current = request();
    setRequest(null);
    current?.resolve(ok);
  };
  return <>{request() && <Modal title={request()!.title} class="confirm-modal" onClose={() => answer(false)}>
    <p class="confirm-message">{request()!.message}</p>
    <div class="form-actions"><Button onClick={() => answer(true)}>{request()!.confirm}</Button><Button variant="ghost" onClick={() => answer(false)}>Cancel</Button></div>
  </Modal>}</>;
}
