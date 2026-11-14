// Closing a <dialog> by clicking its backdrop. The backdrop has no element of
// its own: clicks there target the dialog, so they are told apart by position.
// A drag that starts inside (selecting text in a field) and ends outside also
// targets the dialog, so the press has to start outside too.

function outside(event: MouseEvent): boolean {
  const dialog = event.currentTarget as HTMLDialogElement;
  if (event.target !== dialog) return false;
  const box = dialog.getBoundingClientRect();
  return event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom;
}

export function backdropClose(close: () => void) {
  let pressedOutside = false;
  return {
    onPointerDown: (event: PointerEvent) => { pressedOutside = outside(event); },
    onClick: (event: MouseEvent) => { if (pressedOutside && outside(event)) close(); pressedOutside = false; },
  };
}
