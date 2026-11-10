import { useEffect, useRef, useState, type ReactNode } from "react";

/** Native <dialog> confirmation (focus trapped by the browser, Esc closes). Optional reason field. */
export function ConfirmDialog(props: {
  open: boolean;
  title: string;
  children?: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  reasonLabel?: string;
  reasonRequired?: boolean;
  onConfirm: (reason: string) => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const [reason, setReason] = useState("");
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (props.open && !d.open) {
      setReason("");
      d.showModal();
      reasonRef.current?.focus(); // put keyboard users straight into the reason box
    }
    if (!props.open && d.open) d.close();
  }, [props.open]);

  const blocked = props.reasonRequired && reason.trim().length < 5;
  return (
    <dialog ref={ref} className="dialog" onCancel={props.onCancel} aria-labelledby="dlg-title">
      <form
        method="dialog"
        onSubmit={(e) => {
          e.preventDefault();
          if (!blocked) props.onConfirm(reason.trim());
        }}
      >
        <h2 id="dlg-title">{props.title}</h2>
        {props.children}
        {props.reasonLabel && (
          <label className="field">
            {props.reasonLabel}
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={3} maxLength={500} ref={reasonRef} />
          </label>
        )}
        <div className="row end">
          <button type="button" className="btn" onClick={props.onCancel}>
            Cancel
          </button>
          <button type="submit" className={props.danger ? "btn danger" : "btn primary"} disabled={blocked}>
            {props.confirmLabel}
          </button>
        </div>
      </form>
    </dialog>
  );
}
