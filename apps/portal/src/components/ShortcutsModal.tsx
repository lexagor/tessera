import { Modal } from "@tessera/ui";

const SHORTCUTS = [
  { keys: ["⌘", "K"], label: "Open command palette" },
  { keys: ["Ctrl", "K"], label: "Open command palette" },
  { keys: ["?"], label: "Open keyboard shortcuts" },
  { keys: ["Esc"], label: "Close a dialog or palette" },
  { keys: ["↑", "↓"], label: "Move through palette results" },
  { keys: ["↵"], label: "Open the selected result" },
  { keys: ["Alt", "1"], label: "Go to Overview" },
  { keys: ["Alt", "2"], label: "Go to Analytics" },
  { keys: ["Alt", "3"], label: "Go to Actions" },
  { keys: ["Alt", "4"], label: "Go to Agents" },
  { keys: ["Alt", "5"], label: "Go to Integrations" },
  { keys: ["Alt", "6"], label: "Go to Evidence" },
];

export function ShortcutsModal({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Keyboard shortcuts" onClose={onClose} wide>
      <p>Move through the control plane without leaving the keyboard.</p>
      <div className="tf-shortcuts">
        {SHORTCUTS.map((shortcut) => (
          <div className="tf-shortcut-row" key={`${shortcut.label}-${shortcut.keys.join("-")}`}>
            <span>{shortcut.label}</span>
            <span className="tf-shortcut-keys">
              {shortcut.keys.map((key) => <kbd key={key}>{key}</kbd>)}
            </span>
          </div>
        ))}
      </div>
    </Modal>
  );
}
