export type DesignId = "vercel";
export type DesignMode = "light" | "dark";

export const FIXED_DESIGN: DesignId = "vercel";

const MODE_KEY = "tessera.design-mode";
const LEGACY_DESIGN_KEY = "tessera.design";

function isMode(value: string | null): value is DesignMode {
  return value === "light" || value === "dark";
}

export function readMode(): DesignMode {
  if (typeof window === "undefined") return "light";
  const params = new URLSearchParams(window.location.search);
  const requestedMode = params.get("mode");
  const storedMode = window.localStorage.getItem(MODE_KEY);
  try {
    window.localStorage.removeItem(LEGACY_DESIGN_KEY);
  } catch {
    /* storage can be unavailable in private contexts */
  }
  return isMode(requestedMode) ? requestedMode : isMode(storedMode) ? storedMode : "light";
}

export function applyDesign(mode: DesignMode): void {
  document.documentElement.dataset.design = FIXED_DESIGN;
  document.documentElement.dataset.mode = mode;
  try {
    window.localStorage.setItem(MODE_KEY, mode);
    window.localStorage.removeItem(LEGACY_DESIGN_KEY);
  } catch {
    /* storage can be unavailable in private contexts */
  }
}

export function initDesign(): void {
  if (typeof document === "undefined") return;
  applyDesign(readMode());
}
