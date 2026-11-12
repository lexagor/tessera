export type DesignId = "vercel" | "ui" | "linear" | "factory" | "resend";
export type DesignMode = "light" | "dark";

export interface DesignOption {
  id: DesignId;
  name: string;
  eyebrow: string;
  description: string;
  defaultMode: DesignMode;
}

export const DESIGNS: DesignOption[] = [
  {
    id: "vercel",
    name: "Vercel",
    eyebrow: "Paper terminal",
    description: "Disciplined monochrome, hairline borders, black ink on warm paper.",
    defaultMode: "light",
  },
  {
    id: "ui",
    name: "Ui",
    eyebrow: "Frosted blueprint",
    description: "Soft gray canvas, generous radii, quiet depth, clinical calm.",
    defaultMode: "light",
  },
  {
    id: "linear",
    name: "Linear",
    eyebrow: "Midnight instrument",
    description: "Near-black precision with one acid-lime signal for action.",
    defaultMode: "dark",
  },
  {
    id: "factory",
    name: "Factory",
    eyebrow: "War room",
    description: "Warm black, bone contrast, and orange live-data accents.",
    defaultMode: "dark",
  },
  {
    id: "resend",
    name: "Resend",
    eyebrow: "Velvet terminal",
    description: "Editorial serif, black velvet, and a violet neon trace.",
    defaultMode: "dark",
  },
];

const DESIGN_KEY = "tessera.design";
const MODE_KEY = "tessera.design-mode";

function isDesign(value: string | null): value is DesignId {
  return DESIGNS.some((design) => design.id === value);
}

function isMode(value: string | null): value is DesignMode {
  return value === "light" || value === "dark";
}

export function readDesign(): { design: DesignId; mode: DesignMode } {
  if (typeof window === "undefined") return { design: "vercel", mode: "light" };
  const params = new URLSearchParams(window.location.search);
  const requestedDesign = params.get("design");
  const requestedMode = params.get("mode");
  const storedDesign = window.localStorage.getItem(DESIGN_KEY);
  const storedMode = window.localStorage.getItem(MODE_KEY);
  const design = isDesign(requestedDesign)
    ? requestedDesign
    : isDesign(storedDesign)
      ? storedDesign
      : "vercel";
  const option = DESIGNS.find((item) => item.id === design) ?? DESIGNS[0]!;
  return {
    design,
    mode: isMode(requestedMode)
      ? requestedMode
      : isMode(storedMode)
        ? storedMode
        : option.defaultMode,
  };
}

export function applyDesign(design: DesignId, mode: DesignMode): void {
  document.documentElement.dataset.design = design;
  document.documentElement.dataset.mode = mode;
  try {
    window.localStorage.setItem(DESIGN_KEY, design);
    window.localStorage.setItem(MODE_KEY, mode);
  } catch {
    /* storage can be unavailable in private contexts */
  }
}

export function initDesign(): void {
  if (typeof document === "undefined") return;
  const { design, mode } = readDesign();
  document.documentElement.dataset.design = design;
  document.documentElement.dataset.mode = mode;
}
