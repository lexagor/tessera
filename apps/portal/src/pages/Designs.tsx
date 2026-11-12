import { useState } from "react";

import type { DesignId, DesignMode } from "../design";
import { DESIGNS } from "../design";
import { Badge, Button, Card, PageHeader } from "@tessera/ui";

export function DesignsPage({
  design,
  mode,
  onApply,
}: {
  design: DesignId;
  mode: DesignMode;
  onApply: (design: DesignId, mode: DesignMode) => void;
}) {
  const [previews, setPreviews] = useState<Record<DesignId, DesignMode>>(
    () =>
      Object.fromEntries(
        DESIGNS.map((option) => [option.id, option.defaultMode]),
      ) as Record<DesignId, DesignMode>,
  );

  return (
    <>
      <PageHeader
        title="Five directions. Choose two."
        subtitle="Every direction ships with a light and dark mode. Preview the system, then pick the two that feel most like Tessera."
      />
      <Card style={{ marginBottom: 18 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <div>
            <div className="tf-kpi-label">Current surface</div>
            <div style={{ marginTop: 6 }}>
              <strong>{DESIGNS.find((item) => item.id === design)?.name}</strong>
              <span className="tf-muted"> · {mode} mode</span>
            </div>
          </div>
          <Badge tone="muted">live switcher is in the top bar</Badge>
        </div>
      </Card>

      <div className="tf-design-grid">
        {DESIGNS.map((option) => {
          const previewMode = previews[option.id];
          const active = design === option.id && mode === previewMode;
          return (
            <article className="tf-design-card" key={option.id}>
              <div
                className="tf-design-preview"
                data-design={option.id}
                data-mode={previewMode}
              >
                <div className="preview-bar">
                  <i />
                  <i />
                  <i />
                </div>
                <div className="preview-shell">
                  <div className="preview-side">
                    <span />
                    <span />
                    <span />
                    <span />
                  </div>
                  <div className="preview-main">
                    <div className="preview-title">Prove every action.</div>
                    <div className="preview-sub" />
                    <div className="preview-cards">
                      <div />
                      <div />
                      <div />
                    </div>
                  </div>
                </div>
              </div>
              <div className="tf-design-card-foot">
                <h3>{option.name}</h3>
                <p>
                  <span className="tf-mono">{option.eyebrow}</span> · {option.description}
                </p>
                <div className="tf-design-modes">
                  <Button
                    variant={previewMode === "light" ? "primary" : "ghost"}
                    onClick={() =>
                      setPreviews((current) => ({ ...current, [option.id]: "light" }))
                    }
                  >
                    Light
                  </Button>
                  <Button
                    variant={previewMode === "dark" ? "primary" : "ghost"}
                    onClick={() =>
                      setPreviews((current) => ({ ...current, [option.id]: "dark" }))
                    }
                  >
                    Dark
                  </Button>
                </div>
                <Button
                  variant={active ? "ghost" : "primary"}
                  onClick={() => onApply(option.id, previewMode)}
                  style={{ width: "100%", marginTop: 8 }}
                >
                  {active ? "Currently applied" : "Use this design"}
                </Button>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
