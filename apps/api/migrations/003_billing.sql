-- Stripe billing state, keyed by organization.

CREATE TABLE IF NOT EXISTS billing_subscriptions (
    org_id                   UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    plan                     TEXT NOT NULL,
    status                   TEXT NOT NULL,
    stripe_customer_id       TEXT,
    stripe_subscription_id   TEXT UNIQUE,
    current_period_end       TIMESTAMPTZ,
    cancel_at_period_end     BOOLEAN NOT NULL DEFAULT false,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS billing_subscriptions_customer_idx
    ON billing_subscriptions (stripe_customer_id);
