import { Hono } from "hono";
import Stripe from "stripe";

import { db } from "./db.js";
import { env } from "./env.js";
import { monthlyActionCount, planFor } from "./plans.js";

let stripe: Stripe | null = null;

export function getStripe(): Stripe | null {
  if (!env.STRIPE_SECRET_KEY) return null;
  if (!stripe) {
    stripe = new Stripe(env.STRIPE_SECRET_KEY);
  }
  return stripe;
}

export function priceForPlan(plan: string): string | null {
  if (plan === "team") return env.STRIPE_PRICE_TEAM ?? null;
  if (plan === "growth") return env.STRIPE_PRICE_GROWTH ?? null;
  return null;
}

export interface BillingState {
  plan: string;
  status: string;
  customerId: string | null;
  subscriptionId: string | null;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  usage: { used: number; limit: number };
  stripeConfigured: boolean;
}

export async function getBillingState(orgId: string): Promise<BillingState> {
  const orgRows = await db()`SELECT plan FROM orgs WHERE id = ${orgId}`;
  const billing = await db()`
    SELECT plan, status, stripe_customer_id, stripe_subscription_id,
           current_period_end, cancel_at_period_end
      FROM billing_subscriptions WHERE org_id = ${orgId}
  `;
  const row = billing[0];
  const planName = String(row?.plan ?? orgRows[0]?.plan ?? "team");
  const plan = planFor(planName);
  const used = await monthlyActionCount(orgId);
  return {
    plan: plan.name,
    status: String(row?.status ?? "none"),
    customerId: (row?.stripe_customer_id as string | null) ?? null,
    subscriptionId: (row?.stripe_subscription_id as string | null) ?? null,
    currentPeriodEnd: row?.current_period_end
      ? new Date(row.current_period_end as string).toISOString()
      : null,
    cancelAtPeriodEnd: Boolean(row?.cancel_at_period_end),
    usage: { used, limit: plan.actionsPerMonth },
    stripeConfigured: Boolean(getStripe() && env.STRIPE_PRICE_TEAM && env.STRIPE_PRICE_GROWTH),
  };
}

export async function setStripeCustomer(orgId: string, customerId: string): Promise<void> {
  await db()`
    INSERT INTO billing_subscriptions (org_id, plan, status, stripe_customer_id)
    VALUES (${orgId}, (SELECT plan FROM orgs WHERE id = ${orgId}), 'checkout_pending', ${customerId})
    ON CONFLICT (org_id) DO UPDATE SET
      stripe_customer_id = EXCLUDED.stripe_customer_id,
      updated_at = now()
  `;
}

export async function applySubscription(input: {
  orgId: string;
  plan: string;
  status: string;
  customerId?: string | null;
  subscriptionId?: string | null;
  currentPeriodEnd?: number | null;
  cancelAtPeriodEnd?: boolean;
}): Promise<void> {
  const plan = planFor(input.plan);
  await db().begin(async (tx) => {
    await tx`
      INSERT INTO billing_subscriptions (
        org_id, plan, status, stripe_customer_id, stripe_subscription_id,
        current_period_end, cancel_at_period_end
      ) VALUES (
        ${input.orgId},
        ${plan.name},
        ${input.status},
        ${input.customerId ?? null},
        ${input.subscriptionId ?? null},
        ${input.currentPeriodEnd ? new Date(input.currentPeriodEnd * 1000).toISOString() : null},
        ${input.cancelAtPeriodEnd ?? false}
      )
      ON CONFLICT (org_id) DO UPDATE SET
        plan = EXCLUDED.plan,
        status = EXCLUDED.status,
        stripe_customer_id = coalesce(EXCLUDED.stripe_customer_id, billing_subscriptions.stripe_customer_id),
        stripe_subscription_id = coalesce(EXCLUDED.stripe_subscription_id, billing_subscriptions.stripe_subscription_id),
        current_period_end = EXCLUDED.current_period_end,
        cancel_at_period_end = EXCLUDED.cancel_at_period_end,
        updated_at = now()
    `;
    await tx`UPDATE orgs SET plan = ${plan.name} WHERE id = ${input.orgId}`;
  });
}

export const billingWebhookRoutes = new Hono();

billingWebhookRoutes.post("/v1/webhooks/stripe", async (c) => {
  const client = getStripe();
  if (!client || !env.STRIPE_WEBHOOK_SECRET) {
    return c.json({ error: { code: "not_configured", message: "Stripe billing is not configured" } }, 503);
  }
  const signature = c.req.header("stripe-signature");
  if (!signature) {
    return c.json({ error: { code: "invalid_request", message: "Missing Stripe signature" } }, 400);
  }
  const raw = await c.req.text();
  let event: Stripe.Event;
  try {
    event = await client.webhooks.constructEventAsync(raw, signature, env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    return c.json(
      { error: { code: "invalid_signature", message: error instanceof Error ? error.message : "Invalid signature" } },
      400,
    );
  }

  try {
    if (event.type === "checkout.session.completed") {
      const session = event.data.object as Stripe.Checkout.Session;
      const orgId = session.metadata?.orgId;
      const plan = session.metadata?.plan;
      if (orgId && plan) {
        let currentPeriodEnd: number | null = null;
        if (typeof session.subscription === "string") {
          const subscription = await client.subscriptions.retrieve(session.subscription);
          currentPeriodEnd = subscription.current_period_end;
        }
        await applySubscription({
          orgId,
          plan,
          status: "active",
          customerId: typeof session.customer === "string" ? session.customer : null,
          subscriptionId: typeof session.subscription === "string" ? session.subscription : null,
          currentPeriodEnd,
        });
      }
    } else if (
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      const subscription = event.data.object as Stripe.Subscription;
      const orgId = subscription.metadata?.orgId;
      const plan = subscription.metadata?.plan ?? "team";
      if (orgId) {
        const deleted = event.type === "customer.subscription.deleted";
        await applySubscription({
          orgId,
          plan: deleted ? "developer" : plan,
          status: deleted ? "canceled" : subscription.status,
          customerId: typeof subscription.customer === "string" ? subscription.customer : null,
          subscriptionId: subscription.id,
          currentPeriodEnd: subscription.current_period_end,
          cancelAtPeriodEnd: subscription.cancel_at_period_end,
        });
      }
    } else if (event.type === "invoice.payment_failed") {
      const invoice = event.data.object as Stripe.Invoice;
      const customerId = typeof invoice.customer === "string" ? invoice.customer : null;
      if (customerId) {
        await db()`
          UPDATE billing_subscriptions
             SET status = 'past_due', updated_at = now()
           WHERE stripe_customer_id = ${customerId}
        `;
      }
    }
    return c.json({ received: true });
  } catch (error) {
    console.error("stripe webhook handling failed", error);
    return c.json({ error: { code: "internal_error", message: "Webhook handling failed" } }, 500);
  }
});
