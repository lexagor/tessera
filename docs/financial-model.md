# Financial Model (Planning Template)

**Status:** internal planning template. No forecast, customer outcome, or conversion rate is
validated. The public site intentionally does not publish a price.

## Inputs

| Input | Meaning | Current status |
|---|---|---|
| Design partners | Signed pilots in the funnel | 0 public outcomes; target 3 |
| Paid conversion | Pilots converting to paid | Unproven; set a hypothesis |
| Monthly price | Platform fee | Commercial terms after pilot |
| Included actions | Monthly action allowance | Internal plan limit |
| Monthly actions | Average action volume | No production customer data |
| Overage price | Per-action overage | Hypothesis |
| Gross margin | Revenue after infrastructure/support | Hypothesis |
| CAC | Sales/marketing cost per paid account | Founder time + paid acquisition |
| Monthly churn | Logo churn | No cohort data |
| Fixed monthly cost | Hosting, tools, compliance | Founder input |
| Months | Planning window | 12 |

## Formulas

```text
paid accounts       = design partners × paid conversion
revenue / account   = monthly price + max(0, actions - included) × overage price
MRR                 = paid accounts × revenue / account
ARR                 = MRR × 12
gross profit        = MRR × gross margin
contribution        = gross profit - fixed monthly cost
LTV                 = revenue / account × gross margin ÷ monthly churn
CAC payback         = CAC ÷ (revenue / account × gross margin)
break-even accounts = ceil(fixed monthly cost ÷ (revenue / account × gross margin))
LTV/CAC             = LTV ÷ CAC
```

Run the calculator with explicit inputs:

```bash
DESIGN_PARTNERS=3 PAID_CONVERSION=0.34 MONTHLY_PRICE=1500 \
MONTHLY_ACTIONS=100000 MONTHLY_CHURN=0.02 CAC=6000 \
node scripts/finance-model.mjs
```

The values above are illustrative placeholders, not a forecast. Use conservative, base, and
upside scenarios; show the assumptions and source for every conversion/churn number.

## What must be true

- A design partner accepts the evidence pack in a real security review.
- At least one partner agrees commercial terms after the pilot.
- Support and infrastructure costs are measured, not estimated.
- CAC includes founder time and security/compliance work.
- Churn/expansion are measured from cohorts, not assumed.
- The model reaches a defensible ARR path without relying on an unvalidated ACV.

## Decision gates

1. **Evidence acceptance:** one reviewer accepts a pack; then test willingness to pay.
2. **Paid pilot:** signed order form; measure onboarding and support cost.
3. **Repeatability:** second paid account with the same action/integration pattern.
4. **Scale:** CAC payback and gross margin support hiring; otherwise stay founder-led.

Do not present this template as a forecast or use it in investor materials without replacing the
placeholders with sourced assumptions.
