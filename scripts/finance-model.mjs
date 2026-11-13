#!/usr/bin/env node
/**
 * Transparent unit-economics calculator. It does not invent demand or market size: every
 * number is an input. Outputs are planning scenarios, not forecasts or guarantees.
 */
const num = (name, fallback) => {
  const raw = process.env[name];
  const value = raw === undefined || raw === "" ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    console.error(`${name} must be a non-negative number`);
    process.exit(2);
  }
  return value;
};

const designPartners = num("DESIGN_PARTNERS", 3);
const paidConversion = num("PAID_CONVERSION", 0.34);
const monthlyPrice = num("MONTHLY_PRICE", 1500);
const includedActions = num("INCLUDED_ACTIONS", 250000);
const monthlyActions = num("MONTHLY_ACTIONS", 100000);
const overagePrice = num("OVERAGE_PRICE", 0.004);
const grossMargin = num("GROSS_MARGIN", 0.82);
const cac = num("CAC", 6000);
const monthlyChurn = num("MONTHLY_CHURN", 0.02);
const fixedMonthlyCosts = num("FIXED_MONTHLY_COSTS", 4000);
const months = Math.max(1, Math.round(num("MONTHS", 12)));

if (paidConversion > 1 || grossMargin > 1 || monthlyChurn > 1) {
  console.error("PAID_CONVERSION, GROSS_MARGIN, and MONTHLY_CHURN must be 0..1");
  process.exit(2);
}

const paidAccounts = designPartners * paidConversion;
const overageActions = Math.max(0, monthlyActions - includedActions);
const monthlyRevenuePerAccount = monthlyPrice + overageActions * overagePrice;
const mrr = paidAccounts * monthlyRevenuePerAccount;
const arr = mrr * 12;
const yearRevenue = mrr * months;
const grossProfitMonthly = mrr * grossMargin;
const contributionMonthly = grossProfitMonthly - fixedMonthlyCosts;
const ltv = monthlyRevenuePerAccount * grossMargin / Math.max(monthlyChurn, 0.000001);
const paybackMonths = cac / Math.max(monthlyRevenuePerAccount * grossMargin, 0.000001);
const breakEvenAccounts = Math.ceil(
  fixedMonthlyCosts / Math.max(monthlyRevenuePerAccount * grossMargin, 0.000001),
);
const ltvCac = ltv / Math.max(cac, 0.000001);

console.log(JSON.stringify({
  inputs: {
    designPartners,
    paidConversion,
    monthlyPrice,
    includedActions,
    monthlyActions,
    overagePrice,
    grossMargin,
    cac,
    monthlyChurn,
    fixedMonthlyCosts,
    months,
  },
  outputs: {
    paidAccounts,
    monthlyRevenuePerAccount,
    mrr: Math.round(mrr),
    arr: Math.round(arr),
    revenueOverWindow: Math.round(yearRevenue),
    grossProfitMonthly: Math.round(grossProfitMonthly),
    contributionMonthly: Math.round(contributionMonthly),
    ltv: Math.round(ltv),
    paybackMonths: Math.round(paybackMonths * 10) / 10,
    breakEvenAccounts,
    ltvCac: Math.round(ltvCac * 10) / 10,
  },
  caveat: "Planning model only. Inputs require founder validation; no customer or conversion evidence is implied.",
}, null, 2));
