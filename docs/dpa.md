# Data Processing Addendum (Template)

**Effective:** 2026-11-13

This Data Processing Addendum (“DPA”) forms part of the agreement between the customer
(“Controller”) and Tessera (“Processor”) for the hosted service. It applies to personal data
processed by Processor on behalf of Controller. The parties will complete the signature block
and any negotiated annexes before a paid production commitment.

## 1. Roles and scope

Controller determines the purposes and means of processing. Processor processes personal data
only to provide the service, on documented instructions, and as required by law. The subject
matter is the hosted enforcement and evidence service; the duration is the term of the
agreement; the nature and purpose are authentication, policy enforcement, credential
issuance, evidence generation, verification, support, and security.

## 2. Data categories and data subjects

- Account and workspace administrators, members, and invited users.
- Agent operators and end users represented in action records.
- Customer personnel and contacts in support, audit, and billing records.
- Data categories: identifiers, contact details, authentication identifiers, action metadata,
  tool arguments and outcomes, policy data, evidence records, and operational logs. Special
  category data and production provider secrets are not intended to be submitted; the
  Controller must not instruct their processing without a separate written agreement.

## 3. Processor obligations

Processor will: (a) process only on instructions; (b) ensure personnel are bound by
confidentiality; (c) implement appropriate technical and organizational measures; (d) assist
with data-subject requests and impact assessments to the extent reasonably possible;
(e) notify Controller without undue delay, and in any event within 72 hours of confirming a
personal-data breach; (f) delete or return data at termination subject to law; and
(g) provide information reasonably necessary to demonstrate compliance.

## 4. Security measures

Measures include tenant-scoped authorization and row-level security for broker tables,
non-superuser database roles, encryption in transit, encrypted secret storage, access
controls, audit logging, rate limits, signed records, backups, vulnerability management, and
secure development practices. Measures evolve with risk and are described in the
[Trust Center](trust-center.md) and [Security Guarantees](security-guarantees.md).

## 5. Subprocessors

Controller authorizes the subprocessors in [`subprocessors.md`](subprocessors.md). Processor
will give notice of new subprocessors and an opportunity to object on reasonable grounds.
Subprocessors are bound by obligations no less protective than this DPA.

## 6. International transfers

Where personal data is transferred outside the EEA/UK, the parties will rely on an appropriate
transfer mechanism, including standard contractual clauses where required. The Processor will
provide the current transfer documentation on request.

## 7. Audit and assistance

Processor will make available the information needed to demonstrate compliance and will allow
audits on reasonable notice, subject to confidentiality and scope limits. Audits do not
include access to other tenants' data or the Processor's confidential security controls where
a report or summary is sufficient.

## 8. Deletion and return

On termination, Processor will return or delete personal data within 30 days unless law
requires retention. The Controller may export workspace metadata and evidence before
termination. Backup copies expire on the backup retention schedule. Broker tenant data is
removed through the documented operator purge workflow.

## 9. Liability

Each party's liability under this DPA is subject to the limitations in the agreement, except
where prohibited by law.

## 10. Signature

Controller legal name: ______________________  
Controller address: _________________________  
Authorized signatory: ______________________  
Date: _____________________________________  

Processor legal name: Tessera  
Authorized signatory: ______________________  
Date: _____________________________________  

> This is a working template, not legal advice. Have qualified counsel review it before a
> production commitment.
