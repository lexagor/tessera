# SCIM 2.0 Provisioning

Tessera exposes an organization-scoped SCIM 2.0 Users endpoint at `/scim/v2`.

## Create a token

An owner or admin creates a token in Tessera Settings (Data controls) or via API:

```bash
curl -X POST https://app.thetessera.xyz/v1/scim-tokens \
  -H 'content-type: application/json' \
  -b "tessera_session=..." \
  -d '{"name":"Okta production"}'
```

The response contains the `scim_...` token once. Store it in the IdP secret manager. It is hashed
at rest and only scoped to the workspace that created it. Revoke it with
`DELETE /v1/scim-tokens/{id}`.

## Endpoints

| Method | Path | Behavior |
|---|---|---|
| GET | `/scim/v2/ServiceProviderConfig` | Capabilities |
| GET | `/scim/v2/ResourceTypes` | User resource |
| GET | `/scim/v2/Users` | List members; `filter=userName eq "..."`; `startIndex`/`count` |
| GET | `/scim/v2/Users/{id}` | Read a member |
| POST | `/scim/v2/Users` | Create/find user and add membership |
| PATCH | `/scim/v2/Users/{id}` | Replace `active`, `name.formatted`, or `roles` |
| DELETE | `/scim/v2/Users/{id}` | Remove membership from this workspace |
| GET | `/scim/v2/Groups` | List role groups |
| POST | `/scim/v2/Groups` | Create a role group and optionally add members |
| GET/PATCH/DELETE | `/scim/v2/Groups/{id}` | Read/update/delete a role group |

Use `Authorization: Bearer scim_...` and `content-type: application/scim+json`.

## Role mapping

SCIM `roles[0].value` may be `admin`, `member`, or `viewer`; anything else becomes `member`.
SCIM cannot create an owner. Deactivating or deleting a user removes their membership; the
global user identity remains for other workspaces.

## Groups and roles

Groups map to `admin`, `member`, or `viewer` through the Tessera extension:

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "Refund admins",
  "members": [{ "value": "<user-id>" }],
  "urn:tessera:params:scim:schemas:extension:2.0:Group": { "role": "admin" }
}
```

Adding a member updates that user's workspace role (owners are never downgraded by a group).
Removing a member from a group does not remove workspace membership or change their role; use
SCIM Users `active`/DELETE for deprovisioning.

## Limitations

- Email changes are not applied by PATCH; verify the new identity through Auth0.
- SCIM tokens are privileged; a token can create admins within its workspace.
- The API currently uses one OIDC issuer/client across tenants; customer-owned SSO is configured
  in Auth0 Organizations, not self-service in the portal.

See [`enterprise-sso.md`](enterprise-sso.md) for the SSO model and
[`pentest-scope.md`](pentest-scope.md) for the security test scope.
