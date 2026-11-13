# Fork deployment

This fork deploys the existing KV-backed `nodewarden` Worker through
`.github/workflows/deploy.yml`. Pushes to `main` and manual workflow runs on
`main` run checks and deploy. Pull requests run checks only.

## GitHub Actions configuration

Add these **environment secrets** under **Settings → Environments → production**.
Restrict the environment to the `main` branch, and remove repository-level copies
after migration:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | A dedicated Cloudflare deployment API token |
| `CLOUDFLARE_ACCOUNT_ID` | Account containing the existing Worker |
| `CLOUDFLARE_ZONE_ID` | Zone containing its existing custom domain |
| `CLOUDFLARE_D1_DATABASE_ID` | UUID of the database currently bound as `DB` |
| `CLOUDFLARE_KV_NAMESPACE_ID` | ID of the namespace currently bound as `ATTACHMENTS_KV` |
| `NODEWARDEN_DOMAIN` | Existing custom hostname, without `https://` or a path |

The Cloudflare **Edit Cloudflare Workers** token template is a starting point.
Limit its resources to the deployment account and domain's zone, and include
**Account → D1 → Read** for existing database lookup and **Zone → Zone → Read**
for domain lookup. The Worker deployment
requires **Workers Scripts → Edit**; binding/domain management also uses the
Workers KV and Workers Routes permissions supplied by the template.

`JWT_SECRET` is a runtime secret on Cloudflare. Normal deployments retain it;
the workflow verifies its binding exists and never generates a replacement.

The generic `wrangler.kv.toml` is versioned. The workflow validates settings,
generates the ignored `wrangler.ci.toml`, confirms its bindings match the existing
Worker, and deploys with the Wrangler version in `package-lock.json`. The build
runs before deployment credentials are injected. Generated configuration is
deleted at the end and is not uploaded as an artifact. Environment secrets are
masked by GitHub in workflow logs; keep debug logging disabled.

The required **Release gate** waits for type checking, regression/compatibility
tests, a production build, dependency audits, Gitleaks, Semgrep, CodeQL, actionlint,
and workflow security checks. Scanner failures and missing reports fail closed.
Reviewed false positives are scoped by tool, rule, and exact file in
`.github/security-reviewed-findings.json`, include a justification, and expire.
Unreviewed security findings block release even if the scanning action succeeds.

Live verification checks HTTPS redirection, HSTS, CSP, frontend assets,
database bootstrap, existing invite-only registration, and API authentication.
Production deployment jobs run one at a time.

## Local deployment

The ignored `wrangler.my.toml` contains the local deployment configuration and
the existing resource IDs. It includes a build command and can be deployed with:

```sh
npm ci
npm run deploy:my
```

Keep the account, Worker name, D1/KV IDs, custom domain, and Durable Object
bindings consistent when transferring this file to another machine.

## Updates

`origin` points to this fork and `upstream` to the original project. Fetch and
merge reviewed upstream changes into a feature branch, retaining this fork's
hardening changes. Open a pull request targeting `main`; branch protection
requires the Release gate and resolved conversations, including for admins.
Merging a passing pull request triggers automatic deployment. Direct or forced
pushes to `main` are blocked. An upstream release alone does not deploy.

Dependabot alerts and automated security-update PRs are enabled. Weekly version
updates cover npm and pinned GitHub Actions. A seven-day cooldown applies to
ordinary version updates; security updates follow Dependabot's security-update
policy. Updates are tested through the same pull-request gate and are not
automatically merged.

To redeploy an earlier application revision, revert the corresponding change
through a pull request, or use Cloudflare's deployment rollback where supported.
Code rollback does not roll back persistent database changes.

## Browser security compatibility

Live vault decryption accepts authenticated Bitwarden type-2 symmetric enc
strings only. Changing a ciphertext type cannot disable its MAC check, and both
encryption and authentication keys are required. Old unauthenticated formats must
be migrated using a trusted compatible client and re-encrypted before Web Vault
use; there is no automatic type-based fallback with current vault keys.

Authentication bodies are limited to 256 KiB with tighter WebAuthn field bounds.
Password, API-key, and passkey login attempts share a per-IP budget. Browser idle
locking uses an absolute deadline and checks it on resume/focus before accepting
new activity.
