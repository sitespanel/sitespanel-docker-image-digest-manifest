# SitesPanel image digest manifest

The list of container image digests that SitesPanel customer servers may run, signed with the SitesPanel manifest key and published at:

- `https://packages.sitespanel.io/images/sitespanel-docker-image-digest-manifest.json`
- `https://packages.sitespanel.io/images/sitespanel-docker-image-digest-manifest.json.minisig`

Servers pull images only by a digest listed in a manifest whose signature verifies. They refuse a manifest that is expired, or older than the one they already hold.

The images are built elsewhere and are not changed here:

- **First-party images** are built from SitesPanel's public repositories `sitespanel/<name>-docker` (php, nginx, frankenphp, caddy, apache, adminer, openlitespeed) by GitHub Actions and published to `ghcr.io/sitespanel/<name>` (the panel's ADR-0067). Their entries in `images.yaml` read them there, anonymously, and a digest is approved only if `gh attestation verify` shows the signed build attestation of that repository's own workflow (`.github/workflows/image.yml`) on `main`. They have no mirror: ghcr.io is their primary registry.
- **Third-party images** (MariaDB, Valkey and others) come from their publishers.

## How a digest is approved

The workflow `.github/workflows/manifest.yml` runs every 6 hours. Each run, for each entry in `images.yaml`:

1. It reads the tag's current digest from Docker Hub (read only, retrying when Docker Hub limits requests).
2. A digest already listed is kept as it is, except in the daily run at 00:17 UTC, which re-scans every listed digest.
3. A new digest is scanned with Trivy. It is approved only if no fixable high or critical vulnerability is found, or each one has an approved waiver.
4. A first-party image must also pass its contract in `images.yaml`. The contract checks:
   - the nginx modules and build options;
   - the PHP extensions and tools;
   - the Apache modules;
   - what must not be there.
5. When a new digest is not approved, the last approved digest stays listed and the run says why.
6. When a listed digest fails a later re-scan, it stays listed with its `findings`, so the panel can alert staff.
7. When an image has no approved digest at all, the run fails.

## Waivers

`security/image-scan-waivers.yaml` holds reviewed exceptions. Each one:

- names the image and the CVE;
- says why the finding does not reach SitesPanel;
- carries the date the founder approved it and an expiry at most 30 days later.

A line marked `proposed` waives nothing.

## Format (schema 1)

```json
{
  "schema": 1,
  "sequence": 1793081690,
  "generated_at": "2026-10-27T06:14:50Z",
  "expires_at": "2026-11-10T06:14:50Z",
  "images": [
    {
      "name": "php-fpm", "version": "8.4",
      "repository": "ghcr.io/sitespanel/php", "tag": "8.4-fpm-trixie",
      "digest": "sha256:…", "scanned_at": "2026-10-27T06:14:50Z",
      "waived": ["CVE-…"], "findings": ["CVE-…"], "php_extensions": ["…"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `sequence` | Only grows. It is also in the signature's trusted comment, `sitespanel-docker-image-digest-manifest schema=1 sequence=N`. |
| `expires_at` | 14 days after generation. |
| `tag` | Informational: the digest decides. |
| `waived`, `findings`, `php_extensions` | Present only when not empty. |

Verify a copy with [minisign](https://jedisct1.github.io/minisign/):

```sh
minisign -Vm sitespanel-docker-image-digest-manifest.json -p security/image-manifest-minisign.pub
```

The tool, `go run . build | verify | keygen`, is in this repository. Its source of truth is the `image-manifest/` folder of the SitesPanel repository, which publishes it here.

## Mirror (TASK-0073, ADR-0035, REQ-0068)

Every third-party entry (an image read from Docker Hub) carries `mirror`: the same image, copied unchanged by digest, at `ghcr.io/sitespanel/sitespanel-mirror-<repository path with dashes>` (`library/mariadb` becomes `...-mirror-library-mariadb`). The agent pulls anonymously from the primary, retries with backoff while the failure may pass, then pulls the same digest from the mirror, and runs the container from whichever reference holds the image. A mirror outside `ghcr.io/sitespanel/sitespanel-mirror-` is refused by the manifest tool and ignored by the agent. Copying each approved digest to the mirror is a step of the publishing workflow and is live (a new package at ghcr.io per image, each recorded in `planning/registers/cloud-resources.md`); it needs the founder in the session. First-party entries have none (they are at ghcr.io already).

## SBOM (TASK-0117)

For every digest the run approves, the tool asks Trivy for an SPDX JSON document of the image and records its path and SHA-256 in the entry's `sbom` field. The documents are written to `out/sbom/`, uploaded before the manifest, and the last workflow step checks that each served document has the recorded hash. An unchanged digest keeps its reference; a digest that fails its scan or contract gets none. Agents ignore the field; the manifest schema is unchanged.
