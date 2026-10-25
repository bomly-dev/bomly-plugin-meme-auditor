# Meme Dependency Auditor Plugin

Example Bomly auditor plugin that emits reference-style warning findings for packages with meme-ish names such as `left-pad`, `is-odd`, and `colors`. It is intentionally a little silly: useful for learning the auditor API, not a serious security policy.

## Access

`bomly-plugin.json` declares an empty `access` block: the auditor reads only the dependency graph Bomly sends it and its own `extra_packages` configuration, so it touches no files, makes no network calls, reads no environment variables and starts no processes. It is a disclosure, not a sandbox. An empty graph simply yields no findings, so the auditor declares no requirements.

## Build and test

```bash
go test ./...
go build -o bin/bomly-plugin-meme-auditor ./cmd/bomly-plugin-meme-auditor
```

## Install for local development

```bash
bomly plugin install ./bin/bomly-plugin-meme-auditor --dev
bomly plugin enable bomly.meme.auditor
bomly scan --path . --auditors +bomly.meme.auditor
```

## Install from an archive

```bash
bomly plugin install ./dist/bomly-plugin-meme-auditor_linux_amd64.tar.gz
bomly plugin enable bomly.meme.auditor
```

Direct URL installs must include a checksum unless you explicitly opt out:

```bash
bomly plugin install https://example.internal/bomly-plugin-meme-auditor_linux_amd64.tar.gz \
  --checksum sha256:<digest>
```

## Install from a private GitHub Release

```bash
export BOMLY_GITHUB_TOKEN=<token-with-release-access>
bomly plugin install github:bomly-dev/bomly-plugin-meme-auditor@v0.1.0
bomly plugin enable bomly.meme.auditor
```

`GITHUB_TOKEN`, `GH_TOKEN`, and `GITHUB_AUTH_TOKEN` are also accepted by Bomly.

## Configuration

```yaml
plugins:
  bomly.meme.auditor:
    extra_packages:
      - totally-not-suspicious
```

## Example scan target

This repository includes a small npm example at `examples/npm-meme-app` with a lockfile that references a few meme-ish packages such as `left-pad`, `colors`, and `is-odd`.

```bash
bomly scan --path ./examples/npm-meme-app --auditors +bomly.meme.auditor
```
