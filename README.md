# Meme Dependency Auditor Plugin

Example Bomly auditor plugin that emits reference-style warning findings for packages with meme-ish names such as `left-pad`, `is-odd`, and `colors`. It is intentionally a little silly: useful for learning the auditor API, not a serious security policy.

## Build and test

```bash
go test ./...
go build -o bin/bomly-plugin-meme-dependency-auditor .
```

## Install for local development

```bash
bomly plugin install ./bin/bomly-plugin-meme-dependency-auditor --dev
bomly plugin enable bomly.examples.auditor.meme-deps
bomly scan --path . --auditors +bomly.examples.auditor.meme-deps
```

## Install from an archive

```bash
bomly plugin install ./dist/bomly-plugin-meme-dependency-auditor_linux_amd64.tar.gz
bomly plugin enable bomly.examples.auditor.meme-deps
```

Direct URL installs must include a checksum unless you explicitly opt out:

```bash
bomly plugin install https://example.internal/bomly-plugin-meme-dependency-auditor_linux_amd64.tar.gz \
  --checksum sha256:<digest>
```

## Install from a private GitHub Release

```bash
export BOMLY_GITHUB_TOKEN=<token-with-release-access>
bomly plugin install github:bomly-dev/bomly-plugin-meme-dependency-auditor@v0.1.0
bomly plugin enable bomly.examples.auditor.meme-deps
```

`GITHUB_TOKEN`, `GH_TOKEN`, and `GITHUB_AUTH_TOKEN` are also accepted by Bomly.

## Configuration

```yaml
plugins:
  bomly.examples.auditor.meme-deps:
    extra_packages:
      - totally-not-suspicious
```
