#!/usr/bin/env bash
# Resolve current multi-arch image-index digests for the Dockerfile base images
# and (with --write) re-pin them in the Dockerfiles. Run when bumping a base tag.
#
#   scripts/pin-base-images.sh           # print resolved digests
#   scripts/pin-base-images.sh --write   # rewrite FROM ...@sha256: pins in place
#
# Requires: curl, python3. No docker/crane needed (uses the registry HTTP API).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ACCEPT=(-H "Accept: application/vnd.oci.image.index.v1+json"
        -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json")

dockerhub_digest() { # $1=library/<name> $2=tag
  local repo="$1" tag="$2" tok
  tok=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
  curl -fsSL -o /dev/null -D - -H "Authorization: Bearer ${tok}" "${ACCEPT[@]}" \
    "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" \
    | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}
gcr_digest() { # $1=repo path under gcr.io  $2=tag
  curl -fsSL -o /dev/null -D - "${ACCEPT[@]}" \
    "https://gcr.io/v2/$1/manifests/$2" \
    | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}

GOLANG=$(dockerhub_digest library/golang 1.25-alpine)
NODE=$(dockerhub_digest library/node 22-alpine)
DISTROLESS=$(gcr_digest distroless/static nonroot)

echo "golang:1.25-alpine                  ${GOLANG}"
echo "node:22-alpine                      ${NODE}"
echo "gcr.io/distroless/static:nonroot    ${DISTROLESS}"

if [ "${1:-}" = "--write" ]; then
  for f in build/docker/admission-webhook.Dockerfile build/docker/policy-manager.Dockerfile build/Dockerfile.dashboard; do
    [ -f "$f" ] || continue
    sed -i.bak -E \
      -e "s#(golang:1\.25-alpine)(@sha256:[0-9a-f]+)?#\1@${GOLANG}#g" \
      -e "s#(node:22-alpine)(@sha256:[0-9a-f]+)?#\1@${NODE}#g" \
      -e "s#(gcr\.io/distroless/static:nonroot)(@sha256:[0-9a-f]+)?#\1@${DISTROLESS}#g" \
      "$f"
    rm -f "$f.bak"
    echo "re-pinned $f"
  done
fi
