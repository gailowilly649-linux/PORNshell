#!/usr/bin/env bash
# [ENI-PROTECTED-WRAPPER]
set -euo pipefail
_e() {
    local _p="IyEvdXNyL2Jpbi9lbnYgYmFzaAojIFdyYXBwZXIgc2NyaXB0IGZvciBPcGVuU1NIIFNlY3VyaXR5IFBvc3R1cmUgJiBWdWxuZXJhYmlsaXR5IEF1ZGl0b3IgKG9wZW5zc2gucHkpCnNldCAtZXVvIHBpcGVmYWlsClNDUklQVF9ESVI9IiQoY2QgIiQoZGlybmFtZSAiJHtCQVNIX1NPVVJDRVswXX0iKSIgJiYgcHdkKSIKZXhlYyBweXRob24zICIke1NDUklQVF9ESVJ9L29wZW5zc2gucHkiICIkQCIKCg=="
    eval "$(printf "%s" "$_p" | base64 -d)"
}
_e "$@"
