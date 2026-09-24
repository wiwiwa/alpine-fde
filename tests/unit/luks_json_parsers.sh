#!/usr/bin/env bash
# tests/unit/luks_json_parsers.sh — LUKS2 metadata JSON mini-parsers
# (lib/baseline.sh luks_json_* + lib/cmd/enroll-tpm.sh enrl_json_token_id)
# against EVERY real-world shape, not just the pretty stub shape:
#   * PRETTY — 4-space indented, ": " separators (hand-written stub shape)
#   * COMPACT — single line, NO space after colons: what real cryptsetup
#     emits (observed live on cryptsetup 2.7.5, e2e runs 1789706685/-9163)
#   * INDENTED-NOSPACE — 2-space indented, ": " separators ABSENT (captured
#     verbatim from the local `cryptsetup luksDump --dump-json-metadata`)
# Provenance of the LUKS2 metadata: REAL dump of a fixture LUKS2 image
# (cryptsetup luksFormat --type luks2, pbkdf2); the compact fixture is that
# same dump minified to cryptsetup 2.7.5's single-line form, with a
# systemd-tpm2 token + bound keyslot spliced in (what systemd-cryptenroll
# leaves behind; metadata only — no TPM needed).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/enroll-tpm.sh
source "$REPO/lib/cmd/enroll-tpm.sh"

T=$(mktemp -d /tmp/alpine-fde-luks-json-parsers.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

# --- fixtures -------------------------------------------------------------------
# PRETTY: the classic stub shape (4-space indent, ": " separators)
PRETTY=$T/pretty.json
cat >"$PRETTY" <<'EOF'
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "af": {
                "type": "luks1",
                "stripes": 4000,
                "hash": "sha256"
            },
            "area": {
                "type": "raw",
                "offset": "32768",
                "size": "258048",
                "encryption": "aes-xts-plain64",
                "key_size": 64
            },
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": 1000,
                "salt": "ggAUypj1xsV3WcsbJ6eE8h1Rhgd4sf/sQKitC4k+/rk="
            }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "area": {
                "type": "raw",
                "offset": "3145728",
                "size": "258048",
                "encryption": "aes-xts-plain64",
                "key_size": 64
            },
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": 1000,
                "salt": "c2xvdDFzYWx0MQ=="
            }
        }
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2-blob": "AAEAC0RhdGE="
        }
    },
    "segments": {
        "0": {
            "type": "crypt",
            "offset": "16777216",
            "size": "dynamic",
            "iv_tweak": "0",
            "encryption": "aes-xts-plain64",
            "sector_size": 4096
        }
    },
    "config": {
        "json_size": "12288",
        "keyslots_size": "16744448"
    }
}
EOF

# COMPACT: real cryptsetup 2.7.5 wire form — ONE line, no space after colons
# (same document as PRETTY; token "0" -> keyslot "1")
COMPACT=$T/compact.json
cat >"$COMPACT" <<'EOF'
{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"ggAUypj1xsV3WcsbJ6eE8h1Rhgd4sf/sQKitC4k+/rk="}},"1":{"type":"luks2","key_size":64,"area":{"type":"raw","offset":"3145728","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"c2xvdDFzYWx0MQ=="}}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"4QuPt1wL0WHPN6Cj5jPC0Ro/dsPYsJVb9UPUs7Yjx1A=","digest":"Yn9xJ8+Kky6KU3HAHApvIaiMhdeYIiLUZgBiIljWosI="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}
EOF

# INDENTED-NOSPACE: captured verbatim from local cryptsetup's dump (2-space
# indent, ":" separators) — also mis-parsed by any ": "-anchored parser
REAL=$T/real.json
cat >"$REAL" <<'EOF'
{
  "keyslots":{
    "0":{
      "type":"luks2",
      "key_size":64,
      "af":{
        "type":"luks1",
        "stripes":4000,
        "hash":"sha256"
      },
      "area":{
        "type":"raw",
        "offset":"32768",
        "size":"258048",
        "encryption":"aes-xts-plain64",
        "key_size":64
      },
      "kdf":{
        "type":"pbkdf2",
        "hash":"sha256",
        "iterations":1000,
        "salt":"ggAUypj1xsV3WcsbJ6eE8h1Rhgd4sf/sQKitC4k+/rk="
      }
    },
    "1":{
      "type":"luks2",
      "key_size":64,
      "area":{
        "type":"raw",
        "offset":"3145728",
        "size":"258048",
        "encryption":"aes-xts-plain64",
        "key_size":64
      },
      "kdf":{
        "type":"pbkdf2",
        "hash":"sha256",
        "iterations":1000,
        "salt":"c2xvdDFzYWx0MQ=="
      }
    }
  },
  "tokens":{
    "0":{
      "type":"systemd-tpm2",
      "keyslots":[
        "1"
      ],
      "tpm2-blob":"AAEAC0RhdGE="
    }
  },
  "segments":{
    "0":{
      "type":"crypt",
      "offset":"16777216",
      "size":"dynamic",
      "iv_tweak":"0",
      "encryption":"aes-xts-plain64",
      "sector_size":4096
    }
  },
  "digests":{
    "0":{
      "type":"pbkdf2",
      "keyslots":[
        "0"
      ],
      "segments":[
        "0"
      ],
      "hash":"sha256",
      "iterations":1000,
      "salt":"4QuPt1wL0WHPN6Cj5jPC0Ro/dsPYsJVb9UPUs7Yjx1A=",
      "digest":"Yn9xJ8+Kky6KU3HAHApvIaiMhdeYIiLUZgBiIljWosI="
    }
  },
  "config":{
    "json_size":"12288",
    "keyslots_size":"16744448"
  }
}
EOF

# Variants: two tpm2 tokens, and no tpm2 token at all (each in both shapes)
PRETTY2=$T/pretty2.json
jq -c '.tokens."1" = {"type":"systemd-tpm2","keyslots":["1"]}' "$PRETTY" |
    jq . >"$PRETTY2"
COMPACT2=$T/compact2.json
jq -c '.tokens."1" = {"type":"systemd-tpm2","keyslots":["1"]}' "$COMPACT" >"$COMPACT2"
PRETTYN=$T/pretty-none.json
jq -c '.tokens = {}' "$PRETTY" | jq . >"$PRETTYN"
COMPACTN=$T/compact-none.json
jq -c '.tokens = {}' "$COMPACT" >"$COMPACTN"

# compact fixture with the token keyed "tpm2" (task-reported 2.7.5 shape variant)
COMPACTSTR=$T/compact-strkey.json
jq -c '.tokens = {"tpm2": {"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}' \
    "$COMPACT" >"$COMPACTSTR"

# --- luks_json_count_type ---------------------------------------------------------
assert_eq "count_type pretty: 1 tpm2 token" "1" "$(luks_json_count_type "$PRETTY" systemd-tpm2)"
assert_eq "count_type compact: 1 tpm2 token (2.7.5 wire)" "1" "$(luks_json_count_type "$COMPACT" systemd-tpm2)"
assert_eq "count_type indented-nospace: 1 tpm2 token" "1" "$(luks_json_count_type "$REAL" systemd-tpm2)"
assert_eq "count_type pretty: 2 tpm2 tokens" "2" "$(luks_json_count_type "$PRETTY2" systemd-tpm2)"
assert_eq "count_type compact: 2 tpm2 tokens" "2" "$(luks_json_count_type "$COMPACT2" systemd-tpm2)"
assert_eq "count_type pretty: 0 tokens" "0" "$(luks_json_count_type "$PRETTYN" systemd-tpm2)"
assert_eq "count_type compact: 0 tokens" "0" "$(luks_json_count_type "$COMPACTN" systemd-tpm2)"
assert_eq "count_type compact: type-scoped (crypt segment)" "1" "$(luks_json_count_type "$COMPACT" crypt)"
assert_eq "count_type compact: keyslot type not confused with token type" "2" "$(luks_json_count_type "$COMPACT" luks2)"

# --- luks_json_token_keyslot --------------------------------------------------------
assert_eq "token_keyslot pretty: token -> keyslot 1" "1" "$(luks_json_token_keyslot "$PRETTY" systemd-tpm2)"
assert_eq "token_keyslot compact: token -> keyslot 1" "1" "$(luks_json_token_keyslot "$COMPACT" systemd-tpm2)"
assert_eq "token_keyslot indented-nospace: token -> keyslot 1" "1" "$(luks_json_token_keyslot "$REAL" systemd-tpm2)"
assert_eq "token_keyslot pretty: absent -> empty" "" "$(luks_json_token_keyslot "$PRETTYN" systemd-tpm2)"
assert_eq "token_keyslot compact: absent -> empty" "" "$(luks_json_token_keyslot "$COMPACTN" systemd-tpm2)"

# --- luks_json_slot_blob --------------------------------------------------------------
BLOB_PRETTY=$(luks_json_slot_blob "$PRETTY" 0)
assert_contains "slot_blob pretty: slot 0 has kdf" "$BLOB_PRETTY" "pbkdf2"
assert_contains "slot_blob pretty: slot 0 has area offset" "$BLOB_PRETTY" "32768"
BLOB_COMPACT=$(luks_json_slot_blob "$COMPACT" 0)
assert_contains "slot_blob compact: slot 0 non-empty + has kdf" "$BLOB_COMPACT" "pbkdf2"
assert_contains "slot_blob compact: slot 0 has area offset" "$BLOB_COMPACT" "32768"
BLOB_COMPACT_S1=$(luks_json_slot_blob "$COMPACT" 1)
assert_contains "slot_blob compact: slot 1 has area offset 3145728" "$BLOB_COMPACT_S1" "3145728"
assert_eq "slot_blob compact: same content parses byte-identical" \
    "$(luks_json_slot_blob "$COMPACT" 0)" "$BLOB_COMPACT"
jq -c '."keyslots"."0"."kdf"."salt" = "VBUNEFRB"' "$COMPACT" >"$T/compact-tampered.json"
assert_ne "slot_blob compact: tampered slot 0 differs" "$BLOB_COMPACT" \
    "$(luks_json_slot_blob "$T/compact-tampered.json" 0)"
assert_eq "slot_blob pretty: absent slot -> empty" "" "$(luks_json_slot_blob "$PRETTY" 7)"
assert_eq "slot_blob compact: absent slot -> empty" "" "$(luks_json_slot_blob "$COMPACT" 7)"

# --- enrl_json_token_id ----------------------------------------------------------------
assert_eq "token_id pretty: numeric key" "0" "$(enrl_json_token_id "$PRETTY" systemd-tpm2)"
assert_eq "token_id compact: numeric key" "0" "$(enrl_json_token_id "$COMPACT" systemd-tpm2)"
assert_eq "token_id indented-nospace: numeric key" "0" "$(enrl_json_token_id "$REAL" systemd-tpm2)"
assert_eq "token_id compact: string key (tpm2)" "tpm2" "$(enrl_json_token_id "$COMPACTSTR" systemd-tpm2)"
assert_eq "token_id pretty: absent -> empty" "" "$(enrl_json_token_id "$PRETTYN" systemd-tpm2)"
assert_eq "token_id compact: absent -> empty" "" "$(enrl_json_token_id "$COMPACTN" systemd-tpm2)"

# --- shape-tolerance: pretty and compact of the SAME document agree ----------------------
assert_eq "shape tolerance: count agrees pretty vs compact" \
    "$(luks_json_count_type "$PRETTY" systemd-tpm2)" "$(luks_json_count_type "$COMPACT" systemd-tpm2)"
assert_eq "shape tolerance: keyslot agrees pretty vs compact" \
    "$(luks_json_token_keyslot "$PRETTY" systemd-tpm2)" "$(luks_json_token_keyslot "$COMPACT" systemd-tpm2)"
assert_eq "shape tolerance: token id agrees pretty vs compact" \
    "$(enrl_json_token_id "$PRETTY" systemd-tpm2)" "$(enrl_json_token_id "$COMPACT" systemd-tpm2)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
