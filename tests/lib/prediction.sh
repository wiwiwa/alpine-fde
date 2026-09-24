# tests/lib/prediction.sh — G-T13 prediction check helper (§12): ukify's
# predicted PCR 11 (enter-initrd) == the selection PolicyPCR digest over the
# guest's PRE-UNLOCK PCR 11 reading (the `alpine-fde-pcr-postphase` line),
# compared against the console/event-log reading — NOT the final register.
# Requires: tests/lib/assert.sh sourced, uki_pcrsig_enter_initrd_pol +
# uki_pcr11_policy_digest from tests/lib/uki-build.sh, $CONSOLE set.

assert_pcr11_prediction() { # <label-prefix> — one assertion; fails loudly
    local prefix=${1:-G-T13}
    local pcr11_post pol_enter pol_predicted
    pcr11_post=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' \
        "$CONSOLE" 2>/dev/null | head -1 | cut -d= -f2)
    pol_enter=$(uki_pcrsig_enter_initrd_pol "$RUN/uki-pcrsig.json")
    pol_predicted=$(uki_pcr11_policy_digest "$pcr11_post")
    if [[ -n "$pcr11_post" ]]; then
        assert_eq "$prefix: ukify enter-initrd prediction == pre-unlock PCR 11 state" \
            "$pol_enter" "$pol_predicted"
    else
        _assert_result not-ok \
            "$prefix: ukify enter-initrd prediction == pre-unlock PCR 11 state" \
            "no postphase PCR 11 line in console"
    fi
}
