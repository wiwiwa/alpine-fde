# UKI stub inputs

Deterministic inputs for `ukictl build` unit tests (tests/unit/ukictl_build_stub.sh).
`vmlinuz` is arbitrary fixed content — ukify measures its bytes but does not parse
the kernel image; `.linux` section size/sha256 therefore stays stable for a given
ukify release. `cmdline.txt` pins the fail-closed cmdline flags (§8.2:
`rd.shell=0 rd.emergency=poweroff`).
