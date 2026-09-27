from __future__ import annotations

# Historical entry point retained for coordinator tooling. The final candidate
# provenance model is authoritative and explicitly pins the parity-gap base,
# search overlay, service overlay, immutable-service overlay, strict-B
# invariants, and the exact final changed-file set.
from audit_native_core_final_candidate import main


if __name__ == "__main__":
    main()
