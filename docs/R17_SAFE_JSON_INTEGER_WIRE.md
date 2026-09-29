# R17 safe JSON integer wire: Python Executor -> JavaScript Relay

Status: isolated candidate; no production service update or live cutover.

The Python Executor emits nanosecond timestamps such as stat.st_mtime_ns. Real values commonly exceed JavaScript Number.MAX_SAFE_INTEGER (9007199254740991). When transmitted as bare JSON numbers, a JavaScript parse rounds the value before HMAC canonicalization and the signature check fails.

The Python pc_remote_transport.protocol.canonical_json now recursively maps integer leaves outside the closed range [-9007199254740991, 9007199254740991] to **exact base-10 strings before both HMAC signing and frame serialization**. Safe integers stay JSON numbers, Boolean stays Boolean, and nested dictionaries/arrays are handled. In particular an Executor in-memory modified_ns remains int, while its signed wire representation is a decimal string when unsafe.

Frame sequence and token generation reject unsafe JS integer values instead of silently changing protocol control types. JavaScript consumers must preserve any decimal nanosecond string (or explicitly parse as BigInt), never pass it through Number when exactness matters. Existing signed frame versions and HMAC algorithms do not change; consumers with strict schemas must explicitly admit decimal-string representations for unsafe integer data fields.

Evidence, isolated Windows checkout rooted at source SHA 04f817299b46ecb0ffa8aa908ce84fdb4c3300d0:
- Python targeted tests/test_remote_protocol.py: 10/10 PASS.
- Full Python test suite: exit 0 (five skipped platform/optional tests).
- Independent real Python encode_frame -> actual pinned Control JavaScript decodeRelayFrame passed HMAC validation and preserved modified_ns=1790682348278000001 both top-level and nested. Pinned Control source 2e5e06ba6966435c0e49e49a9de6e9c550eae8f6.
- Negative boundary checks cover 2^53 and unsafe sequence/token generation.

This change fixes only integer precision on the Python-originating signed relay frames. It does not provide new ChatGPT plugin registration, solve session TTL, or authorize any service upgrade. Cross-language real-host file.info/list compatibility and exact CI on Windows/Ubuntu remain separate release gates.

## Reproduce
From an isolated checkout on Windows or Ubuntu: python -m pytest tests/test_remote_protocol.py and python -m pytest. The full suite is part of the branch-scoped CI.
