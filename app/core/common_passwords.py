"""HIPAA Phase 1 PR2: small, always-available common-password blocklist.

Deliberately NOT the primary or comprehensive compromised-password
mechanism -- that's `app/core/compromised_password.py`'s HIBP k-anonymity
lookup, which checks against hundreds of millions of real breached
passwords. This module exists as an always-on floor with zero network
dependency: it still rejects the most obviously unsafe choices even
during a Pwned Passwords outage (with PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED
left at its default `false`) or if that check is disabled entirely.

Source: a small, illustrative subset of passwords that appear at the top
of essentially every public "most common passwords" list (NCSC UK's 2019
top-100k analysis, SplashData/NordPass annual reports, the
10-million-password-list and rockyou.txt corpora) -- not a full copy of
any of those datasets, which would be tens of thousands of entries and
belongs in the network-backed check, not embedded in this repository.
Matching is case-insensitive exact-match only (not substring/fuzzy) --
"Password123!" is a different string from "password123" and is NOT
caught here (it may still be caught by the HIBP check, since it is in
fact a very commonly breached password).

Update process: manual. This list is not expected to change often --
add an entry if a specific weak password recurs in practice (e.g. shows
up repeatedly in incident review), not as an attempt to keep pace with
the general compromised-password corpus, which is the network check's
job. Limitations: no substring/pattern matching (e.g. "password1",
"password2", ... are each their own entry, not derived), no
keyboard-walk detection, no leetspeak normalization -- deliberately
simple, so its behavior is easy to reason about and test.
"""

COMMON_PASSWORDS = frozenset({
    "password", "password1", "password12", "password123", "password1234",
    "123456", "12345678", "123456789", "1234567890", "12345",
    "qwerty", "qwerty123", "qwertyuiop", "1q2w3e4r", "1q2w3e4r5t",
    "letmein", "letmein123", "welcome", "welcome1", "welcome123",
    "admin", "administrator", "admin123", "root", "toor",
    "iloveyou", "iloveyou1", "iloveyou123", "monkey", "monkey123",
    "dragon", "dragon123", "master", "master123", "superman",
    "trustno1", "sunshine", "sunshine1", "princess", "princess1",
    "football", "football1", "baseball", "baseball1", "basketball",
    "shadow", "shadow1", "michael", "michael1", "jennifer",
    "computer", "internet", "changeme", "changeme123", "default",
    "abc123", "abcd1234", "a1b2c3d4", "1234abcd", "qazwsx",
    "1qaz2wsx", "zxcvbnm", "asdfghjkl", "asdf1234", "starwars",
    "batman", "pokemon", "hunter2", "whatever", "whatever1",
    "letme1n", "passw0rd", "p@ssword", "p@ssw0rd", "pass1234",
    "test1234", "testtest", "temp1234", "temppass", "guest",
    "guest123", "user1234", "login123", "access123", "secret123",
    "freedom", "freedom1", "matrix", "matrix1", "ninja",
    "ninja123", "flower", "flower1", "loveme", "hello123",
    "hello1234", "welcome2023", "welcome2024", "spring2023", "spring2024",
    "summer2023", "summer2024", "autumn2023", "winter2023", "january2024",
    "chocolate", "cookie123", "banana123", "orange123", "purple123",
    "michelle", "jessica1", "jordan23", "george1", "charlie1",
    "1111111111", "0000000000", "9999999999", "aaaaaaaaaa", "zzzzzzzzzz",
    "qqqqqqqqqq", "121212121212", "123123123123", "654321654321", "111111000000",
})
