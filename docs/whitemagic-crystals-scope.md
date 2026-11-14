# WhiteMagic crystal adapter scope

The plaintext rows (`whitemagic-crystals` — shipped `LocalCrystalStore` default
auto-persisting its off-store anchor under `$XDG_STATE_HOME/whitemagic/anchors/`
— and the `whitemagic-crystals+in-store` counterfactual keeping `commitment.json`
inside `store-<ctx>/`) unseal the encrypted values and compare the returned
bytes to the stored plaintext values. Their edit-detection point is the
verified read path.

The `whitemagic-crystals+ciphertext-audit` row identifies an encrypted-envelope
audit without the decryption key. The earlier `whitemagic-crystals+l5` label
originally claimed a safe plaintext read; that name was retired and renamed to
`whitemagic-crystals+ciphertext-audit` when a detached-plaintext counterfactual
proved that no-KEK verification authenticates the signed ciphertext envelope
rather than independently stored plaintext fields. Its content-payload hook exposes the signed
ciphertext; metadata is checked separately by the same envelope audit and its
T8 control. A detached plaintext cache is outside that measured payload.
The row reports `detection_point=audit` and successful detection is `REPORTED`,
not a verified plaintext read refusal. It does not implement a formal
zero-knowledge proof and must not be cited as one. A consumer of plaintext
must use the unsealing row or a separate demonstrated binding mechanism.

The client source is selected by `AGMI_WHITEMAGIC_CRYSTAL_CLIENT`, then checked
against the full commit's expected SHA-256 before any source is executed.
The loader executes exactly those checked bytes. Measurement identity records
both the full commit and file digest; wrong source bytes fail rather than
being measured under the pinned label.

The dedicated workflow fetches only this byte-pinned file and fails if it is
missing or different. The normal suite may still skip an opt-in adapter when
no source is selected, but this dedicated job cannot silently skip it.
