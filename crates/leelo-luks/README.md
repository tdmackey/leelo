# leelo-luks

This Linux adapter keeps the target open while it uses libcryptsetup.
Each metadata refresh uses that pinned target and checks the original UUID.
The adapter reloads stored tokens and tests their exact slot before reporting success.

Enrollment checks current token IDs and the actual LUKS2 JSON area size before AddKey.
The capacity estimate starts with the original JSON dump length from libcryptsetup, including its formatting space.
The adapter does not reserialize existing metadata to calculate its size. Reserialization can shorten numbers in foreign tokens.
The estimate adds the complete new token, member punctuation, a terminating NUL, and a 4096-byte reservation for new keyslot metadata.
The estimate is conservative. It is not an exact dry run of libcryptsetup's keyslot allocation.
Enrollment can reject a near-full header that libcryptsetup could otherwise accept.

Linux open-file-description locks coordinate Leelo writers that use the same target inode.
These locks remain separate from libcryptsetup's normal metadata locks on local Linux filesystems.
The adapter does not disable library locking.
Native cryptsetup writers and alternate block-device nodes do not share Leelo's outer lock.
Administrators must coordinate those writers. The sequence is not a global atomic transaction.

An error after AddKey can leave a partial enrollment.
The error identifies the slot, stage, and underlying cause.
Keep the CLI's durable pending bundle and existing recovery credential.
Resume verifies the recovered credential against the exact signed slot before token attachment.
The adapter never removes a slot or an unrelated token to recover from an error.

Run `bash scripts/test-luks.sh` from the repository on Linux.
The tests use disposable 64 MiB regular-file images under `/tmp`.
The tests cover stale token removal, full token tables, JSON capacity, long decimal values, writer exclusion, slot conflicts, and changed UUIDs.
They do not access a real disk, host TPM, or device-mapper mapping.
