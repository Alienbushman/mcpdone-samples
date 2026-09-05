# no_auditable_code

Deliberately holds no Python source, no TypeScript/JavaScript source and no
dependency manifest.

Used by the action self-test to prove that a scan which examines zero files
fails the job instead of going green. Before v0.10 the action fell through
to `exit 0` on any exit code it did not recognise, so a scan that read
nothing reported success -- the CI shape of the silent-clean bug.

Do not add code here.
