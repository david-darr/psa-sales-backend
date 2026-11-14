# PSA Command tool review recovery

PSA Command 1.5.0 added workspace arguments to PSA Sales tool schemas. Kairos
pins tool definitions and holds changed definitions for human review. On an
existing 1.4.3 connection, the unchanged visible set is sales_overview and the
seven Taskbar tools. The PSA tools remain in the bridge; discovery does not
query the key's role or scopes. This exact partial list is not a scope failure.

Immediate recovery on Chris's machine:

1. Tool Store > Tools > existing PSA Command connection > Check.
2. Review the new/changed PSA tools and accept them. Keep the connection ID and
   keys; do not remove and recreate it or rotate credentials for this symptom.
3. Confirm psa_connection, psa_team and psa_schools through read-only calls in
   the affected chat/bot. Confirm the scheduled routine still selects PSA Command.
4. Resume the next scheduled hand-off only after reviewing current task/school
   state. Do not replay missed writes automatically.

PSA Command 1.5.1 surfaces this condition in Account & setup, lists held PSA
names/descriptions, and offers an explicit human Enable reviewed PSA tools
button using Kairos's existing authenticated review endpoint. It does not
accept tools, change permissions, or run jobs automatically. Every 1.5.0 tool
fingerprint remains unchanged in this patch. No migration is required.

This release does not prove that Chris has accepted the held tools, that his
machine has installed the update, or that his scheduled hand-off succeeded.
Chris's read-only confirmation remains the final check.
