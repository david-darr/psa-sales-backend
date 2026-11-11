# November 12 campaign launch

Read-only production audit November 11: four current unapproved plans, 175 eligible intro emails, 08:00-16:00 America/New_York, follow-ups on days 4/11/18, end December 18. Daily caps sum to 102; the shared standard campaign limit is 150. Three older plans are cancelled. Current previews are expired and must be refreshed before approval. Do not restore cancelled plans. The five-minute due-work clock is active and the web sending worker reports online.

Campaign automation remains off. The person must perform one controlled internal delivery test and confirm recipient, rendered text, PDFs, recorded result and no duplicates. Use the sending employee's own account. SMTP acceptance alone is not evidence of inbox delivery. A self-test checks that mailbox and queue, but campaign scheduling still requires checking the actual plan window and approval.

After receipt confirmation, enable CAMPAIGN_AUTOMATION_ENABLED=true on Render and redeploy. Refresh/review current plans after all template/contact edits, then the sender approves them privately. Verify automation_enabled=true, valid delegated key, connected mailbox, 102/day intent (or explicitly revise caps), approved state, correct Eastern window and healthy worker. Do not approve campaigns with SQL or an AI key. Monitor the first group and retain pause/kill controls.

School suppression release requires 20261111_school_contact_suppression.sql before backend code. Existing global opt-outs remain global, local flags default false, and no approved content is rewritten. Suspect UTF-8 corruption is rejected with a repair instruction rather than automatically changing the wording. The current saved templates did not contain the reported U+00C2/U+00B7 pair at audit time.
