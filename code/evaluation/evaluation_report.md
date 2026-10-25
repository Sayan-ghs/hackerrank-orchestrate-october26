# Evaluation Report

## Final full-dataset run

The final run was executed with:

```text
python code/main.py
```

The generated `dataset/output.csv` contains 518 data rows (plus the header), sorted by the numeric case suffix. Every `steps_json` value parses as an array, and every non-empty array has consecutive `step_no` values beginning at 1.

Structural results:

| Check | Result |
| --- | ---: |
| Input cases | 518 |
| Output data rows | 518 |
| `NOT_APPLICABLE` rows | 2 |
| `COMPLETE` rows | 356 |
| `INCOMPLETE` rows | 160 |
| Parsed step objects | 882 |
| Blank `system_id` values | 0 |
| Non-consecutive step sequences | 0 |

The hidden canonical full-dataset answer is not included in the participant workspace, so hidden case/field accuracy cannot be measured locally. The reported counts above are reproducible contract and self-consistency checks, not claims of hidden-set accuracy.

## Accuracy dimensions

The implementation reports the following dimensions during review:

- **Case-level status accuracy:** status is derived from policy-relevant observations at or before `audit_at`, never from `reported_status`.
- **Step-level accuracy:** each finding maps to one allowed remediation and desired post-remediation state.
- **Field-level accuracy:** emitted fields are restricted to the required schema and allowed operation/state combinations.
- **Sequence accuracy:** findings, remediation, and verification are emitted in phase order; operations use the problem-statement order and then `system_id`/`resource_id`.

## Additional team-created evaluation cases

These are deterministic regression cases represented by the supplied evidence and exercised by the same engine:

1. **Historical email resolution:** an email in a deletion request is an `old_value` in `user_audit_log.csv`; the current user identity and all aliases are used for matching.
2. **Shared support conversation:** a support message containing shared order/customer context is retained and planned for `REDACT_RECORD`, not deletion.
3. **Recreation risk:** an active integration `DATA_FLOW` is reported, disabled in remediation, and checked with `VERIFY_DATA_FLOW_DISABLED`.
4. **Restore risk:** an active `BACKUP_ARCHIVE` is reported, blocked in remediation, and checked with `VERIFY_RESTORE_BLOCKED`.

## Failures found and improvements made

- The starter solver was empty, so the first implementation added CSV loading, identity alias resolution, evidence manifest resolution, recursive JSON extraction, SQLite snapshot extraction, text/log parsing, and activity reconciliation.
- Initial extraction preserved SQL table names as systems; this was corrected by normalizing resource prefixes to canonical service IDs.
- Log readbacks represented absence as `rows=0`/HTTP 404 rather than the literal `NOT_FOUND`; these conditions are now normalized to `ABSENT`.
- Multilingual deletion templates did not contain English deletion keywords. Request authorization now defaults to the deletion queue semantics and explicitly excludes the two refusal templates (“not asking for deletion” and “do not close the account”).
- Output validation was added for row count, ordering, JSON parsing, system identifiers, and step numbering.
