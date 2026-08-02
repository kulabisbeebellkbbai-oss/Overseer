# Overseer project guard

The user-scoped Codex guard requires authoritative evidence after completed
shared-resource work. Record evidence is accepted only when the record exists
in the live Overseer store and all required fields exactly match.

Use one JSON object per final-answer line:

```text
Overseer evidence: {"record_type":"crew_message","record_id":"crew.kira.example","expected":{"owner_domain":"kira","status":"acknowledged","review_status":"approved","requested_by":"Roadex"}}
```

Supported record types are `crew_message`, `admin_plan`, `claim`,
`usage_continuation`, `backup_provisioning_plan`, and
`storage_root_authorization`. The hook reports missing required fields rather
than accepting a weak partial assertion.

The guard fails closed when a record is missing, its expected fields differ,
the store is unavailable, or evidence is supplied only as prose/tool output.
Distinct hook attempts repeating the same rejected claim create one
deduplicated Odo risk-assessment message. Re-running the same Stop event is
idempotent and does not increase the occurrence count.

Install or refresh the user-scoped copy with:

```bash
python3 scripts/install_overseer_project_guard.py
```

After installing a non-managed hook, review and trust it with `/hooks`.
