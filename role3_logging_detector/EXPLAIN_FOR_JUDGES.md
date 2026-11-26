# How to Explain Your Part (Role 3) to Judges — Simple Cheat Sheet

Use these plain-English answers during Stage 2 Q&A:

### 1. Log Integrity ("How do you stop log tampering or log injection?")
* **Log Injection:** Every log line is stored as strict JSON (`.jsonl`), and we strip newlines/control characters from user text (`sanitize_text`). That means user input can never create a fake second log line or change the `actor_id`.
* **Tamper-Evidence:** Each line stores `prev_hash` (the SHA-256 hash of the previous line) and its own `entry_hash`. If anyone edits or deletes even one character, `verify-logs` catches the exact broken line.

### 2. Routine vs. Suspicious Activity ("How do you tell an admin apart from an attacker without AI?")
* We use **deterministic rules** (no AI/ML). A privilege change with a valid `ticket_id` + `mfa_verified: true` is treated as routine; a privilege jump or `bulk_export` without approval triggers an alert.
* We measure accuracy with `evaluate`, which outputs **F1**, **Median Time to Alert (MTTA)**, and **False Alerts per 1,000 benign events**.

### 3. Lateral Movement ("How do you catch attackers with valid credentials?")
* Even if an account's credentials are valid, our detector tracks a **per-identity service graph** over a 5-minute window (e.g., `auth-gateway -> msg-relay -> backup-store`).
* If an identity hops between services on a disallowed path, it raises a `lateral_movement` alert showing the **identity, services, event IDs, and exact path rule**.

### 4. Clock Differences ("What if logs arrive out of order?")
* We buffer and sort events using a **±30s clock-skew window** (`max_skew_seconds=30`).
* If two events for the same user arrive out of order within that uncertainty window (`2 × max_skew`), we still analyze them and mark `order_uncertain: true` on the alert so operators know ordering was ambiguous.

### 5. How XERJ Fits In
* Every verified log record and alert is optionally pushed to our local **XERJ** node (`track4-audit` and `track4-alerts` indices on `127.0.0.1:9200`) so operators and teammates can search incidents in milliseconds.
