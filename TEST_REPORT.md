# SecureLog test report

Generated 2026-11-16 11:43 on Windows 10, Python 3.11.3.

## Test suites

| Suite | Result | Time |
|---|---|---|
| Ledger security (hash chain, HMAC, Merkle, seals, forward security, time sealing) | ✅ 20/20 passed | 8.3 s |
| Authentication (passwords, tokens, agent keys, lockout) | ✅ 12/12 passed | 4.1 s |
| Agent heartbeats, silence and rollback detection | ✅ 9/9 passed | 4.7 s |
| Attack detection rules (brute force, sudo, backdoor, log wiping, port scan) | ✅ 18/18 passed | 6.1 s |
| Dashboard statistics and integrity monitor | ✅ 6/6 passed | 8.0 s |
| Ubuntu agent (log parsing, no-loss queue, witness) | skipped on Windows (run on Ubuntu) | - |

**Total: 65/65 tests passed.**

## Attack detection matrix

Each attack edits the SQLite database directly, the way a real attacker would.

| # | Attack | Server check | Auditor (K0) | Evidence | Note |
|---|---|---|---|---|---|
| 1 | Edit one log's message directly in the database | ✅ Detected | ✅ Detected | content_hash, mac |  |
| 2 | Change the attacker's IP address in a log | ✅ Detected | ✅ Detected | content_hash, mac |  |
| 3 | Change which machine a log came from (agent_id) | ✅ Detected | ✅ Detected | content_hash, mac |  |
| 4 | Back-date a log's timestamp | ✅ Detected | ✅ Detected | content_hash, mac |  |
| 5 | Swap the contents of two logs (reorder events) | ✅ Detected | ✅ Detected | content_hash, mac |  |
| 6 | Delete one log from a sealed batch | ✅ Detected | ✅ Detected | batch_range, chain_link, merkle_root |  |
| 7 | Insert a fake log into a sealed batch | ✅ Detected | ✅ Detected | batch_order, batch_range, chain_link, content_hash, mac, merkle_root |  |
| 8 | Replace a sealed Merkle root | ✅ Detected | ✅ Detected | merkle_root, seal |  |
| 9 | Delete the newest sealed batch (logs + root) | ✅ Detected | ✅ Detected | chain_link, orphan_batch, seal_records_missing | server refuses new writes |
| 10 | Edit a log and recompute all public hashes and roots (no key) | ✅ Detected | ✅ Detected | mac, seal | open-batch HMACs break |
| 11 | Same rewrite, when every log is already sealed (no key) | ❌ Not detected | ✅ Detected | mac, seal | only the auditor's seals catch it |
| 12 | Steal the CURRENT key, rewrite an OLD batch and re-sign everything | ❌ Not detected | ✅ Detected | mac, seal | forward security: old keys are gone |
| 13 | Steal the current key and rewrite the OPEN (unsealed) batch | ❌ Not detected | ❌ Not detected | - | limitation: open batch (time sealing limits it to 10 min) |
| 14 | Delete the newest logs of the open batch | ❌ Not detected | ❌ Not detected | - | limitation: open batch (time sealing limits it to 10 min) |

12 of 14 attacks detected. The 2 undetected ones are the documented limitations of the open (unsealed) batch.
Ran in 11.8 s. All results as expected.

## Full test output

### Ledger security (hash chain, HMAC, Merkle, seals, forward security, time sealing)

```
PASS  test_agent_identity_is_protected
PASS  test_careless_edit_detected
PASS  test_clean_log_is_valid_everywhere
PASS  test_crash_between_seal_commit_and_key_evolution_recovers
PASS  test_deleting_log_from_sealed_batch_detected
PASS  test_deleting_whole_last_sealed_batch_detected
PASS  test_event_time_is_protected_and_normalised_to_utc
PASS  test_forged_merkle_root_detected
PASS  test_key_evolution_is_forward_only
PASS  test_known_limitation_open_batch_tail_truncation
PASS  test_merkle_no_duplicate_leaf_ambiguity
PASS  test_merkle_proofs_all_sizes
PASS  test_proof_endpoint_logic
PASS  test_rewrite_attack_detected_by_server_when_open_batch_has_logs
PASS  test_rewrite_attack_on_sealed_data_only_caught_by_auditor
PASS  test_secret_key_never_in_public_state
PASS  test_server_events_go_into_the_ledger
PASS  test_stolen_current_key_cannot_forge_old_batches
PASS  test_time_based_sealing
PASS  test_time_based_sealing_with_waiting_logs_is_race_free

20/20 passed
```

### Authentication (passwords, tokens, agent keys, lockout)

```
PASS  test_admin_credentials
PASS  test_agent_keys
PASS  test_alg_none_token_rejected
PASS  test_expired_token_rejected
PASS  test_lockout_expires
PASS  test_login_lockout
PASS  test_logout_revokes_token
PASS  test_manage_init_creates_working_env
PASS  test_password_hash_and_verify
PASS  test_tampered_token_rejected
PASS  test_token_roundtrip
PASS  test_token_signed_with_other_secret_rejected

12/12 passed
```

### Agent heartbeats, silence and rollback detection

```
PASS  test_first_heartbeat_registers_agent
PASS  test_forged_seal_detected
PASS  test_honest_server_never_alerts
PASS  test_list_includes_registered_but_never_seen
PASS  test_recent_heartbeat_is_not_silent
PASS  test_rollback_of_database_and_key_detected_once
PASS  test_rollback_of_database_only_detected
PASS  test_silent_agent_alerts_once
PASS  test_stop_and_return

9/9 passed
```

### Attack detection rules (brute force, sudo, backdoor, log wiping, port scan)

```
PASS  test_backdoor_admin_account
PASS  test_brute_force_then_success_is_critical
PASS  test_different_ips_are_separate
PASS  test_late_delivery_uses_original_event_time
PASS  test_log_wiping_commands
PASS  test_normal_group_change_is_not_an_alert
PASS  test_normal_login_is_not_an_alert
PASS  test_normal_sudo_is_not_an_alert
PASS  test_one_wrong_sudo_password_is_not_an_alert
PASS  test_port_scan
PASS  test_real_ubuntu_ssh_one_connection_is_not_brute_force
PASS  test_real_ubuntu_ssh_two_connections_is_brute_force
PASS  test_real_ubuntu_sudo_three_wrong_passwords
PASS  test_repeated_hits_on_one_port_are_not_a_scan
PASS  test_server_events_are_ignored_and_detector_starts_at_now
PASS  test_slow_failures_are_not_brute_force
PASS  test_ssh_brute_force
PASS  test_sudo_password_guessing

18/18 passed
```

### Dashboard statistics and integrity monitor

```
PASS  test_monitor_caches_its_result
PASS  test_monitor_check_is_race_free_while_logs_arrive
PASS  test_monitor_raises_one_alert_per_incident
PASS  test_search_and_filter_logic
PASS  test_severity_rule_covers_all_event_types
PASS  test_stats_count_all_logs_not_just_loaded_ones

6/6 passed
```
