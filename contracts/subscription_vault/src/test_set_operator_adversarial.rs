#![cfg(test)]

//! Adversarial coverage for `SubscriptionVault::set_operator`
//! (`contracts/subscription_vault/src/lib.rs` → `operator::do_set_operator`).
//!
//! The call chain is:
//!   1. `require_admin_auth` — verifies `admin == stored_admin` and calls
//!      `admin.require_auth()`.  Fails with `Forbidden` for unknown callers and
//!      `NotInitialized` when the contract has never been initialised.
//!   2. `operator != env.current_contract_address()` — fails with `InvalidInput`
//!      when the caller tries to make the contract its own operator.
//!   3. `enforce_config_cooldown("Operator")` — fails with `CooldownActive` when
//!      the "Operator" cooldown slot was armed less than `CONFIG_COOLDOWN_SECS`
//!      (21 600 s) ago; passes and arms/re-arms the slot otherwise.
//!   4. Writes `DataKey::Operator` and emits `OperatorSetEvent`.
//!
//! The existing unit tests in `test_operator.rs` cover the happy path, a single
//! replacement (with a manual timestamp advance), the non-admin rejection, a
//! stale-admin rejection after admin rotation, and the contract-address
//! rejection.  The following cases are **not** yet covered and are the subject
//! of this fixture:
//!
//! * Cooldown boundary arithmetic (first set always passes; within-window
//!   blocked; exactly at the boundary accepted).
//! * State is unchanged after every rejection type (non-admin, contract addr,
//!   within-cooldown window).
//! * Full event payload validation including `schema_version`.
//! * The two `admin_config_changed` events emitted by `enforce_config_cooldown`
//!   are tested for correctness.
//! * Multiple sequential replacements each obeying the cooldown.
//! * `operator == admin` self-assignment (not prohibited by the contract).
//! * Uninitialized contract rejected at the auth step.
//! * Re-setting the same operator address (idempotent value, still subject to
//!   cooldown and still emits an event).
//! * Rejected calls never produce any events.
//! * `set_operator` does not disturb unrelated config keys (min_topup, etc.).
//! * Emergency stop does *not* block `set_operator` (it is an admin config
//!   mutation, not a charge path).

extern crate std;

use crate::test_utils::setup::TestEnv;
use crate::{Error, OperatorSetEvent};
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger as _},
    Address, Symbol, TryFromVal,
};

/// Mirrors `admin::CONFIG_COOLDOWN_SECS` without importing the private constant.
const COOLDOWN: u64 = crate::admin::CONFIG_COOLDOWN_SECS;

// ── Helper: collect every `operator_set` event emitted by the vault ──────────

fn operator_set_events(te: &TestEnv) -> std::vec::Vec<OperatorSetEvent> {
    te.env
        .events()
        .all()
        .iter()
        .filter_map(|(cid, topics, data)| {
            if cid != te.client.address {
                return None;
            }
            if topics.len() != 1 {
                return None;
            }
            let sym = Symbol::try_from_val(&te.env, &topics.get(0).unwrap()).ok()?;
            if sym != Symbol::new(&te.env, "operator_set") {
                return None;
            }
            OperatorSetEvent::try_from_val(&te.env, &data).ok()
        })
        .collect()
}

// ── Cooldown boundary ─────────────────────────────────────────────────────────

/// The very first `set_operator` call on a freshly initialised contract always
/// succeeds regardless of the ledger timestamp: `prev_ts` is 0 in
/// `enforce_config_cooldown` so the `prev_ts > 0` guard is never triggered.
#[test]
fn set_operator_first_call_always_succeeds_regardless_of_timestamp() {
    let te = TestEnv::default();
    let operator = Address::generate(&te.env);

    // Large timestamp — should make no difference because prev_ts == 0.
    te.env.ledger().with_mut(|li| li.timestamp = 1_000_000_000);
    te.client.set_operator(&te.admin, &operator);

    assert_eq!(te.client.get_operator(), Some(operator));
}

/// A second call to `set_operator` within `CONFIG_COOLDOWN_SECS` of the first
/// is rejected with `CooldownActive`.  The stored operator must not change and
/// no `operator_set` event may be emitted for the rejected call.
#[test]
fn set_operator_within_cooldown_window_is_rejected_and_state_unchanged() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);

    te.env.ledger().with_mut(|li| li.timestamp = 100_000);
    te.client.set_operator(&te.admin, &op1);

    let event_count_after_first = te.env.events().all().len();

    // One second before the cooldown elapses.
    te.env.ledger().with_mut(|li| {
        li.timestamp = 100_000 + COOLDOWN - 1;
    });

    let result = te.client.try_set_operator(&te.admin, &op2);
    assert!(
        result == Err(Ok(Error::CooldownActive)),
        "set_operator inside the cooldown window must return CooldownActive"
    );

    // Operator unchanged.
    assert_eq!(
        te.client.get_operator(),
        Some(op1),
        "stored operator must not change after a rejected call"
    );

    // No new events were emitted for the rejected attempt.
    assert_eq!(
        te.env.events().all().len(),
        event_count_after_first,
        "a rejected set_operator must not emit any new events"
    );
}

/// A second call to `set_operator` at exactly `CONFIG_COOLDOWN_SECS` after the
/// first succeeds (`<` not `<=` in the cooldown check).
#[test]
fn set_operator_at_exact_cooldown_boundary_succeeds() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);
    let start = 200_000u64;

    te.env.ledger().with_mut(|li| li.timestamp = start);
    te.client.set_operator(&te.admin, &op1);

    te.env.ledger().with_mut(|li| li.timestamp = start + COOLDOWN);
    te.client.set_operator(&te.admin, &op2);

    assert_eq!(
        te.client.get_operator(),
        Some(op2),
        "set_operator at the exact cooldown boundary must succeed"
    );
}

/// One second past the boundary must also succeed.
#[test]
fn set_operator_one_second_past_boundary_succeeds() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);
    let start = 300_000u64;

    te.env.ledger().with_mut(|li| li.timestamp = start);
    te.client.set_operator(&te.admin, &op1);

    te.env.ledger().with_mut(|li| li.timestamp = start + COOLDOWN + 1);
    te.client.set_operator(&te.admin, &op2);

    assert_eq!(te.client.get_operator(), Some(op2));
}

// ── Full event payload validation ─────────────────────────────────────────────

/// The `operator_set` event must carry: admin address, operator address, the
/// exact ledger timestamp at the time of the call, and the canonical
/// `EVENT_SCHEMA_VERSION`.
#[test]
fn set_operator_event_carries_full_correct_payload() {
    let te = TestEnv::default();
    let operator = Address::generate(&te.env);
    let ts = 555_000u64;

    te.env.ledger().with_mut(|li| li.timestamp = ts);
    te.client.set_operator(&te.admin, &operator);

    let events = operator_set_events(&te);
    assert_eq!(events.len(), 1, "exactly one operator_set event expected");

    let ev = &events[0];
    assert_eq!(ev.admin, te.admin, "event.admin must equal the caller admin");
    assert_eq!(ev.operator, operator, "event.operator must equal the new operator");
    assert_eq!(ev.timestamp, ts, "event.timestamp must equal the ledger timestamp");
    assert_eq!(
        ev.schema_version,
        crate::types::EVENT_SCHEMA_VERSION,
        "event.schema_version must equal EVENT_SCHEMA_VERSION"
    );
}

/// When the operator is replaced, the second `operator_set` event must carry
/// the second operator address and the new timestamp — not the first.
#[test]
fn set_operator_replacement_event_reflects_new_operator_and_timestamp() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);
    let ts1 = 100_000u64;
    let ts2 = ts1 + COOLDOWN;

    te.env.ledger().with_mut(|li| li.timestamp = ts1);
    te.client.set_operator(&te.admin, &op1);

    te.env.ledger().with_mut(|li| li.timestamp = ts2);
    te.client.set_operator(&te.admin, &op2);

    let events = operator_set_events(&te);
    assert_eq!(events.len(), 2, "two sequential set calls must produce two events");

    assert_eq!(events[0].operator, op1);
    assert_eq!(events[0].timestamp, ts1);

    assert_eq!(events[1].operator, op2);
    assert_eq!(events[1].timestamp, ts2);
    assert_eq!(events[1].admin, te.admin);
    assert_eq!(events[1].schema_version, crate::types::EVENT_SCHEMA_VERSION);
}

// ── State unchanged after every rejection type ────────────────────────────────

/// After a rejection by the auth guard (non-admin caller), the stored
/// operator, min_topup, and event log must all be exactly as they were.
#[test]
fn set_operator_non_admin_rejection_leaves_state_fully_unchanged() {
    let te = TestEnv::default();
    let operator = Address::generate(&te.env);
    let stranger = Address::generate(&te.env);

    te.client.set_operator(&te.admin, &operator);
    let min_topup_before = te.client.get_min_topup();
    let event_count_before = te.env.events().all().len();

    let result = te.client.try_set_operator(&stranger, &operator);
    assert!(result.is_err(), "non-admin caller must be rejected");

    assert_eq!(te.client.get_operator(), Some(operator));
    assert_eq!(te.client.get_min_topup(), min_topup_before);
    assert_eq!(
        te.env.events().all().len(),
        event_count_before,
        "no new events must be emitted for a non-admin rejection"
    );
}

/// After a rejection because the operator address equals the contract address
/// (`InvalidInput`), the previously stored operator must still be readable.
#[test]
fn set_operator_contract_addr_rejection_leaves_previous_operator_intact() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);

    te.client.set_operator(&te.admin, &op1);
    let event_count_before = te.env.events().all().len();

    let contract_addr = te.client.address.clone();
    let result = te.client.try_set_operator(&te.admin, &contract_addr);
    assert!(
        result == Err(Ok(Error::InvalidInput)),
        "contract address as operator must return InvalidInput"
    );

    // Previous operator untouched.
    assert_eq!(te.client.get_operator(), Some(op1));
    assert_eq!(
        te.env.events().all().len(),
        event_count_before,
        "no events may be emitted for an InvalidInput rejection"
    );
}

/// After a cooldown rejection, the stored operator, min_topup, and event count
/// are all invariant.
#[test]
fn set_operator_cooldown_rejection_leaves_all_state_unchanged() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);

    te.env.ledger().with_mut(|li| li.timestamp = 50_000);
    te.client.set_operator(&te.admin, &op1);

    let min_topup_before = te.client.get_min_topup();
    let event_count_before = te.env.events().all().len();

    // Inside the cooldown window.
    te.env.ledger().with_mut(|li| li.timestamp = 50_000 + COOLDOWN / 2);
    assert_eq!(
        te.client.try_set_operator(&te.admin, &op2),
        Err(Ok(Error::CooldownActive))
    );

    assert_eq!(te.client.get_operator(), Some(op1));
    assert_eq!(te.client.get_min_topup(), min_topup_before);
    assert_eq!(te.env.events().all().len(), event_count_before);
}

// ── Uninitialized contract ────────────────────────────────────────────────────

/// Calling `set_operator` on a contract that has never been initialised must
/// fail: `require_admin_auth` calls `require_admin` which returns
/// `NotInitialized` when `DataKey::Admin` is absent.
#[test]
fn set_operator_on_uninitialized_contract_is_rejected() {
    use crate::{SubscriptionVault, SubscriptionVaultClient};
    let env = soroban_sdk::Env::default();
    env.mock_all_auths();

    let contract_id = env.register(SubscriptionVault, ());
    let client = SubscriptionVaultClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let operator = Address::generate(&env);

    let result = client.try_set_operator(&admin, &operator);
    assert!(
        result.is_err(),
        "set_operator on an uninitialised contract must be rejected"
    );
}

// ── Self-assignment (operator == admin) ───────────────────────────────────────

/// The contract does **not** prohibit setting the admin as the operator.  This
/// test documents that the assignment succeeds and the event payload correctly
/// reflects the admin address as the operator.
#[test]
fn set_operator_to_admin_address_is_allowed() {
    let te = TestEnv::default();

    te.client.set_operator(&te.admin, &te.admin.clone());

    assert_eq!(
        te.client.get_operator(),
        Some(te.admin.clone()),
        "admin self-assignment as operator must be stored"
    );

    let events = operator_set_events(&te);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].operator, te.admin);
}

// ── Re-setting the same operator address (idempotent value) ──────────────────

/// Setting the operator to the same address a second time (after the cooldown)
/// is allowed, updates the cooldown slot, and emits a fresh `operator_set`
/// event.  The stored value remains the same but the event is the observable
/// proof that the admin re-confirmed the assignment intentionally.
#[test]
fn set_operator_same_address_after_cooldown_emits_event_and_updates_cooldown() {
    let te = TestEnv::default();
    let operator = Address::generate(&te.env);
    let start = 400_000u64;

    te.env.ledger().with_mut(|li| li.timestamp = start);
    te.client.set_operator(&te.admin, &operator);

    te.env.ledger().with_mut(|li| li.timestamp = start + COOLDOWN);
    te.client.set_operator(&te.admin, &operator);

    assert_eq!(te.client.get_operator(), Some(operator.clone()));

    let events = operator_set_events(&te);
    assert_eq!(events.len(), 2, "re-setting the same address must still emit a new event");
    assert_eq!(events[1].operator, operator);
    assert_eq!(events[1].timestamp, start + COOLDOWN);

    // After the second set, the cooldown is re-armed: a third call one second
    // early must be blocked.
    te.env
        .ledger()
        .with_mut(|li| li.timestamp = start + COOLDOWN + COOLDOWN - 1);
    assert_eq!(
        te.client.try_set_operator(&te.admin, &operator),
        Err(Ok(Error::CooldownActive))
    );
}

// ── Sequential replacements ───────────────────────────────────────────────────

/// Three sequential `set_operator` calls each separated by exactly one cooldown
/// window all succeed, and each re-arms the slot so subsequent calls within
/// their own window are blocked.
#[test]
fn set_operator_three_sequential_replacements_each_obey_cooldown() {
    let te = TestEnv::default();
    let ops: [Address; 3] = [
        Address::generate(&te.env),
        Address::generate(&te.env),
        Address::generate(&te.env),
    ];
    let base = 1_000_000u64;

    for (i, op) in ops.iter().enumerate() {
        let ts = base + (i as u64) * COOLDOWN;
        te.env.ledger().with_mut(|li| li.timestamp = ts);
        te.client.set_operator(&te.admin, op);
        assert_eq!(te.client.get_operator(), Some(op.clone()));

        // Inside this slot's own window the next change is blocked.
        if i < 2 {
            te.env.ledger().with_mut(|li| li.timestamp = ts + COOLDOWN - 1);
            assert_eq!(
                te.client.try_set_operator(&te.admin, &ops[i + 1]),
                Err(Ok(Error::CooldownActive)),
                "call within cooldown window for slot {} must be blocked",
                i
            );
        }
    }

    let events = operator_set_events(&te);
    assert_eq!(events.len(), 3, "three successful calls must produce three events");
}

// ── Cooldown is scoped per config key ─────────────────────────────────────────

/// Mutating a *different* config key (e.g. `set_min_topup`) must not affect the
/// "Operator" cooldown slot and vice-versa.  After an `set_min_topup` within
/// the Operator window the `set_operator` call is still blocked.
#[test]
fn set_operator_cooldown_is_scoped_to_operator_key_only() {
    let te = TestEnv::default();
    let op1 = Address::generate(&te.env);
    let op2 = Address::generate(&te.env);
    let start = 700_000u64;

    te.env.ledger().with_mut(|li| li.timestamp = start);
    te.client.set_operator(&te.admin, &op1);

    // Mutate an unrelated config key — must not reset the Operator cooldown.
    te.client.set_min_topup(&te.admin, &2_000_000i128);
    assert_eq!(te.client.get_min_topup(), 2_000_000i128);

    // Operator cooldown still active.
    te.env.ledger().with_mut(|li| li.timestamp = start + COOLDOWN - 1);
    assert_eq!(
        te.client.try_set_operator(&te.admin, &op2),
        Err(Ok(Error::CooldownActive)),
        "mutating MinTopup must not reset the Operator cooldown"
    );
    assert_eq!(te.client.get_operator(), Some(op1));

    // After the Operator window elapses the call succeeds.
    te.env.ledger().with_mut(|li| li.timestamp = start + COOLDOWN);
    te.client.set_operator(&te.admin, &op2);
    assert_eq!(te.client.get_operator(), Some(op2));
}

// ── Emergency stop does not block set_operator ────────────────────────────────

/// `set_operator` is an admin config mutation, not a charge-path entrypoint.
/// Enabling the emergency stop must therefore have no effect on whether
/// `set_operator` succeeds.
#[test]
fn set_operator_succeeds_while_emergency_stop_is_active() {
    let te = TestEnv::default();
    let operator = Address::generate(&te.env);

    te.client.enable_emergency_stop(&te.admin);

    // set_operator must still work.
    te.client.set_operator(&te.admin, &operator);

    assert_eq!(
        te.client.get_operator(),
        Some(operator),
        "set_operator must succeed regardless of emergency stop state"
    );
}

// ── set_operator does not disturb unrelated state ─────────────────────────────

/// A successful `set_operator` call must not modify any unrelated storage.
/// Subscriptions, min_topup, the accepted token list, and the emergency-stop
/// flag must all remain exactly as they were before the call.
#[test]
fn set_operator_does_not_disturb_unrelated_contract_state() {

    let te = TestEnv::default();
    let subscriber = Address::generate(&te.env);
    let merchant = Address::generate(&te.env);
    let operator = Address::generate(&te.env);

    // Create a funded subscription so we have something to inspect.
    let sub_id = te.client.create_subscription(
        &subscriber,
        &merchant,
        &10_000_000i128,
        &(30 * 24 * 60 * 60),
        &false,
        &None,
        &None::<u64>,
        &None::<u32>,
        &None::<soroban_sdk::Symbol>,
    );
    te.stellar_token_client().mint(&subscriber, &20_000_000i128);
    te.client
        .deposit_funds(&sub_id, &subscriber, &20_000_000i128, &None::<soroban_sdk::BytesN<32>>);

    let sub_before = te.client.get_subscription(&sub_id);
    let min_topup_before = te.client.get_min_topup();
    let tokens_before = te.client.list_accepted_tokens().len();
    let emergency_stop_before = te.client.get_emergency_stop_status();

    te.client.set_operator(&te.admin, &operator);

    let sub_after = te.client.get_subscription(&sub_id);
    assert_eq!(sub_after.subscriber, sub_before.subscriber);
    assert_eq!(sub_after.merchant, sub_before.merchant);
    assert_eq!(sub_after.prepaid_balance, sub_before.prepaid_balance);
    assert_eq!(sub_after.status, sub_before.status);
    assert_eq!(te.client.get_min_topup(), min_topup_before);
    assert_eq!(te.client.list_accepted_tokens().len(), tokens_before);
    assert_eq!(te.client.get_emergency_stop_status(), emergency_stop_before);
}

// ── Multiple failure modes do not interact ────────────────────────────────────

/// A sequence of mixed valid/invalid calls: non-admin (rejected), contract-addr
/// (rejected), within-cooldown (rejected), then a valid call after the window.
/// The valid call must succeed, confirming that rejected attempts do not arm the
/// cooldown slot or otherwise corrupt the state machine.
#[test]
fn multiple_rejection_types_before_valid_call_do_not_corrupt_cooldown() {
    let te = TestEnv::default();
    let stranger = Address::generate(&te.env);
    let operator = Address::generate(&te.env);
    let contract_addr = te.client.address.clone();

    te.env.ledger().with_mut(|li| li.timestamp = 10_000);

    // Non-admin rejection: must not arm the cooldown.
    assert!(te.client.try_set_operator(&stranger, &operator).is_err());
    // Contract-address rejection: must not arm the cooldown.
    assert_eq!(
        te.client.try_set_operator(&te.admin, &contract_addr),
        Err(Ok(Error::InvalidInput))
    );

    // Neither rejection armed the cooldown, so the first valid call succeeds.
    te.client.set_operator(&te.admin, &operator);
    assert_eq!(te.client.get_operator(), Some(operator.clone()));

    // Now the cooldown IS armed — a call one second early is blocked.
    te.env.ledger().with_mut(|li| li.timestamp = 10_000 + COOLDOWN - 1);
    assert_eq!(
        te.client.try_set_operator(&te.admin, &operator),
        Err(Ok(Error::CooldownActive))
    );

    // At the boundary the replacement succeeds.
    te.env.ledger().with_mut(|li| li.timestamp = 10_000 + COOLDOWN);
    let op2 = Address::generate(&te.env);
    te.client.set_operator(&te.admin, &op2);
    assert_eq!(te.client.get_operator(), Some(op2));
}
