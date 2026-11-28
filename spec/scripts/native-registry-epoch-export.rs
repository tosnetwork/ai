// Append this test to the Registry epoch sandbox module in a disposable copy.
// The fixture, builders and transactions all come from the pinned sandbox.
#[test]
fn export_registry_epoch_protocol_vectors() {
    use base64::Engine;
    use serde_json::{Value, json};

    let path = std::env::var("NATIVE_REGISTRY_PROTOCOL_VECTORS_OUT")
        .expect("set the output path for the epoch vector export");
    let mut f = Fixture::new();
    let key = f.old_key.clone();
    let mut states = serde_json::Map::new();
    let mut steps = Vec::new();
    let boc = |cell: &Cell| {
        let mut bytes = Vec::new();
        chain_block::BocWriter::with_flags([cell.clone()], chain_block::BocFlags::Crc32)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let hash = |cell: &Cell| hex::encode(cell.hash(0).as_slice());
    let mut state = |f: &Fixture| {
        let cell = f.state();
        let hash = hash(&cell);
        let (epoch, live, total) = f.counts();
        states.entry(hash.clone()).or_insert_with(
            || json!({"boc": boc(&cell), "epoch": epoch, "live": live, "total": total}),
        );
        hash
    };
    let mut step = |f: &mut Fixture,
                    name: &str,
                    action: &Cell,
                    input: Value,
                    possession: &[&RegistryKey],
                    expected: i32| {
        let before = state(f);
        let result = f.submit(action, &[&key], possession);
        let vm = gas_at(&result, &f.registry);
        assert_eq!(vm.exit, expected, "{name}");
        assert_eq!(vm.aborted, expected != 0, "{name}");
        let after = state(f);
        steps.push(json!({
            "name": name,
            "input": input,
            "action_boc": boc(action),
            "action_hash": hash(action),
            "before": before,
            "after": after,
            "exit": vm.exit,
            "out_messages": out_messages(&result, &f.registry),
        }));
    };
    let a = [0xa1; 32];
    let b = [0xb1; 32];
    let c = [0xc1; 32];
    let mut run =
        |f: &mut Fixture, name: &str, kind: u8, digest: &[u8; 32], epoch: u64, exit: i32| {
            let action = f.next_action(kind, delegation_payload(digest, epoch));
            let (generation, sequence) = f.state_position();
            let sequence = sequence + 1;
            let input = json!({"kind": kind, "digest": hex::encode(digest), "expected_epoch": epoch,
            "generation": generation, "sequence": sequence, "nonce": (sequence % 250) as u8 + 1});
            step(f, name, &action, input.clone(), &[], exit);
            (action, input)
        };
    run(&mut f, "add-a", DELEGATE_AGENT, &a, 1, 0);
    run(&mut f, "add-b", DELEGATE_AGENT, &b, 1, 0);
    let (withdrawal, withdrawal_input) = run(&mut f, "withdraw-a", WITHDRAW_DELEGATION, &a, 1, 0);
    run(
        &mut f,
        "readd-withdrawn-a",
        DELEGATE_AGENT,
        &a,
        1,
        ERR_WITHDRAWN_DIGEST,
    );
    run(
        &mut f,
        "withdraw-absent-c",
        WITHDRAW_DELEGATION,
        &c,
        1,
        ERR_DIGEST_NOT_LIVE,
    );
    run(
        &mut f,
        "withdraw-b-wrong-epoch",
        WITHDRAW_DELEGATION,
        &b,
        2,
        ERR_EPOCH_MISMATCH,
    );
    step(
        &mut f,
        "replay-withdrawal",
        &withdrawal,
        withdrawal_input,
        &[],
        0,
    );

    let mut payload = BuilderData::new();
    payload.checked_append_reference(policy(&key)).unwrap();
    let update = f.next_action(UPDATE_AGENT_POLICY, payload.into_cell().unwrap());
    let (generation, sequence) = f.state_position();
    let sequence = sequence + 1;
    step(
        &mut f,
        "identical-policy-bump",
        &update,
        json!({
            "kind": UPDATE_AGENT_POLICY, "generation": generation, "sequence": sequence, "nonce": (sequence % 250) as u8 + 1,
        }),
        &[&key],
        0,
    );
    let output = json!({
        "schema": "tos.service.registry.v2.epoch.vectors",
        "contract_code_hash": format!("tvm-cell-sha256:{}", hash(&f.contract_code)),
        "network": {
            "network_id": "tos-testnet",
            "genesis_root_hash": format!("sha256:{}", "11".repeat(32)),
            "genesis_file_hash": format!("sha256:{}", "22".repeat(32)),
        },
        "agent_id": format!("agent_{}", hex::encode(f.object_id)),
        "states": states,
        "steps": steps,
    });
    std::fs::write(path, serde_json::to_string_pretty(&output).unwrap() + "\n").unwrap();
}
