
/// Module: suicircle
// module suicircle::suicircle;
module suicircle::suicircle {
    use sui::event;
    use sui::clock::{Self, Clock};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};
    use std::string::{Self, String};

    // Error codes
    const E_NOT_AUTHORIZED: u64 = 0;
    const E_TRANSFER_NOT_FOUND: u64 = 1;
    const E_INVALID_RECIPIENT: u64 = 2;
    const E_TRANSFER_EXPIRED: u64 = 3;
    const E_INSUFFICIENT_GAS_FEE: u64 = 4;
    const E_ALREADY_CLAIMED: u64 = 5;
    const E_INVALID_SEAL_KEY: u64 = 6;
    const E_TRANSFER_CANCELLED: u64 = 7;

    // Transfer status enum
    const STATUS_PENDING: u8 = 0;
    const STATUS_CLAIMED: u8 = 1;
    const STATUS_EXPIRED: u8 = 2;
    const STATUS_CANCELLED: u8 = 3;

    // File transfer struct - core of suiCircle protocol
    public struct FileTransfer has key, store {
        id: UID,
        encrypted_cid: String, // Seal-encrypted content identifier
        metadata_cid: String, // Encrypted metadata (filename, size, type) Wallrus
        sender: address,
        recipient: address,
        created_at: u64,
        expires_at: Option<u64>,
        seal_public_key: vector<u8>,
        encryption_algorithm: String,
        transfer_message: String,
        file_count: u64,
        total_size: u64,
        status: u8,
        access_conditions: Option<AccessCondition>,
        gas_fee_paid: u64,
    }

    // Access conditions for advanced gating
    public struct AccessCondition has store, drop {
        condition_type: String,
        token_address: Option<address>,
        minimum_amount: u64,
        additional_data: vector<u8>,
    }

    // Global protocol statistics and fee collection
    public struct ProtocolStats has key {
        id: UID,
        total_transfers: u64,
        total_data_transferred: u64,
        gas_fees_collected: Balance<SUI>,
        protocol_fee_rate: u64,
        admin: address,
    }

    // User activity tracking
    public struct UserActivity has key, store {
        id: UID,
        user: address,
        transfers_sent: u64,
        transfers_received: u64,
        total_data_sent: u64,
        total_data_received: u64,
        last_activity: u64,
    }

    // Events
    public struct TransferInitiated has copy, drop {
        transfer_id: address,
        sender: address,
        recipient: address,
        encrypted_cid: String,
        file_count: u64,
        total_size: u64,
        expires_at: Option<u64>,
        gas_fee: u64,
        timestamp: u64,
    }

    public struct TransferClaimed has copy, drop {
        transfer_id: address,
        recipient: address,
        claimed_at: u64,
    }

    public struct TransferCancelled has copy, drop {
        transfer_id: address,
        sender: address,
        cancelled_at: u64,
    }

    public struct GasFeesCollected has copy, drop {
        transfer_id: address,
        fee_amount: u64,
        protocol_fee: u64,
        timestamp: u64,
    }

    // Initialize protocol
    fun init(ctx: &mut TxContext) {
        let stats = ProtocolStats {
            id: object::new(ctx),
            total_transfers: 0,
            total_data_transferred: 0,
            gas_fees_collected: balance::zero(),
            protocol_fee_rate: 100, // 1% protocol fee
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(stats);
    }

    // Send files with Seal encryption and wallet-based access
    public entry fun send_files(
        stats: &mut ProtocolStats,
        encrypted_cid: vector<u8>,
        metadata_cid: vector<u8>,
        recipient: address,
        seal_public_key: vector<u8>,
        encryption_algorithm: vector<u8>,
        transfer_message: vector<u8>,
        file_count: u64,
        total_size: u64,
        expires_in_hours: Option<u64>,
        mut gas_fee: Coin<SUI>, // Pass by value to consume the coin
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let timestamp = clock::timestamp_ms(clock);

        // Calculate expiry time
        let expires_at = if (option::is_some(&expires_in_hours)) {
            let hours = *option::borrow(&expires_in_hours);
            option::some(timestamp + (hours * 3600 * 1000))
        } else {
            option::none()
        };

        // Process gas fee
        let gas_amount = coin::value(&gas_fee);
        assert!(gas_amount > 0, E_INSUFFICIENT_GAS_FEE);
        let protocol_fee = (gas_amount * stats.protocol_fee_rate) / 10000;
        let protocol_fee_coin = coin::split(&mut gas_fee, protocol_fee, ctx);
        balance::join(&mut stats.gas_fees_collected, coin::into_balance(protocol_fee_coin));

        // Return remaining gas to sender
        transfer::public_transfer(gas_fee, sender);

        // Create transfer object
        let transfer_id = object::new(ctx);
        let transfer_addr = object::uid_to_address(&transfer_id);
        let file_transfer = FileTransfer {
            id: transfer_id,
            encrypted_cid: string::utf8(encrypted_cid),
            metadata_cid: string::utf8(metadata_cid),
            sender,
            recipient,
            created_at: timestamp,
            expires_at,
            seal_public_key,
            encryption_algorithm: string::utf8(encryption_algorithm),
            transfer_message: string::utf8(transfer_message),
            file_count,
            total_size,
            status: STATUS_PENDING,
            access_conditions: option::none(),
            gas_fee_paid: gas_amount,
        };

        // Update protocol statistics
        stats.total_transfers = stats.total_transfers + 1;
        stats.total_data_transferred = stats.total_data_transferred + total_size;

        // Update sender activity
        update_user_activity(sender, true, total_size, timestamp, ctx);

        // Share transfer object
        transfer::share_object(file_transfer);

        // Emit transfer initiated event
        event::emit(TransferInitiated {
            transfer_id: transfer_addr,
            sender,
            recipient,
            encrypted_cid: string::utf8(encrypted_cid),
            file_count,
            total_size,
            expires_at,
            gas_fee: gas_amount,
            timestamp,
        });
    }

    // Claim files
    public entry fun claim_transfer(
        transfer: &mut FileTransfer,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let claimer = tx_context::sender(ctx);
        let timestamp = clock::timestamp_ms(clock);

        assert!(transfer.recipient == claimer, E_NOT_AUTHORIZED);
        assert!(transfer.status == STATUS_PENDING, E_ALREADY_CLAIMED);

        if (option::is_some(&transfer.expires_at)) {
            let expiry = *option::borrow(&transfer.expires_at);
            assert!(timestamp <= expiry, E_TRANSFER_EXPIRED);
        };

        if (option::is_some(&transfer.access_conditions)) {
            let condition = option::borrow(&transfer.access_conditions);
            verify_access_condition(condition, claimer);
        };

        transfer.status = STATUS_CLAIMED;

        update_user_activity(claimer, false, transfer.total_size, timestamp, ctx);

        event::emit(TransferClaimed {
            transfer_id: object::uid_to_address(&transfer.id),
            recipient: claimer,
            claimed_at: timestamp,
        });
    }

    // Cancel transfer
    // public entry fun cancel_transfer(
    //     transfer: &mut FileTransfer,
    //     clock: &Clock,
    //     ctx: &mut TxContext
    // ) {
    //     let canceller = tx_context::sender(ctx);
    //     let timestamp = clock::timestamp_ms(clock);

    //     assert!(transfer.sender == canceller, E_NOT_AUTHORIZED);
    //     assert!(transfer.status == STATUS_PENDING, E_TRANSFER_CANCELLED);

    //     transfer.status = STATUS_CANCELLED;
    //     event::emit(TransferCancelled {
    //         transfer_id: object::uid_to_address(&transfer.id),
    //         sender: canceller,
    //         cancelled_at: timestamp,
    //     });
    // }

    // Verify access conditions
    fun verify_access_condition(condition: &AccessCondition, user: address) {
        // Placeholder: NFT ownership, or DAO membership
    }

    // Update user activity
    fun update_user_activity(
        user: address,
        is_sender: bool,
        data_size: u64,
        timestamp: u64,
        ctx: &mut TxContext
    ) {
        let activity = UserActivity {
            id: object::new(ctx),
            user,
            transfers_sent: if (is_sender) 1 else 0,
            transfers_received: if (is_sender) 0 else 1,
            total_data_sent: if (is_sender) data_size else 0,
            total_data_received: if (is_sender) 0 else data_size,
            last_activity: timestamp,
        };
        transfer::transfer(activity, user);
    }

    // View functions
    public fun get_transfer_info(transfer: &FileTransfer): (
        String, String, address, address, u64, Option<u64>, u8, u64, u64, u64
    ) {
        (
            transfer.encrypted_cid,
            transfer.metadata_cid,
            transfer.sender,
            transfer.recipient,
            transfer.created_at,
            transfer.expires_at,
            transfer.status,
            transfer.file_count,
            transfer.total_size,
            transfer.gas_fee_paid
        )
    }

    public fun get_seal_info(transfer: &FileTransfer, ctx: &TxContext): (
        vector<u8>, String
    ) {
        assert!(
            transfer.recipient == tx_context::sender(ctx) ||
            transfer.sender == tx_context::sender(ctx),
            E_NOT_AUTHORIZED
        );
        (transfer.seal_public_key, transfer.encryption_algorithm)
    }

    public fun get_protocol_stats(stats: &ProtocolStats): (u64, u64, u64, u64) {
        (
            stats.total_transfers,
            stats.total_data_transferred,
            balance::value(&stats.gas_fees_collected),
            stats.protocol_fee_rate
        )
    }

    public fun can_claim_transfer(transfer: &FileTransfer, user: address, timestamp: u64): bool {
        if (transfer.recipient != user) return false;
        if (transfer.status != STATUS_PENDING) return false;

        if (option::is_some(&transfer.expires_at)) {
            let expiry = *option::borrow(&transfer.expires_at);
            if (timestamp > expiry) return false;
        };

        true
    }

    // User pays gas fee → 
    // Protocol takes 1% cut → 
    // Protocol fees accumulate → 
    // Admin fee withdraw to their address

    // Admin functions
    public entry fun update_protocol_fee(
        stats: &mut ProtocolStats,
        new_rate: u64,
        ctx: &TxContext
    ) {
        assert!(stats.admin == tx_context::sender(ctx), E_NOT_AUTHORIZED);
        assert!(new_rate <= 1000, E_INSUFFICIENT_GAS_FEE);
        stats.protocol_fee_rate = new_rate;
    }

    public entry fun withdraw_protocol_fees(
        stats: &mut ProtocolStats,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(stats.admin == tx_context::sender(ctx), E_NOT_AUTHORIZED);
        let withdrawal = coin::take(&mut stats.gas_fees_collected, amount, ctx);
        transfer::public_transfer(withdrawal, stats.admin);
    }

    public entry fun emergency_cancel_transfer(
        transfer: &mut FileTransfer,
        stats: &ProtocolStats,
        ctx: &TxContext
    ) {
        assert!(stats.admin == tx_context::sender(ctx), E_NOT_AUTHORIZED);
        transfer.status = STATUS_CANCELLED;
    }
}



