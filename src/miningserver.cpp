#include <miningserver.h>

#include <chainparams.h>
#include <compat.h>
#include <consensus/merkle.h>
#include <miner.h>
#include <netbase.h>
#include <streams.h>
#include <sync.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validation.h>
#include <validationinterface.h>

#include <atomic>

#include <event2/event.h>

static const uint16_t CURRENT_MINING_PROTOCOL_VERSION = 1;

enum class VersionFlags {
    /** Indicates all provided templates must have 0 for coinbase value remaining */
    NEED_NO_REMAINING_VALUE = (1 << 0),
    /** Indicates all provided templates should be in BLOCK_TEMPLATE_HEADER version */
    NEED_HEADER_TEMPLATE_VARIANTS = (1 << 1),
};
static const uint16_t ALL_KNOWN_VERSION_FLAGS = (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE | (uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS;

enum class MsgTypes {
    /** Used to mark read buffer as pending */
    UNKNOWN = 0,
    /** Sent from client to server to start, consists of:
     * 3 bytes - message length (always 0x06||0x00||0x00)
     * 2 bytes - max protocol version supported
     * 2 bytes - min protocol version supported
     * 2 bytes - flags (see VersionFlags, above)
     */
    PROTOCOL_SUPPORT = 1,
    /** Sent from server to client, consists of:
     * 3 bytes - message length (always 0x25||0x00||0x00)
     * 2 bytes - protocol version selected
     * 2 bytes - protocol flags selected
     * 33 bytes - compressed server pubkey for auth
     */
    PROTOCOL_VERSION = 2,
    /** Sent from client to server, consists of:
     * 3 bytes - message length (always 0x02||0x00||0x00)
     * 2 bytes - additional coinbase tx length to reserve (less 328 bytes)
     */
    ADDITIONAL_COINBASE_LENGTH = 3,
    /** Sent from server to client, consists of:
     * 3 bytes - message length
     * 64 bytes - signature over sha256(BLOCK_TEMPLATE || remaining data) in R, S format, in BE.
     * 8 bytes - template timestamp (used to identify template uniquely, in ms)
     * 32 bytes - target hash
     * 44 bytes - header (with nonce + merkle root skipped)
     *          - aka (version, prev_block, time, nbits)
     * 1 byte - number of merkle entries
     * N * 32 bytes - right-hand-side branches of the transaction merkle tree
     * 8 bytes - coinbase value remaining
     *
     * 4 bytes - coinbase transaction version
     * 1 byte - coinbase prefix length (obviously < 100 - feel free to use as
     *          scriptSig length compactsize if you add no data!)
     * N bytes - coinbase prefix (including block height push)
     * 1 byte - coinbase postfix length (always 0 from us)
     * 0 bytes - coinbase postfix
     * 4 bytes - coinbase input nSequence
     * 2 bytes - length of remaining coinbase transaction data
     * CompactSize - number of coinbase outputs to append to end of coinbase
     * N * (8 + P + M) - coinbase outputs
         * 8 bytes - output value
         * CompactSize - output scriptPubKey length
         * M bytes - output scriptPubKey
     * 4 bytes - coinbase locktime
     */
    BLOCK_TEMPLATE = 4,
    /** Sent from client to server, consists of:
     * 3 bytes - message length
     * 8 bytes - template timestamp
     * 4 bytes - header nVersion
     * 4 bytes - header timestamp
     * 4 bytes - header nonce
     * 1 byte  - user tag length
     * N bytes - user tag
     * 4 bytes - coinbase transaction length
     * N bytes - coinbase transaction, serialized
     */
    WINNING_NONCE = 5,
    /** Sent from client to server, consists of:
     * 3 bytes - message length (always 0x08||0x00||0x00)
     * 8 bytes - template timestamp
     */
    TRANSACTION_DATA_REQUEST = 6,
    /** Sent from server to client in response to
     * TRANSACTION_DATA_REQUEST, consists of:
     * 3 bytes - message length
     * 64 bytes - signature over sha256(TRANSACTION_DATA || remaining data) in R, S format, in BE.
     * 8 bytes - template timestamp
     * 80 bytes - previous block header
     * 4 bytes - number of transactions (not including coinbase)
     * N * (M + 4) bytes - transactions, serialized with witnesses:
         * 4 bytes - transaction data length
         * M bytes - transaction data
     */
    TRANSACTION_DATA = 7,
    /** Sent from server to client, consists of:
     * 3 bytes - message length
     * 64 bytes - signature over sha256(COINBASE_PREFIX_POSTFIX || remaining data) in R, S format, in BE.
     * 8 bytes - timestamp
     * 1 byte - coinbase prefix postfix length (obviously < 100)
     * N bytes - coinbase prefix postfix
     */
    COINBASE_PREFIX_POSTFIX = 8,
    /** Sent from server to client, consists of:
     * 3 bytes - message length
     * 64 bytes - signature over sha256(BLOCK_TEMPLATE_HEADER || remaining data) in R, S format, in BE.
     * 8 bytes - template timestamp (used to identify template uniquely, in ms)
     * 8 bytes - template variant (used to identify template uniquely per-client, in ms)
     * 32 bytes - target hash
     * 44 bytes - header (with nonce skipped)
     *          - aka (version, prev_block, merkle_root, time, nbits)
     */
    BLOCK_TEMPLATE_HEADER = 9,
    /** Sent from client to server, consists of:
     * 3 bytes - message length
     * 8 bytes - template timestamp
     * 8 bytes - template variant
     * 4 bytes - header nVersion
     * 4 bytes - header timestamp
     * 4 bytes - header nonce
     * 1 byte  - user tag length
     * N bytes - user tag
     */
    WINNING_NONCE_HEADER = 10,
    /** We don't implement sending this and should never receive it:
    NEW_WORK_SERVER = 11, */
    /** We don't implement sending/handling this, consists of:
     * 3 bytes - message length
     * ...
     */
    VENDOR_MESSAGE = 12,
};

/** Default name for server auth privkey */
static const std::string SERVER_PRIVKEY_AUTH_FILE = ".miningserver_key";

struct BlockTemplate {
    CTransactionRef m_original_coinbase_tx;
    uint32_t m_original_version;
    uint32_t m_original_time;
    std::shared_ptr<CBlock> m_block;
    std::vector<uint256> m_merkle_rhss;
    CTxOut m_segwit_commitment;

    BlockTemplate(CBlock&& block, CTxOut&& segwit_commitment) :
        m_original_coinbase_tx(block.vtx[0]), m_original_version(block.nVersion), m_original_time(block.nTime),
        m_block(std::make_shared<CBlock>(std::move(block))),
        m_merkle_rhss(BlockMerkleBranch(*m_block, 0)),
        m_segwit_commitment(segwit_commitment) { }
};

static std::atomic<uint64_t> max_client_id;
struct ClientState {
    event* m_read_event = nullptr;

    uint16_t m_flags = 0;
    uint64_t m_client_id;

    std::list<std::vector<unsigned char>> m_outbound_messages_pending;
    size_t m_outbound_next_msg_offset_sent = 0;

    MsgTypes m_next_msg_type = MsgTypes::PROTOCOL_SUPPORT;
    uint32_t m_next_msg_offset = 0;
    std::vector<unsigned char> m_msg_read_buffer;
    uint32_t m_bytes_to_skip = 0;

    //TODO: Handle this in template creation
    uint16_t m_coinbase_tx_overhead = 0;

    ClientState() : m_client_id(max_client_id.fetch_add(1)), m_msg_read_buffer(10) {} // first message is PROTOCOL_SUPPORT, of 9 bytes + message type byte
};

struct LibeventContext : public CValidationInterface {
    const CKey m_auth_key;
    const uint64_t m_node_id;
    CScript m_payout_script;

    CCriticalSection m_cs;

    std::atomic_bool m_have_had_clients;
    std::map<uint64_t, BlockTemplate> m_templates;

    struct event_base* m_event_base = nullptr;
    struct event* m_listen_event = nullptr;

    std::unordered_map<SOCKET, ClientState> m_clients;
    std::list<event*> m_client_events_to_free;

    SOCKET m_listen_socket = INVALID_SOCKET;
    std::unique_ptr<std::thread> m_event_thread;

    LibeventContext(const CKey& auth_key, uint64_t node_id) :
        m_auth_key(auth_key), m_node_id(node_id) {}

    ~LibeventContext() {
        for (auto& client_pair : m_clients) {
            DisconnectClient(client_pair.first, &client_pair.second);
        }
        FreeLooseClientEvents();
        if (m_listen_event) {
            event_del(m_listen_event);
            event_free(m_listen_event);
        }
        if (m_event_base) {
            event_base_free(m_event_base);
        }
    }

    void FreeLooseClientEvents() {
        AssertLockNotHeld(m_cs);
        for (auto& event : m_client_events_to_free) {
            event_del(event);
            event_free(event);
        }
        m_client_events_to_free.clear();
    }

    void DisconnectClient(evutil_socket_t sock, ClientState *client) {
        LogPrint(BCLog::MININGSERVER, "Client %lu disconnected\n", client->m_client_id);
        if (client->m_read_event) {
            m_client_events_to_free.push_back(client->m_read_event);
            client->m_read_event = nullptr;
        }
        close(sock);
    }

    void DisconnectAndFreeClient(const std::unordered_map<SOCKET, ClientState>::iterator& it) {
        DisconnectClient(it->first, &it->second);
        m_clients.erase(it);
    }

    bool SendMessages(evutil_socket_t sock, ClientState* client);

    CTransactionRef BuildHeaderVariantCoinbaseTx(const CTransactionRef& original_coinbase_tx, uint64_t client_id);
    std::vector<unsigned char> EncodeBestTemplate(bool need_full_payout);
    std::vector<unsigned char> EncodeBestTemplateHeader(uint64_t client_id);
    void BuildNewTemplate();

    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override {
        if (fInitialDownload) return;
        if (!m_have_had_clients.load(std::memory_order_relaxed)) return;
        //TODO: this completely destroys near-tip resync performance after a day offline...fix
        BuildNewTemplate();
    }

    size_t txn_since_last_build = 0;
    void TransactionAddedToMempool(const CTransactionRef& ptx) override {
        if (!m_have_had_clients.load(std::memory_order_relaxed)) return;
        if (++txn_since_last_build < 250) return;
        txn_since_last_build = 0;
        BuildNewTemplate();
    }
};

MiningServer::MiningServer(const CKey& auth_key, uint64_t node_id) : m_event_ctx(new LibeventContext(auth_key, node_id)) { }
MiningServer::~MiningServer() { }

static void WriteCallback(evutil_socket_t sock, short events, void* event_ctx) {
    LibeventContext* ctx = (LibeventContext*)event_ctx;
    ctx->FreeLooseClientEvents();
    LOCK(ctx->m_cs);

    auto client_it = ctx->m_clients.find(sock);
    if (client_it == ctx->m_clients.end()) return;
    ClientState* client = &client_it->second;

    if (!ctx->SendMessages(sock, client)) {
        ctx->DisconnectAndFreeClient(client_it);
    }
}

bool LibeventContext::SendMessages(evutil_socket_t sock, ClientState* client) {
    while (!client->m_outbound_messages_pending.empty()) {
        ssize_t sent = send(sock, client->m_outbound_messages_pending.front().data() + client->m_outbound_next_msg_offset_sent, client->m_outbound_messages_pending.front().size() - client->m_outbound_next_msg_offset_sent, MSG_NOSIGNAL);
        if (sent >= 0) {
            client->m_outbound_next_msg_offset_sent += sent;
            if (client->m_outbound_next_msg_offset_sent >= client->m_outbound_messages_pending.front().size()) {
                client->m_outbound_messages_pending.pop_front();
                client->m_outbound_next_msg_offset_sent = 0;
            } else {
                break;
            }
        } else {
            return false;
        }
    }
    if (!client->m_outbound_messages_pending.empty()) {
        struct event* m_write_event = event_new(m_event_base, sock, EV_WRITE, WriteCallback, this);
        if (!m_write_event) {
            return false;
        }
        event_add(m_write_event, nullptr);
    }
    return true;
}

CTransactionRef LibeventContext::BuildHeaderVariantCoinbaseTx(const CTransactionRef& original_coinbase_tx, uint64_t client_id) {
    CMutableTransaction coinbase_tx(*original_coinbase_tx);
    coinbase_tx.vin[0].scriptSig << client_id;
    if (m_node_id != 0) {
        coinbase_tx.vin[0].scriptSig << m_node_id;
    }
    coinbase_tx.vout[0].scriptPubKey = m_payout_script;
    return MakeTransactionRef(std::move(coinbase_tx));
}

std::vector<unsigned char> LibeventContext::EncodeBestTemplateHeader(uint64_t client_id) {
    auto& block_template = *m_templates.rbegin();

    std::vector<unsigned char> encoded_template(68);
    encoded_template[0] = (uint8_t)MsgTypes::BLOCK_TEMPLATE_HEADER;
    encoded_template[1] = 0xbc;
    encoded_template[2] = 0x00;
    encoded_template[3] = 0x00;
    CVectorWriter writer(SER_NETWORK, PROTOCOL_VERSION, encoded_template, 68);

    writer << block_template.first;
    writer << client_id;
    writer << ArithToUint256(arith_uint256().SetCompact(block_template.second.m_block->nBits));

    uint256 merkle_root[2];
    merkle_root[0] = BuildHeaderVariantCoinbaseTx(block_template.second.m_original_coinbase_tx, client_id)->GetHash();
    for (const uint256& hash : block_template.second.m_merkle_rhss) {
        merkle_root[1] = hash;
        SHA256D64(merkle_root[0].begin(), merkle_root[0].begin(), 1);
    }

    writer << block_template.second.m_original_version;
    writer << block_template.second.m_block->hashPrevBlock;
    writer << merkle_root[0];
    writer << block_template.second.m_original_time;
    writer << block_template.second.m_block->nBits;

    uint256 message_hash;
    uint8_t type = (uint8_t)MsgTypes::BLOCK_TEMPLATE_HEADER;
    CSHA256()
        .Write(&type, 1)
        .Write(encoded_template.data() + 68, encoded_template.size() - 68)
        .Finalize(message_hash.begin());
    assert(m_auth_key.SignNonRecoverableCompact(message_hash, encoded_template.data() + 4));

    return encoded_template;
}

std::vector<unsigned char> LibeventContext::EncodeBestTemplate(bool need_full_payout) {
    auto& block_template = *m_templates.rbegin();

    std::vector<unsigned char> encoded_template(68);
    encoded_template[0] = (uint8_t)MsgTypes::BLOCK_TEMPLATE;
    CVectorWriter writer(SER_NETWORK, PROTOCOL_VERSION, encoded_template, 68);

    writer << block_template.first;
    writer << ArithToUint256(arith_uint256().SetCompact(block_template.second.m_block->nBits));

    writer << block_template.second.m_original_version;
    writer << block_template.second.m_block->hashPrevBlock;
    writer << block_template.second.m_original_time;
    writer << block_template.second.m_block->nBits;

    writer << (uint8_t) block_template.second.m_merkle_rhss.size();
    for (const uint256& hash : block_template.second.m_merkle_rhss) {
        writer << hash;
    }

    if (need_full_payout) {
        writer << (uint64_t) 0; // 0 value remaining
    } else {
        writer << block_template.second.m_original_coinbase_tx->vout[0].nValue;
    }

    writer << (int32_t) 2; // coinbase transaction version

    // write enough to coinbase to make coinbase tx unique
    const CScript& coinbase = block_template.second.m_original_coinbase_tx->vin[0].scriptSig;
    writer << (uint8_t)(coinbase.size() + (m_node_id != 0 ? 8 : 0));
    writer.write((const char*)coinbase.data(), coinbase.size());
    if (m_node_id != 0) {
        writer << m_node_id;
    }
    writer << (uint8_t)0; // 0 coinbase_postfix

    writer << (uint32_t)0xffffffff;

    writer.seek(2);
    size_t remaining_length_pos = writer.GetPos();

    if (need_full_payout) {
        writer << (uint8_t) 2; // 2 outputs follow

        writer << block_template.second.m_original_coinbase_tx->vout[0].nValue;
        WriteCompactSize(writer, m_payout_script.size());
        writer.write((const char*)m_payout_script.data(), m_payout_script.size());
    } else {
        writer << (uint8_t) 1; // 1 output follows
    }

    writer << block_template.second.m_segwit_commitment;
    writer << (uint32_t) 0; // coinbase locktime

    uint16_t data_len = writer.GetPos() - remaining_length_pos;
    writer.SetPos(remaining_length_pos - 2);
    writer << data_len;

    uint256 message_hash;
    uint8_t type = (uint8_t)MsgTypes::BLOCK_TEMPLATE;
    CSHA256()
        .Write(&type, 1)
        .Write(encoded_template.data() + 68, encoded_template.size() - 68)
        .Finalize(message_hash.begin());
    assert(m_auth_key.SignNonRecoverableCompact(message_hash, encoded_template.data() + 4));

    encoded_template[1] = ((encoded_template.size() - 4) >> 0 ) & 0xff;
    encoded_template[2] = ((encoded_template.size() - 4) >> 8 ) & 0xff;
    encoded_template[3] = ((encoded_template.size() - 4) >> 16) & 0xff;

    return encoded_template;
}

void LibeventContext::BuildNewTemplate() {
    CScript scriptDummy = CScript() << OP_TRUE;
    std::unique_ptr<CBlockTemplate> block_template = BlockAssembler(Params()).CreateNewBlock(scriptDummy);

    LOCK(m_cs);
    uint64_t template_timestamp = (uint64_t)GetTimeMillis();
    if (m_templates.size()) {
        template_timestamp = std::max(m_templates.rbegin()->first + 1, template_timestamp);
    }
    CTxOut segwit_commitment_output(block_template->block.vtx[0]->vout.back());
    m_templates.emplace(std::piecewise_construct, std::forward_as_tuple(template_timestamp), std::forward_as_tuple(std::move(block_template->block), std::move(segwit_commitment_output)));

    std::vector<evutil_socket_t> failed_clients;

    std::vector<unsigned char> full_payout_template, no_payout_template;
    size_t clients_sent = 0;
    for (auto& client_pair : m_clients) {
        if (client_pair.second.m_next_msg_type != MsgTypes::PROTOCOL_SUPPORT) {
            if (client_pair.second.m_flags & (uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS) {
                client_pair.second.m_outbound_messages_pending.emplace_back(EncodeBestTemplateHeader(client_pair.second.m_client_id));
            } else if (client_pair.second.m_flags & (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE) {
                if (no_payout_template.empty()) {
                    no_payout_template = EncodeBestTemplate(true);
                }
                client_pair.second.m_outbound_messages_pending.emplace_back(no_payout_template);
            } else {
                if (full_payout_template.empty()) {
                    full_payout_template = EncodeBestTemplate(false);
                }
                client_pair.second.m_outbound_messages_pending.emplace_back(full_payout_template);
            }
            if (!SendMessages(client_pair.first, &client_pair.second)) {
                failed_clients.push_back(client_pair.first);
            } else {
                clients_sent++;
            }
        }
    }
    LogPrint(BCLog::MININGSERVER, "Sent new template to %lu clients\n", clients_sent);

    for (evutil_socket_t& sock : failed_clients) {
        DisconnectAndFreeClient(m_clients.find(sock));
    }

    if (m_templates.size() >= 3) {
        m_templates.erase(m_templates.begin());
    }
}

static void ReadCallback(evutil_socket_t sock, short events, void* event_ctx) {
    LibeventContext* ctx = (LibeventContext*)event_ctx;
    ctx->FreeLooseClientEvents();
    LOCK(ctx->m_cs);

    auto client_it = ctx->m_clients.find(sock);
    if (client_it == ctx->m_clients.end()) return;
    ClientState* client = &client_it->second;

    do {
        if (client->m_bytes_to_skip != 0) {
            char buff[4096];
            int recvd = recv(sock, buff, std::max((uint32_t)4096, client->m_bytes_to_skip), MSG_DONTWAIT);
            if (recvd < 0) {
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                    return ctx->DisconnectAndFreeClient(client_it);
                }
                break;
            } else if (recvd == 0) {
                break;
            }
            client->m_bytes_to_skip -= recvd;
            continue;
        }
        if (client->m_next_msg_type == MsgTypes::UNKNOWN) {
            unsigned char type;
            int recvd = recv(sock, &type, 1, MSG_DONTWAIT);
            if (recvd < 0) {
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                    return ctx->DisconnectAndFreeClient(client_it);
                }
                break;
            } else if (recvd == 0) {
                break;
            }
            client->m_next_msg_type = (MsgTypes)type;
            switch(client->m_next_msg_type) {
                case MsgTypes::ADDITIONAL_COINBASE_LENGTH:
                case MsgTypes::WINNING_NONCE:
                case MsgTypes::TRANSACTION_DATA_REQUEST:
                case MsgTypes::WINNING_NONCE_HEADER:
                case MsgTypes::VENDOR_MESSAGE:
                    break;
                default:
                    return ctx->DisconnectAndFreeClient(client_it);
            }
            client->m_msg_read_buffer.resize(3);
            client->m_next_msg_offset = 0;
        }
        int recvd = recv(sock, client->m_msg_read_buffer.data() + client->m_next_msg_offset, client->m_msg_read_buffer.size() - client->m_next_msg_offset, MSG_DONTWAIT);
        if (recvd > 0) {
            client->m_next_msg_offset += recvd;
            if (client->m_next_msg_offset == client->m_msg_read_buffer.size()) {
                if (client->m_msg_read_buffer.size() == 3) {
                    uint8_t message_length_high;
                    uint16_t message_length_low;
                    VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                    reader >> message_length_low >> message_length_high;
                    uint32_t message_length = (((uint32_t)message_length_high) << 16) | message_length_low;

                    if (client->m_next_msg_type == MsgTypes::VENDOR_MESSAGE) {
                        client->m_next_msg_type = MsgTypes::UNKNOWN;
                        client->m_bytes_to_skip = message_length;
                        continue;
                    }

                    switch(client->m_next_msg_type) {
                        case MsgTypes::ADDITIONAL_COINBASE_LENGTH:
                            if (message_length != 2) ctx->DisconnectAndFreeClient(client_it);
                            break;
                        case MsgTypes::WINNING_NONCE:
                            if (message_length < 25 || message_length > 1000280) ctx->DisconnectAndFreeClient(client_it);
                            break;
                        case MsgTypes::TRANSACTION_DATA_REQUEST:
                            if (message_length != 8) ctx->DisconnectAndFreeClient(client_it);
                            break;
                        case MsgTypes::WINNING_NONCE_HEADER:
                            if (message_length < 29 || message_length > 284) ctx->DisconnectAndFreeClient(client_it);
                            break;
                        default: return ctx->DisconnectAndFreeClient(client_it); // unreachable
                    }
                    client->m_msg_read_buffer.resize(message_length);
                    client->m_next_msg_offset = 0;
                    continue;
                }
                switch(client->m_next_msg_type) {
                    case MsgTypes::PROTOCOL_SUPPORT: {
                        LogPrint(BCLog::MININGSERVER, "Received PROTOCOL_SUPPORT from %lu\n", client->m_client_id);

                        uint8_t message_type_byte, message_length_low;
                        uint16_t message_length_high, min_protocol_version, max_protocol_version;
                        VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                        reader >> message_type_byte >> message_length_low >> message_length_high
                               >> min_protocol_version >> max_protocol_version >> client->m_flags;

                        if (message_type_byte != 1 || message_length_low != 6 || message_length_high != 0 ||
                                min_protocol_version > CURRENT_MINING_PROTOCOL_VERSION || max_protocol_version < CURRENT_MINING_PROTOCOL_VERSION) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        switch (client->m_flags & ((uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS | (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE)) {
                            case 0b00:
                                client->m_flags = 0;
                                break;
                            case 0b01:
                                client->m_flags = (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE;
                                break;
                            case 0b10:
                                // We prefer they use the non-header variants as we avoid re-signing work for each client.
                                client->m_flags = (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE;
                                break;
                            case 0b11:
                                client->m_flags = ((uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS | (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE);
                                break;
                        }

                        if (client->m_flags & (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE) {
                            if (ctx->m_payout_script.empty()) {
                                return ctx->DisconnectAndFreeClient(client_it);
                            }
                        }

                        {
                            client->m_outbound_messages_pending.emplace_back();
                            CVectorWriter writer(SER_NETWORK, PROTOCOL_VERSION, client->m_outbound_messages_pending.back(), 0);
                            writer << (uint8_t)MsgTypes::PROTOCOL_VERSION;
                            writer << (uint8_t)0x25;
                            writer << (uint16_t) 0;
                            writer << CURRENT_MINING_PROTOCOL_VERSION;
                            writer << (uint16_t)(client->m_flags & ALL_KNOWN_VERSION_FLAGS);
                            CPubKey our_key = ctx->m_auth_key.GetPubKey();
                            assert(our_key.size() == 33); //TODO: Check on init
                            writer.write((const char*)our_key.begin(), our_key.size());
                        }

                        if (!(client->m_flags & (uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS)) {
                            client->m_outbound_messages_pending.emplace_back(68);
                            std::vector<unsigned char>& msg = client->m_outbound_messages_pending.back();
                            msg[0] = (uint8_t)MsgTypes::COINBASE_PREFIX_POSTFIX;
                            msg[1] = 0x51;
                            msg[2] = 0;
                            msg[3] = 0;
                            CVectorWriter writer(SER_NETWORK, PROTOCOL_VERSION, client->m_outbound_messages_pending.back(), 68);
                            writer << GetTimeMillis() << (uint8_t)8 << client->m_client_id;

                            uint256 message_hash;
                            uint8_t type = (uint8_t)MsgTypes::COINBASE_PREFIX_POSTFIX;
                            CSHA256()
                                .Write(&type, 1)
                                .Write(msg.data() + 68, msg.size() - 68)
                                .Finalize(message_hash.begin());
                            assert(ctx->m_auth_key.SignNonRecoverableCompact(message_hash, msg.data() + 4));
                        }

                        if (ctx->m_templates.empty()) {
                            ctx->m_have_had_clients = true;
                            ctx->BuildNewTemplate();
                        }

                        if (client->m_flags & (uint16_t)VersionFlags::NEED_HEADER_TEMPLATE_VARIANTS) {
                            client->m_outbound_messages_pending.emplace_back(ctx->EncodeBestTemplateHeader(client->m_client_id));
                        } else {
                            client->m_outbound_messages_pending.emplace_back(ctx->EncodeBestTemplate(client->m_flags & (uint16_t)VersionFlags::NEED_NO_REMAINING_VALUE));
                        }

                        if (!ctx->SendMessages(sock, client)) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        client->m_next_msg_type = MsgTypes::UNKNOWN;
                        client->m_next_msg_offset = 0;
                        break;
                    }
                    case MsgTypes::ADDITIONAL_COINBASE_LENGTH: {
                        VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                        reader >> client->m_coinbase_tx_overhead;
                        break;
                    }
                    case MsgTypes::WINNING_NONCE: {
                        uint64_t template_id;
                        uint32_t header_version, header_timestamp, header_nonce;
                        uint8_t user_tag_len;
                        VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                        reader >> template_id >> header_version >> header_timestamp >> header_nonce >> user_tag_len;

                        if (client->m_msg_read_buffer.size() < 21 + (size_t)user_tag_len + 4) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        std::string user_tag(user_tag_len, ' ');
                        reader.read(&user_tag[0], user_tag_len);

                        uint32_t coinbase_tx_len;
                        reader >> coinbase_tx_len;

                        if ((uint64_t)client->m_msg_read_buffer.size() != 21 + (uint64_t)user_tag_len + 4 + (uint64_t)coinbase_tx_len) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        LogPrint(BCLog::MININGSERVER, "Received WINNING_NONCE from %lu\n", client->m_client_id);

                        auto template_it = ctx->m_templates.find(template_id);
                        if (template_it == ctx->m_templates.end()) {
                            LogPrint(BCLog::MININGSERVER, "Received WINNING_NONCE which didn't match any known templates from %lu!\n", client->m_client_id);
                            client->m_next_msg_type = MsgTypes::UNKNOWN;
                            client->m_next_msg_offset = 0;
                            break;
                        }

                        try {
                            CMutableTransaction coinbase_tx_builder(deserialize, reader);
                            if (coinbase_tx_builder.vin.size() != 1) {
                                return ctx->DisconnectAndFreeClient(client_it);
                            }
                            coinbase_tx_builder.vin[0].scriptWitness = template_it->second.m_original_coinbase_tx->vin[0].scriptWitness;
                            template_it->second.m_block->vtx[0] = MakeTransactionRef(std::move(coinbase_tx_builder));
                        } catch (std::ios_base::failure& e) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        template_it->second.m_block->nVersion = header_version;
                        template_it->second.m_block->nTime = header_timestamp;
                        template_it->second.m_block->nNonce = header_nonce;

                        uint256 merkle_root[2];
                        merkle_root[0] = template_it->second.m_block->vtx[0]->GetHash();
                        for (const uint256& hash : template_it->second.m_merkle_rhss) {
                            merkle_root[1] = hash;
                            SHA256D64(merkle_root[0].begin(), merkle_root[0].begin(), 1);
                        }
                        template_it->second.m_block->hashMerkleRoot = merkle_root[0];

                        bool is_new_block = false;
                        ProcessNewBlock(Params(), template_it->second.m_block, true, &is_new_block);

                        if (is_new_block) {
                            LogPrintf("Mining user %s via client %lu provided block!\n", SanitizeString(user_tag), client->m_client_id);
                        }

                        // Now that we've passed template_it->second into validation,
                        // make a copy of it so that we don't edit it in the future if
                        // we get another WINNING_NONCE for the same block.
                        // TODO: Ideally we'd do this after we create a new template and
                        // forward it to all our peers.
                        template_it->second.m_block = std::make_shared<CBlock>(*template_it->second.m_block);

                        client->m_next_msg_type = MsgTypes::UNKNOWN;
                        client->m_next_msg_offset = 0;
                        break;
                    }
                    case MsgTypes::TRANSACTION_DATA_REQUEST: {
                        LogPrint(BCLog::MININGSERVER, "Received TRANSACTION_DATA_REQUEST from %lu\n", client->m_client_id);

                        uint64_t template_id;
                        VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                        reader >> template_id;

                        auto template_it = ctx->m_templates.find(template_id);
                        if (template_it == ctx->m_templates.end()) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        client->m_outbound_messages_pending.emplace_back(68);
                        std::vector<unsigned char>& msg = client->m_outbound_messages_pending.back();
                        msg[0] = (uint8_t)MsgTypes::TRANSACTION_DATA;
                        CVectorWriter writer(SER_NETWORK, PROTOCOL_VERSION, msg, 68);
                        writer << template_id;

                        {
                            LOCK(cs_main);
                            const CBlockIndex *prev_index = LookupBlockIndex(template_it->second.m_block->hashPrevBlock);
                            assert(prev_index);
                            writer << prev_index->GetBlockHeader();
                        }

                        writer << (uint32_t)32;
                        writer.write((const char*)template_it->second.m_original_coinbase_tx->vin[0].scriptWitness.stack[0].data(), 32);

                        uint32_t tx_count = template_it->second.m_block->vtx.size() - 1;
                        writer << tx_count;

                        std::vector<unsigned char> tx_serialize_buff;
                        for (size_t i = 1; i < template_it->second.m_block->vtx.size(); i++) {
                            {
                                CVectorWriter temp_tx_writer(SER_NETWORK, PROTOCOL_VERSION, tx_serialize_buff, 0);
                                temp_tx_writer << template_it->second.m_block->vtx[i];
                            } // release temp_tx_writer

                            uint32_t tx_size = tx_serialize_buff.size();
                            writer << tx_size;
                            writer.write((char*)tx_serialize_buff.data(), tx_serialize_buff.size());
                            tx_serialize_buff.resize(0);
                        }

                        uint256 message_hash;
                        uint8_t msg_type = (uint8_t)MsgTypes::TRANSACTION_DATA;
                        CSHA256()
                            .Write(&msg_type, 1)
                            .Write(msg.data() + 68, msg.size() - 68)
                            .Finalize(message_hash.begin());
                        assert(ctx->m_auth_key.SignNonRecoverableCompact(message_hash, msg.data() + 4));

                        msg[1] = ((msg.size() - 4) >> 0 ) & 0xff;
                        msg[2] = ((msg.size() - 4) >> 8 ) & 0xff;
                        msg[3] = ((msg.size() - 4) >> 16) & 0xff;

                        if (!ctx->SendMessages(sock, client)) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        client->m_next_msg_type = MsgTypes::UNKNOWN;
                        client->m_next_msg_offset = 0;
                        break;
                    }
                    case MsgTypes::WINNING_NONCE_HEADER: {
                        uint64_t template_id, template_variant;
                        uint32_t header_version, header_timestamp, header_nonce;
                        uint8_t user_tag_len;
                        VectorReader reader(client->m_msg_read_buffer, SER_NETWORK, PROTOCOL_VERSION);
                        reader >> template_id >> template_variant >> header_version >> header_timestamp >> header_nonce >> user_tag_len;

                        if (client->m_msg_read_buffer.size() != 29 + (size_t)user_tag_len) {
                            return ctx->DisconnectAndFreeClient(client_it);
                        }

                        LogPrint(BCLog::MININGSERVER, "Received WINNING_NONCE_HEADER from %lu\n", client->m_client_id);

                        std::string user_tag(user_tag_len, ' ');
                        reader.read(&user_tag[0], user_tag_len);

                        auto template_it = ctx->m_templates.find(template_id);
                        if (template_it == ctx->m_templates.end()) {
                            LogPrint(BCLog::MININGSERVER, "Received WINNING_NONCE_HEADER which didn't match any known templates from %lu!\n", client->m_client_id);
                            client->m_next_msg_type = MsgTypes::UNKNOWN;
                            client->m_next_msg_offset = 0;
                            break;
                        }

                        template_it->second.m_block->vtx[0] = ctx->BuildHeaderVariantCoinbaseTx(template_it->second.m_original_coinbase_tx, template_variant);

                        uint256 merkle_root[2];
                        merkle_root[0] = template_it->second.m_block->vtx[0]->GetHash();
                        for (const uint256& hash : template_it->second.m_merkle_rhss) {
                            merkle_root[1] = hash;
                            SHA256D64(merkle_root[0].begin(), merkle_root[0].begin(), 1);
                        }
                        template_it->second.m_block->hashMerkleRoot = merkle_root[0];

                        template_it->second.m_block->nVersion = header_version;
                        template_it->second.m_block->nTime = header_timestamp;
                        template_it->second.m_block->nNonce = header_nonce;

                        bool is_new_block = false;
                        ProcessNewBlock(Params(), template_it->second.m_block, true, &is_new_block);

                        if (is_new_block) {
                            LogPrintf("Mining user %s via client %lu provided block!\n", SanitizeString(user_tag), client->m_client_id);
                        }

                        // Now that we've passed template_it->second into validation,
                        // make a copy of it so that we don't edit it in the future if
                        // we get another WINNING_NONCE for the same block.
                        // TODO: Ideally we'd do this after we create a new template and
                        // forward it to all our peers.
                        template_it->second.m_block = std::make_shared<CBlock>(*template_it->second.m_block);

                        client->m_next_msg_type = MsgTypes::UNKNOWN;
                        client->m_next_msg_offset = 0;
                        break;
                    }
                    default: return ctx->DisconnectAndFreeClient(client_it);
                }
            }
        } else if (recvd == 0) {
            break;
        } else {
            int nErr = WSAGetLastError();
            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                return ctx->DisconnectAndFreeClient(client_it);
            }
            break;
        }
    } while(true);
}

static void AcceptCallback(evutil_socket_t sock, short events, void* event_ctx) {
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET socket = accept(sock, (struct sockaddr*)&sockaddr, &len);

    if (socket == INVALID_SOCKET)
    {
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK)
            LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        return;
    }

    SetSocketNoDelay(socket);

    LibeventContext* ctx = (LibeventContext*)event_ctx;

    struct event* client_read_event = event_new(ctx->m_event_base, socket, EV_READ | EV_PERSIST, ReadCallback, event_ctx);
    if (!client_read_event) {
        LogPrintf("Failed to create libevent event for new mining client\n");
        CloseSocket(socket);
        return;
    }

    LOCK(ctx->m_cs);

    event_add(client_read_event, nullptr);
    auto pair = ctx->m_clients.emplace(std::piecewise_construct, std::forward_as_tuple(socket), std::forward_as_tuple());
    pair.first->second.m_read_event = client_read_event;
}

/** Get path of server auth privkey file */
static fs::path GetAuthFile(bool temp = false)
{
    std::string arg = gArgs.GetArg("-miningkeyfile", SERVER_PRIVKEY_AUTH_FILE);
    if (temp) {
        arg += ".tmp";
    }
    return AbsPathForConfigVal(fs::path(arg));
}

static bool GenerateAuthKey()
{
    CKey auth;
    auth.MakeNewKey(/* compressed */ true);
    std::string key = HexStr(auth.begin(), auth.end());

    std::ofstream file;
    fs::path filepath_tmp = GetAuthFile(/* temp */ true);
    file.open(filepath_tmp.string().c_str());
    if (!file.is_open()) {
        LogPrintf("Unable to open mining server authentication key file %s for writing\n", filepath_tmp.string());
        return false;
    }
    file << key;
    file.close();

    fs::path filepath = GetAuthFile(/* temp */ false);
    if (!RenameOver(filepath_tmp, filepath)) {
        LogPrintf("Unable to rename mining server authentication key file %s to %s\n", filepath_tmp.string(), filepath.string());
        return false;
    }
    LogPrintf("Generated mining server authentication key file %s\n", filepath.string());
    return true;
}

bool MiningServer::ReadAuthKey(CKey& auth)
{
    std::ifstream file;
    fs::path filepath = GetAuthFile();
    file.open(filepath.string().c_str());
    if (!file.is_open()) {
        if (!GenerateAuthKey()) return false;
        file.open(filepath.string().c_str());
    }
    if (!file.is_open()) return false;

    std::string key;
    std::getline(file, key);
    file.close();
    const auto key_data = ParseHex(key);
    auth.Set(key_data.begin(), key_data.end(), /* compressed */ true);
    return auth.IsValid();
}

bool MiningServer::Start(const CService& bind_addr, const CScript& payout_script) {
    m_event_ctx->m_payout_script = payout_script;

    m_event_ctx->m_event_base = event_base_new();
    if (!m_event_ctx->m_event_base) {
        return false;
    }

    std::string err_string;
    m_event_ctx->m_listen_socket = BindListenSocket(bind_addr, err_string);
    if (m_event_ctx->m_listen_socket == INVALID_SOCKET) {
        return false;
    }

    m_event_ctx->m_listen_event = event_new(m_event_ctx->m_event_base, m_event_ctx->m_listen_socket, EV_READ | EV_PERSIST, AcceptCallback, m_event_ctx.get());
    if (!m_event_ctx->m_listen_event) {
        CloseSocket(m_event_ctx->m_listen_socket);
        event_base_free(m_event_ctx->m_event_base);
        m_event_ctx->m_event_base = nullptr;
        return false;
    }
    event_add(m_event_ctx->m_listen_event, nullptr);

    m_event_ctx->m_event_thread.reset(new std::thread(&TraceThread<std::function<void ()> >, "miningserver", std::bind(&event_base_dispatch, m_event_ctx->m_event_base)));

    RegisterValidationInterface(m_event_ctx.get());

    return true;
}

void MiningServer::Interrupt() {
    if (m_event_ctx->m_event_base) {
        event_base_loopbreak(m_event_ctx->m_event_base);
    }
}

void MiningServer::Stop() {
    if (m_event_ctx) {
        UnregisterValidationInterface(m_event_ctx.get());
        if (m_event_ctx->m_event_base) {
            event_base_loopbreak(m_event_ctx->m_event_base);
            if (m_event_ctx->m_event_thread) m_event_ctx->m_event_thread->join();
        }
        m_event_ctx.reset();
    }
}
