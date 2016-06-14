// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "chainparams.h"
#include "hash.h"
#include "random.h"
#include "streams.h"
#include "txmempool.h"
#include "main.h"
#include "util.h"

#include <unordered_map>

#define MIN_TRANSACTION_SIZE 60

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block) :
        nonce(GetRand(std::numeric_limits<uint64_t>::max())),
        shorttxids(block.vtx.size() - 1), prefilledtxn(1), header(block) {
    FillShortTxIDSelector();
    //TODO: Use our mempool prior to block acceptance to predictively fill more than just the coinbase
    prefilledtxn[0] = {0, block.vtx[0]};
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        shorttxids[i - 1] = GetShortID(tx.GetHash());
    }
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}



ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, size_t max_mempool_txn_iterations) {
    if (cmpctblock.header.IsNull() || (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() > MAX_BLOCK_SIZE / MIN_TRANSACTION_SIZE)
        return READ_STATUS_INVALID;

    assert(header.IsNull() && txn_available.empty());
    header = cmpctblock.header;
    txn_available.resize(cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size());

    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
        if (cmpctblock.prefilledtxn[i].tx.IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1;
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i + 1) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txn_available[lastprefilledindex] = std::make_shared<CTransaction>(cmpctblock.prefilledtxn[i].tx);
    }
    prefilled_count = cmpctblock.prefilledtxn.size();

    // Calculate map of txids -> positions and check mempool to see what we have (or dont)
    // Because well-formed cmpctblock messages will have a (relatively) uniform distribution
    // of short IDs, any highly-uneven distribution of elements can be safely treated as a
    // READ_STATUS_FAILED.
    std::unordered_map<uint64_t, uint16_t> shorttxids(cmpctblock.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctblock.shorttxids.size(); i++) {
        while (txn_available[i + index_offset])
            index_offset++;
        shorttxids[cmpctblock.shorttxids[i]] = i + index_offset;
        // The chance that any bucket has more than 16 elements has a chance
        // lower than one in a billion for up to 913429 elements in the table.
        // The number of elements in a fixed bucket is binomially distributed with
        // p=1/#buckets n=#txn. Since the number of buckets is at least equal to the
        // number of transactions (max_load_factor=1.0), the worst case is when
        // X > 16 with X~Binomial(n=913429, p=1/913429). This P(X > 16) equals
        // 1.09478 * 10^-15. The chance that this happens for any of the 913429 buckets
        // is at most 913429 times this probability, which is 0.000000001.
        if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 16)
            return READ_STATUS_FAILED;
    }
    // TODO: in the shortid-collision case, we should instead request both transactions
    // which collided. Falling back to full-block-request here is overkill.
    if (shorttxids.size() != cmpctblock.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    char have_txn[txn_available.size() / 8 + 1];
    memset(have_txn, 0, txn_available.size() / 8 + 1);

    LOCK(pool->cs);
    CTxMemPool::indexed_transaction_set::index<mining_score>::type::iterator it = pool->mapTx.get<mining_score>().begin();
    uint256 thishash; // We prefetch the next hash we need to speed up memory access
    if (it != pool->mapTx.get<mining_score>().end())
        thishash = it->GetTx().GetHash();
    for (uint32_t i = 0; i < max_mempool_txn_iterations && it != pool->mapTx.get<mining_score>().end(); i++) {
        const CTxMemPoolEntry* entry = &(*it);
        uint64_t shortid = cmpctblock.GetShortID(thishash);
        it++;
        if (it != pool->mapTx.get<mining_score>().end())
            thishash = it->GetTx().GetHash();
        std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
        if (idit != shorttxids.end()) {
            if (!(have_txn[idit->second / 8] & (1 << (idit->second & 0x7)))) {
                txn_available[idit->second] = entry->GetSharedTx();
                have_txn[idit->second / 8] |= 1 << (idit->second & 0x7);
                mempool_count++;
            } else {
                // If we find two mempool txn that match the short id, just request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBlock failure would be annoying
                if (txn_available[idit->second]) {
                    txn_available[idit->second].reset();
                    mempool_count--;
                }
            }
        }
    }

    LogPrint("cmpctblock", "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu\n", cmpctblock.header.GetHash().ToString(), cmpctblock.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION));

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    assert(index < txn_available.size());
    return txn_available[index] ? true : false;
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransaction>& vtx_missing) const {
    assert(!header.IsNull());
    block = header;
    block.vtx.resize(txn_available.size());

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            block.vtx[i] = vtx_missing[tx_missing_offset++];
        } else
            block.vtx[i] = *txn_available[i];
    }
    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_INVALID;

    CValidationState state;
    if (!CheckBlock(block, state, Params().GetConsensus())) {
        // TODO: We really want to just check merkle tree manually here,
        // but that is expensive, and CheckBlock caches a block's
        // "checked-status" (in the CBlock?). CBlock should be able to
        // check its own merkle root and cache that check.
        if (state.CorruptionPossible())
            return READ_STATUS_FAILED; // Possible Short ID collision
        return READ_STATUS_INVALID;
    }

    LogPrint("cmpctblock", "Successfully reconstructed block %s with %lu txn prefilled, %lu txn from mempool and %lu txn requested\n", header.GetHash().ToString(), prefilled_count, mempool_count, vtx_missing.size());
    if (vtx_missing.size() < 5) {
        for(const CTransaction& tx : vtx_missing)
            LogPrint("cmpctblock", "Reconstructed block %s required tx %s\n", header.GetHash().ToString(), tx.GetHash().ToString());
    }

    return READ_STATUS_OK;
}
