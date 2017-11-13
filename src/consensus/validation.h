// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_VALIDATION_H
#define BITCOIN_CONSENSUS_VALIDATION_H

#include <string>
#include "version.h"
#include "consensus/consensus.h"
#include "primitives/transaction.h"
#include "primitives/block.h"

/** "reject" message codes */
static const unsigned char REJECT_MALFORMED = 0x01;
static const unsigned char REJECT_INVALID = 0x10;
static const unsigned char REJECT_OBSOLETE = 0x11;
static const unsigned char REJECT_DUPLICATE = 0x12;
static const unsigned char REJECT_NONSTANDARD = 0x40;
// static const unsigned char REJECT_DUST = 0x41; // part of BIP 61
static const unsigned char REJECT_INSUFFICIENTFEE = 0x42;
static const unsigned char REJECT_CHECKPOINT = 0x43;

/** A "reason" why something was invalid, suitable for (possibly) getting angry
  * (and retaliating) at the provider of the object in question (ie banning
  * peers).
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
enum class ValidationInvalidReason {
    // txn and blocks:
    VALID,           //!< not actually invalid
    CONSENSUS,       //!< invalid by consensus rules (excluding any below reasons)
    SOFT_FORK,       //!< invalid by non-ancient soft-fork rules (in some rare cases possibly by original consensus rules, too)
    UNKNOWN_INVALID, //!< this object was cached as being invalid, but we don't know why
    // Only blocks:
    MUTATED,         //!< the block's data didn't match the data committed to by the PoW
    MISSING_PREV,    //!< We don't have the previous block the checked one is built on
    INVALID_PREV,    //!< A block this one builds on is invalid
    BAD_TIME,        //!< block timestamp was > 2 hours in the future (or our clock is bad)
    CHECKPOINT,      //!< the block failed to meet one of our checkpoints
    // Only loose txn:
    NOT_STANDARD,    //!< didn't meet our local policy rules
    MISSING_INPUTS,  //!< a transaction was missing some of its inputs (or its inputs were spent at < coinbase maturity height)
    WITNESS_MUTATED, //!< tx might be missing a witness or witness may have been malleated
    CONFLICT,        //!< tx already in mempool or conflicts with an existing one (which is in chain or in mempool and RBF failed)
    MEMPOOL_LIMIT,   //!< violated mempool's fee/size/descendant/etc limits
};

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   //!< everything ok
        MODE_INVALID, //!< network rule violation (DoS value may be set)
        MODE_ERROR,   //!< run-time error
    } mode;
    ValidationInvalidReason reason;
    int nDoS;
    std::string strRejectReason;
    unsigned int chRejectCode;
    bool corruptionPossible;
    std::string strDebugMessage;
public:
    CValidationState() : mode(MODE_VALID), reason(ValidationInvalidReason::VALID), nDoS(0), chRejectCode(0), corruptionPossible(false) {}
    bool DoS(int level, ValidationInvalidReason reasonIn, bool ret = false,
             unsigned int chRejectCodeIn=0, const std::string &strRejectReasonIn="",
             bool corruptionIn=false,
             const std::string &strDebugMessageIn="") {
        reason = reasonIn;
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        strDebugMessage = strDebugMessageIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(ValidationInvalidReason _reason, bool ret = false,
                 unsigned int _chRejectCode=0, const std::string &_strRejectReason="",
                 const std::string &_strDebugMessage="") {
        return DoS(0, _reason, ret, _chRejectCode, _strRejectReason, false, _strDebugMessage);
    }
    bool Error(const std::string& strRejectReasonIn) {
        if (mode == MODE_VALID)
            strRejectReason = strRejectReasonIn;
        mode = MODE_ERROR;
        return false;
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    void SetCorruptionPossible() {
        corruptionPossible = true;
    }
    ValidationInvalidReason GetReason() const { return reason; }
    int GetDoS() const { return nDoS; }
    unsigned int GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
    std::string GetDebugMessage() const { return strDebugMessage; }
};

// These implement the weight = (stripped_size * 4) + witness_size formula,
// using only serialization with and without witness data. As witness_size
// is equal to total_size - stripped_size, this formula is identical to:
// weight = (stripped_size * 3) + total_size.
static inline int64_t GetTransactionWeight(const CTransaction& tx)
{
    return ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}
static inline int64_t GetBlockWeight(const CBlock& block)
{
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}

#endif // BITCOIN_CONSENSUS_VALIDATION_H
