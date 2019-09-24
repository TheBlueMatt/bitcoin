#include <chainparams.h>
#include <validation.h>
#include <shutdown.h>
#include <serialize.h>
#include <consensus/validation.h>
#include <random.h>
#include <logging.h>

/** A class that deserializes a single thing one time. */
class InputStream
{
public:
    InputStream(int nTypeIn, int nVersionIn, const unsigned char *data, size_t datalen) :
    m_type(nTypeIn),
    m_version(nVersionIn),
    m_data(data),
    m_remaining(datalen)
    {}

    void read(char* pch, size_t nSize)
    {
        if (nSize > m_remaining)
            throw std::ios_base::failure(std::string(__func__) + ": end of data");

        if (pch == nullptr)
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");

        if (m_data == nullptr)
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");

        memcpy(pch, m_data, nSize);
        m_remaining -= nSize;
        m_data += nSize;
    }

    template<typename T>
    InputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    int GetVersion() const { return m_version; }
    int GetType() const { return m_type; }
private:
    const int m_type;
    const int m_version;
    const unsigned char* m_data;
    size_t m_remaining;
};

extern "C" {

bool rusty_IsInitialBlockDownload() {
    return ::ChainstateActive().IsInitialBlockDownload();
}

bool rusty_ShutdownRequested() {
    return ShutdownRequested();
}

void rusty_ProcessNewBlock(const uint8_t* blockdata, size_t blocklen, const void* pindexvoid) {
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    CBlock block;
    try {
        InputStream(SER_NETWORK, PROTOCOL_VERSION, blockdata, blocklen) >> block;
    } catch (...) {}
    if (pindex && block.GetHash() == pindex->GetBlockHash()) {
        ProcessNewBlock(::Params(), std::make_shared<const CBlock>(block), true, nullptr);
    } else {
        ProcessNewBlock(::Params(), std::make_shared<const CBlock>(block), false, nullptr);
    }
}

const void* rusty_ConnectHeaders(const uint8_t* headers_data, size_t stride, size_t count) {
    std::vector<CBlockHeader> headers;
    for(size_t i = 0; i < count; i++) {
        CBlockHeader header;
        try {
            InputStream(SER_NETWORK, PROTOCOL_VERSION, headers_data + (stride * i), 80) >> header;
        } catch (...) {}
        headers.push_back(header);
    }
    CValidationState state_dummy;
    const CBlockIndex* last_index = nullptr;
    ProcessNewBlockHeaders(headers, state_dummy, ::Params(), &last_index);
    return last_index;
}

const void* rusty_GetChainTip() {
    LOCK(cs_main);
    const CBlockIndex* tip = ::ChainActive().Tip();
    assert(tip != nullptr);
    return tip;
}

const void* rusty_GetBestHeader() {
    LOCK(cs_main);
    assert(pindexBestHeader != nullptr);
    return pindexBestHeader;
}

const void* rusty_GetGenesisIndex() {
    LOCK(cs_main);
    const CBlockIndex* genesis = ::ChainActive().Genesis();
    assert(genesis != nullptr);
    return genesis;
}

const void* rusty_HeightToIndex(const int32_t height) {
    LOCK(cs_main);
    return ::ChainActive()[height];
}

int32_t rusty_IndexToHeight(const void* pindexvoid) {
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    assert(pindex != nullptr);
    return pindex->nHeight;
}

const uint8_t* rusty_IndexToHash(const void* pindexvoid) {
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    assert(pindex != nullptr);
    return pindex->phashBlock->begin();
}

void rusty_SerializeIndex(const void* pindexvoid, unsigned char* eighty_bytes_dest) {
    //TODO: Could optimize this a bit
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    std::vector<unsigned char> ser;
    ser.reserve(80);
    CVectorWriter(SER_NETWORK, PROTOCOL_VERSION, ser, 0) << pindex->GetBlockHeader();
    assert(ser.size() == 80);
    memcpy(eighty_bytes_dest, ser.data(), 80);
}

void* rusty_ProviderStateInit(const void* pindexvoid) {
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    BlockProviderState* state = new BlockProviderState;
    state->m_best_known_block = pindex;
    return state;
}

void rusty_ProviderStateFree(void* providerindexvoid) {
    BlockProviderState* state = (BlockProviderState*) providerindexvoid;
    delete state;
}

void rusty_ProviderStateSetBest(void* providerindexvoid, const void* pindexvoid) {
    BlockProviderState* state = (BlockProviderState*) providerindexvoid;
    const CBlockIndex *pindex = (const CBlockIndex*) pindexvoid;
    state->m_best_known_block = pindex;
}

const void* rusty_ProviderStateGetNextDownloads(void* providerindexvoid, bool has_witness) {
    BlockProviderState* state = (BlockProviderState*) providerindexvoid;
    std::vector<const CBlockIndex*> blocks;
    LOCK(cs_main);
    state->FindNextBlocksToDownload(has_witness, 1, blocks, ::Params().GetConsensus(), [] (const uint256& block_hash) { return false; });
    return blocks.empty() ? nullptr : blocks[0];
}

void rusty_ProvideEntropy(const unsigned char* buf, size_t num) {
    AddEntropy(buf, num);
}

void rusty_LogLine(const unsigned char* str, bool debug) {
    if (debug) {
        LogPrint(BCLog::RUST, "%s\n", str);
    } else {
        LogPrintf("%s\n", str);
    }
}

void rusty_AcceptToMemoryPool(const unsigned char* txdata, size_t txdatalen) {
    CTransactionRef tx;
    try {
        InputStream(SER_NETWORK, PROTOCOL_VERSION, txdata, txdatalen) >> tx;
    } catch (...) {}
    LOCK(cs_main);
    CValidationState state_dummy;
    AcceptToMemoryPool(::mempool, state_dummy, tx, nullptr, nullptr, false, 0);
}

#include <termios.h>
#include <unistd.h>
bool rusty_set_char_dev_raw_115200(int fd) {
    struct termios term;
    if (tcgetattr(fd, &term) != 0) {
        return false;
    }
    if (cfsetspeed(&term, B115200) != 0) {
        return false;
    }
    cfmakeraw(&term);
    if (tcsetattr(fd, TCSANOW, &term) != 0) {
        return false;
    }
    return true;
}

#include <sys/select.h>
uint8_t rusty_select(int fd, bool await_write, long timeout_sec, long timeout_usec) {
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(fd, &rd);
    struct timeval t;
    t.tv_sec = timeout_sec;
    t.tv_usec = timeout_usec;
    if (await_write) {
        fd_set wr;
        FD_ZERO(&wr);
        FD_SET(fd, &wr);
        select(fd + 1, &rd, &wr, nullptr, &t);
        return (FD_ISSET(fd, &rd) ? 1 : 0) |
            (FD_ISSET(fd, &wr) ? 0b10 : 0);
    } else {
        select(fd + 1, &rd, nullptr, nullptr, &t);
        return FD_ISSET(fd, &rd) ? 1 : 0;
    }
}

bool rusty_select_possible(int fd) {
    return fd <= FD_SETSIZE;
}

}
