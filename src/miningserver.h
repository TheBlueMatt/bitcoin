// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MININGSERVER_H
#define BITCOIN_MININGSERVER_H

#include <key.h>
#include <netaddress.h>
#include <script/script.h>

struct LibeventContext;
class MiningServer {
private:
    std::unique_ptr<LibeventContext> m_event_ctx;

public:
    MiningServer(const CKey& auth_key, uint64_t node_id);
    ~MiningServer();

    /**
     * Helper to read the server privkey for auth
     */
    static bool ReadAuthKey(CKey& auth);

    // pyout_script should either be empty, or something to our local wallet/specified
    // by our local user in cli or so
    bool Start(const CService& bind_addr, const CScript& payout_script);
    void Interrupt();
    void Stop();
};

#endif
