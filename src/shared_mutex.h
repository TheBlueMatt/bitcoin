// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Compat-wrapper to create a simple shared_mutex without C++17

#ifndef BITCOIN_SHARED_MUTEX_H
#define BITCOIN_SHARED_MUTEX_H

#include <atomic>
#include <condition_variable>
#include <mutex>

namespace bitcoin_cpp17 {
    class shared_mutex {
    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic_bool m_writer_present;
        std::atomic_int64_t m_readers_present;

        void release_shared_count() {
            if (m_readers_present.fetch_sub(1) == -0xffffffff) {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                }
                m_cv.notify_all();
            }
        }

    public:
        typedef std::mutex::native_handle_type native_handle_type;

        shared_mutex();
        shared_mutex(const shared_mutex&) = delete;

        void lock() {
            bool writer_was_present = m_writer_present.exchange(true);
            while (writer_was_present) {
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_cv.wait(lock);
                }
                writer_was_present = m_writer_present.exchange(true);
            }
            // We're now the only writer!
            int64_t readers_present = m_readers_present.fetch_sub(0xffffffff);
            if (readers_present != 0) {
                std::unique_lock<std::mutex> lock(m_mutex);
                readers_present = m_readers_present.load(std::memory_order_relaxed);
                while (readers_present != -0xffffffff) {
                    m_cv.wait(lock);
                    readers_present = m_readers_present.load(std::memory_order_relaxed);
                }
            }
        }

        bool try_lock() {
            bool writer_was_present = m_writer_present.exchange(true);
            if (writer_was_present) return false;
            int64_t readers_present = m_readers_present.fetch_sub(0xffffffff);
            if (readers_present != 0) {
                m_readers_present.fetch_add(0xffffffff);
                m_writer_present = false;
                return false;
            }
        }

        void unlock() {
            m_readers_present.fetch_add(0xffffffff);
            m_writer_present = false;
            m_cv.notify_all();
        }

        void lock_shared() {
            int64_t prev_reader_count = m_readers_present.fetch_add(1);
            if (prev_reader_count < 0) {
                release_shared_count();
                std::unique_lock<std::mutex> lock(m_mutex);
                prev_reader_count = m_readers_present.fetch_add(1);
                while (prev_reader_count < 0) {
                    m_readers_present.fetch_sub(1);
                    m_cv.wait(lock);
                    prev_reader_count = m_readers_present.fetch_add(1);
                }
            }
        }

        bool try_lock_shared() {
            int64_t prev_reader_count = m_readers_present.fetch_add(1);
            if (prev_reader_count < 0) {
                release_shared_count();
                return false;
            }
            return true;
        }

        void unlock_shared() {
            release_shared_count();
        }

        native_handle_type native_handle() {
            return m_mutex.native_handle();
        }
    };
}

#endif
