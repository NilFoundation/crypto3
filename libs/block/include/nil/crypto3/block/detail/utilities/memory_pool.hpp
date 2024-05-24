#ifndef CRYPTO3_MEM_POOL_HPP
#define CRYPTO3_MEM_POOL_HPP

#include <nil/crypto3/utilities/types.hpp>

#include <mutex>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace detail {
            inline bool ptr_in_pool(const void *pool_ptr, size_t poolsize, const void *buf_ptr, size_t bufsize) {
                const uintptr_t pool = reinterpret_cast<uintptr_t>(pool_ptr);
                const uintptr_t buf = reinterpret_cast<uintptr_t>(buf_ptr);
                return (buf >= pool) && (buf + bufsize <= pool + poolsize);
            }

            inline size_t padding_for_alignment(size_t n, size_t alignment) {
                const size_t mod = n % alignment;
                if (mod == 0) {
                    return 0;
                }
                return alignment - mod;
            }
        }    // namespace detail

        class memory_pool final {
        public:
            /**
             * Initialize a memory pool. The memory is not owned by *this,
             * it must be freed by the caller.
             * @param pool the pool
             * @param pool_size size of pool
             * @param page_size some nominal page size (does not need to match
             *        the system page size)
             * @param min_allocation return null for allocs for smaller amounts
             * @param max_allocation return null for allocs of larger amounts
             * @param align_bit align all returned memory to (1<<align_bit) bytes
             */
            memory_pool(uint8_t *pool, size_t pool_size, size_t page_size, size_t min_alloc, size_t max_alloc,
                        uint8_t align_bit) :
                m_page_size(page_size),
                m_min_alloc(min_alloc), m_max_alloc(max_alloc), m_align_bit(align_bit) {
                if (pool == nullptr) {
                    throw std::invalid_argument("memory_pool pool was null");
                }

                if (m_min_alloc > m_max_alloc) {
                    throw std::invalid_argument("memory_pool min_alloc > max_alloc");
                }

                if (m_align_bit > 6) {
                    throw std::invalid_argument("memory_pool invalid align_bit");
                }

                // This is basically just to verify that the range is valid
                clear_mem(pool, pool_size);

                m_pool = pool;
                m_pool_size = pool_size;
                m_freelist.emplace_back(0, m_pool_size);
            }

            void *allocate(size_t req) {
                const size_t alignment = (1 << m_align_bit);

                if (req > m_pool_size) {
                    return nullptr;
                }
                if (req < m_min_alloc || req > m_max_alloc) {
                    return nullptr;
                }

                std::lock_guard<std::mutex> lock(m_mutex);

                auto best_fit = m_freelist.end();

                for (auto i = m_freelist.begin(); i != m_freelist.end(); ++i) {
                    // If we have a perfect fit, use it immediately
                    if (i->second == req && (i->first % alignment) == 0) {
                        const size_t offset = i->first;
                        m_freelist.erase(i);
                        clear_mem(m_pool + offset, req);

                        BOOST_ASSERT_MSG((reinterpret_cast<uintptr_t>(m_pool) + offset) % alignment == 0,
                                         "Returning correctly aligned pointer");

                        return m_pool + offset;
                    }

                    if (((best_fit == m_freelist.end()) || (best_fit->second > i->second)) &&
                        (i->second >= (req + detail::padding_for_alignment(i->first, alignment)))) {
                        best_fit = i;
                    }
                }

                if (best_fit != m_freelist.end()) {
                    const size_t offset = best_fit->first;

                    const size_t alignment_padding = detail::padding_for_alignment(offset, alignment);

                    best_fit->first += req + alignment_padding;
                    best_fit->second -= req + alignment_padding;

                    // Need to realign, split the block
                    if (alignment_padding) {
                        /*
                        If we used the entire block except for small piece used for
                        alignment at the beginning, so just update the entry already
                        in place (as it is in the correct location), rather than
                        deleting the empty range and inserting the new one in the
                        same location.
                        */
                        if (best_fit->second == 0) {
                            best_fit->first = offset;
                            best_fit->second = alignment_padding;
                        } else {
                            m_freelist.insert(best_fit, std::make_pair(offset, alignment_padding));
                        }
                    }

                    clear_mem(m_pool + offset + alignment_padding, req);

                    BOOST_ASSERT_MSG((reinterpret_cast<uintptr_t>(m_pool) + offset + alignment_padding) % alignment ==
                                         0,
                                     "Returning correctly aligned pointer");

                    return m_pool + offset + alignment_padding;
                }

                return nullptr;
            }

            bool deallocate(void *p, std::size_t n) BOOST_NOEXCEPT {
                if (!detail::ptr_in_pool(m_pool, m_pool_size, p, n)) {
                    return false;
                }

                std::memset(p, 0, n);

                std::lock_guard<std::mutex> lock(m_mutex);

                const size_t start = static_cast<uint8_t *>(p) - m_pool;

                auto comp = [](std::pair<size_t, size_t> x, std::pair<size_t, size_t> y) { return x.first < y.first; };

                auto i = std::lower_bound(m_freelist.begin(), m_freelist.end(), std::make_pair(start, 0), comp);

                // try to merge with later block
                if (i != m_freelist.end() &&

                    start + n == i->first) {
                    i->first = start;
                    i->second += n;
                    n = 0;
                }

                // try to merge with previous block
                if (i != m_freelist.begin()) {
                    auto prev = std::prev(i);

                    if (prev->first + prev->second == start) {
                        if (n) {
                            prev->second += n;
                            n = 0;
                        } else {
                            // merge adjoining
                            prev->second += i->second;
                            m_freelist.erase(i);
                        }
                    }
                }

                if (n != 0) {    // no merge possible?
                    m_freelist.insert(i, std::make_pair(start, n));
                }

                return true;
            }

            memory_pool(const memory_pool &) = delete;

            memory_pool &operator=(const memory_pool &) = delete;

        private:
            const size_t m_page_size = 0;
            const size_t m_min_alloc = 0;
            const size_t m_max_alloc = 0;
            const uint8_t m_align_bit = 0;

            std::mutex m_mutex;

            std::vector<std::pair<size_t, size_t>> m_freelist;
            uint8_t *m_pool = nullptr;
            size_t m_pool_size = 0;
        };
    }    // namespace crypto3
}    // namespace nil

#endif