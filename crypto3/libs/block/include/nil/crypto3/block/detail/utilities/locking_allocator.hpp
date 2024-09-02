#ifndef CRYPTO3_MLOCK_ALLOCATOR_HPP
#define CRYPTO3_MLOCK_ALLOCATOR_HPP

#include <nil/crypto3/utilities/detail/mem_pool/mem_pool.hpp>
#include <nil/crypto3/utilities/detail/os_utils.hpp>

#include <vector>
#include <memory>

namespace nil {
    namespace crypto3 {

        class memory_pool;

        class mlock_allocator final {
        public:
            static mlock_allocator &instance() {
                static mlock_allocator mlock;
                return mlock;
            }

            void *allocate(size_t num_elems, size_t elem_size) {
                if (!m_pool) {
                    return nullptr;
                }

                const size_t n = num_elems * elem_size;
                if (n / elem_size != num_elems) {
                    return nullptr;
                }    // overflow!

                return m_pool->allocate(n);
            }

            bool deallocate(void *p, size_t num_elems, size_t elem_size) BOOST_NOEXCEPT {
                if (!m_pool) {
                    return false;
                }

                size_t n = num_elems * elem_size;

                /*
                We return nullptr in allocate if there was an overflow, so if an
                overflow occurs here we know the pointer was not allocated by this pool.
                */
                if (n / elem_size != num_elems) {
                    return false;
                }

                return m_pool->deallocate(p, n);
            }

            mlock_allocator(const mlock_allocator &) = delete;

            mlock_allocator &operator=(const mlock_allocator &) = delete;

        private:
            mlock_allocator() {
                const size_t mem_to_lock = get_memory_locking_limit();

                if (mem_to_lock) {
                    m_locked_pages = static_cast<uint8_t *>(allocate_locked_pages(mem_to_lock));

                    if (m_locked_pages) {
                        m_locked_pages_size = mem_to_lock;
                        m_pool = std::make_unique<memory_pool>(m_locked_pages, m_locked_pages_size, system_page_size(),
                                                               CRYPTO3_MLOCK_ALLOCATOR_MIN_ALLOCATION,
                                                               CRYPTO3_MLOCK_ALLOCATOR_MAX_ALLOCATION, 4);
                    }
                }
            }

            ~mlock_allocator() {
                if (m_pool) {
                    m_pool.reset();
                    // free_locked_pages scrubs the memory before free
                    free_locked_pages(m_locked_pages, m_locked_pages_size);
                }
            }

            std::unique_ptr<memory_pool> m_pool;
            uint8_t *m_locked_pages = nullptr;
            size_t m_locked_pages_size = 0;
        };
    }    // namespace crypto3
}    // namespace nil

#endif