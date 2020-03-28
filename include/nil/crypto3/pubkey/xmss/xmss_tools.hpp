#ifndef CRYPTO3_PUBKEY_XMSS_TOOLS_HPP
#define CRYPTO3_PUBKEY_XMSS_TOOLS_HPP

#include <iterator>
#include <type_traits>

#include <nil/crypto3/utilities/cpuid/cpuid.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

#if defined(CRYPTO3_TARGET_OS_HAS_THREADS)
#include <thread>
#include <chrono>

#include <nil/crypto3/pubkey/xmss/xmss_hash.hpp>
#endif

namespace nil {
    namespace crypto3 {

        /**
         * Helper tools for low level byte operations required
         * for the XMSS implementation.
         **/
        class XMSS_Tools final {
        public:
            XMSS_Tools(const XMSS_Tools &) = delete;

            void operator=(const XMSS_Tools &) = delete;

            /**
             * Concatenates the byte representation in big-endian order of any
             * integral value to a secure_vector.
             *
             * @param target Vector to concatenate the byte representation of the
             *               integral value to.
             * @param src integral value to concatenate.
             **/
            template<typename T, typename U = typename std::enable_if<std::is_integral<T>::value, void>::type>
            static void concat(secure_vector<uint8_t> &target, const T &src);

            /**
             * Concatenates the last n bytes of the byte representation in big-endian
             * order of any integral value to a to a secure_vector.
             *
             * @param target Vector to concatenate the byte representation of the
             *               integral value to.
             * @param src Integral value to concatenate.
             * @param len number of bytes to concatenate. This value must be smaller
             *            or equal to the size of type T.
             **/
            template<typename T, typename U = typename std::enable_if<std::is_integral<T>::value, void>::type>
            static void concat(secure_vector<uint8_t> &target, const T &src, size_t len);

            /**
             * Not a public API function - will be removed in a future release.
             *
             * Determines the maximum number of threads to be used
             * efficiently, based on runtime timining measurements. Ideally the
             * result will correspond to the physical number of cores. On systems
             * supporting simultaneous multi threading (SMT)
             * std::thread::hardware_concurrency() usually reports a supported
             * number of threads which is bigger (typically by a factor of 2) than
             * the number of physical cores available. Using more threads than
             * physically available cores for computationally intesive tasks
             * resulted in slowdowns compared to using a number of threads equal to
             * the number of physical cores on test systems. This function is a
             * temporary workaround to prevent performance degradation due to
             * overstressing the CPU with too many threads.
             *
             * @return Presumed number of physical cores based on timing measurements.
             **/
            static size_t max_threads();    // TODO: Remove max_threads() and use
            // nil::crypto3::CPUID once proper plattform
            // independent detection of physical cores is
            // available.

        private:
            XMSS_Tools();

            /**
             * Measures the time t1 it takes to calculate hashes using
             * std::thread::hardware_concurrency() many threads and the time t2
             * calculating the same number of hashes using
             * std::thread::hardware_concurrency() / 2 threads.
             *
             * @return std::thread::hardware_concurrency() if t1 < t2
             *         std::thread::hardware_concurrency() / 2 otherwise.
             **/
            static size_t bench_threads();    // TODO: Remove bench_threads() and use
            // nil::crypto3::CPUID once proper plattform
            // independent detection of physical cores
            // is //available.
        };

        template<typename T, typename U>
        void XMSS_Tools::concat(secure_vector<uint8_t> &target, const T &src) {
            const uint8_t *src_bytes = reinterpret_cast<const uint8_t *>(&src);
            if (cpuid::is_little_endian()) {
                std::reverse_copy(src_bytes, src_bytes + sizeof(src), std::back_inserter(target));
            } else {
                std::copy(src_bytes, src_bytes + sizeof(src), std::back_inserter(target));
            }
        }

        template<typename T, typename U>
        void XMSS_Tools::concat(secure_vector<uint8_t> &target, const T &src, size_t len) {
            size_t c = static_cast<size_t>(std::min(len, sizeof(src)));
            if (len > sizeof(src)) {
                target.resize(target.size() + len - sizeof(src), 0);
            }

            const uint8_t *src_bytes = reinterpret_cast<const uint8_t *>(&src);
            if (cpuid::is_little_endian()) {
                std::reverse_copy(src_bytes, src_bytes + c, std::back_inserter(target));
            } else {
                std::copy(src_bytes + sizeof(src) - c, src_bytes + sizeof(src), std::back_inserter(target));
            }
        }

#if defined(CRYPTO3_TARGET_OS_HAS_THREADS)

        size_t XMSS_Tools::max_threads() {
            static const size_t threads {bench_threads()};
            return threads;
        }

        size_t XMSS_Tools::bench_threads() {
            if (std::thread::hardware_concurrency() <= 1) {
                return 1;
            }
            const size_t BENCH_ITERATIONS = 1000;
            std::vector<std::thread> threads;
            threads.reserve(std::thread::hardware_concurrency());
            std::vector<std::chrono::nanoseconds> durations;

            std::vector<size_t> concurrency {std::thread::hardware_concurrency(),
                                             std::thread::hardware_concurrency() / 2};

            for (const auto &cc : concurrency) {
                std::vector<XMSS_Hash> hash(std::thread::hardware_concurrency(), XMSS_Hash("SHA-256"));

                const std::vector<uint8_t> buffer(hash[0].output_length());
                std::vector<secure_vector<uint8_t>> data(std::thread::hardware_concurrency(),
                                                         secure_vector<uint8_t>(hash[0].output_length()));
                auto start = std::chrono::high_resolution_clock::now();
                for (size_t i = 0; i < cc; ++i) {
                    auto &hs = hash[i];
                    auto &d = data[i];

                    const size_t n_iters = BENCH_ITERATIONS * (std::thread::hardware_concurrency() / cc);
                    threads.emplace_back(std::thread([n_iters, &hs, &d]() {
                        for (size_t n = 0; n < n_iters; n++) {
                            hs.h(d, d, d);
                        }
                    }));
                }
                durations.emplace_back(std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::high_resolution_clock::now() - start));
                for (auto &t : threads) {
                    t.join();
                }
                threads.clear();
            }

            if (durations[0].count() < durations[1].count()) {
                return concurrency[0];
            } else {
                return concurrency[1];
            }
        }

#endif
    }    // namespace crypto3
}    // namespace nil

#endif
