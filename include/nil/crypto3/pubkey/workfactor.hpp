#ifndef CRYPTO3_PUBKEY_WORKFACTOR_HPP
#define CRYPTO3_PUBKEY_WORKFACTOR_HPP

#include <nil/crypto3/utilities/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                size_t nfs_workfactor(size_t bits, double k) {
                    // approximates natural logarithm of integer of given bitsize
                    const double log2_e = std::log2(std::exp(1));
                    const double log_p = bits / log2_e;

                    const double log_log_p = std::log(log_p);

                    // RFC 3766: k * e^((1.92 + o(1)) * cubrt(ln(n) * (ln(ln(n)))^2))
                    const double est = 1.92 * std::pow(log_p * log_log_p * log_log_p, 1.0 / 3.0);

                    // return log2 of the workfactor
                    return static_cast<size_t>(std::log2(k) + log2_e * est);
                }
            }    // namespace detail

            /**
             * Return the appropriate exponent size to use for a particular prime
             * group. This is twice the size of the estimated cost of breaking the
             * key using an index calculus attack; the assumption is that if an
             * arbitrary discrete log on a group of size bits would take about 2^n
             * effort, and thus using an exponent of size 2^(2*n) implies that all
             * available attacks are about as easy (as e.g Pollard's kangaroo
             * algorithm can compute the DL in sqrt(x) operations) while minimizing
             * the exponent size for performance reasons.
             */

            size_t dl_exponent_size(size_t prime_group_size) {
                /*
                This uses a slightly tweaked version of the standard work factor
                function above. It assumes k is 1 (thus overestimating the strength
                of the prime group by 5-6 bits), and always returns at least 128 bits
                (this only matters for very small primes).
                */
                const size_t MIN_WORKFACTOR = 64;

                return 2 * std::max<std::size_t>(MIN_WORKFACTOR, detail::nfs_workfactor(prime_group_size, 1));
            }

            /**
             * Estimate work factor for integer factorization
             * @param n_bits size of modulus in bits
             * @return estimated security level for this modulus
             */

            size_t if_work_factor(size_t n_bits) {
                // RFC 3766 estimates k at .02 and o(1) to be effectively zero for sizes of interest

                return detail::nfs_workfactor(n_bits, .02);
            }

            /**
             * Estimate work factor for discrete logarithm
             * @param prime_group_size size of the group in bits
             * @return estimated security level for this group
             */

            size_t dl_work_factor(size_t prime_group_size) {
                // Lacking better estimates...
                return if_work_factor(prime_group_size);
            }

            /**
             * Estimate work factor for EC discrete logarithm
             * @param prime_group_size size of the group in bits
             * @return estimated security level for this group
             */

            size_t ecp_work_factor(size_t prime_group_size) {
                return prime_group_size / 2;
            }
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
