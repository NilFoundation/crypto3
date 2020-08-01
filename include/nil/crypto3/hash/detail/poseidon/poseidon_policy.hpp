//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_POLICY_HPP
#define CRYPTO3_HASH_POSEIDON_POLICY_HPP

#include <nil/crypto3/detail/static_digest.hpp>

#include <boost/static_assert.hpp>
#include <boost/assert.hpp>

#include <array>
#include <utility>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                /*!
                 * @brief Poseidon internal parameters
                 * @tparam FieldType
                 * @tparam t arity of Poseidon permutation in Field elements
                 * @tparam c capacity of sponge construction
                 * @tparam DigestBits
                 * @tparam M desired security level in bits
                 * @tparam strength
                 */
                // at this moment only for bls12-381 - filecoin oriented im
                template<typename FieldT, std::size_t t, std::size_t DigestBits, std::size_t M>
                struct base_poseidon_policy {

                    constexpr static std::size_t const digest_bits = DigestBits;

                    typedef FieldT word_type;

                    constexpr static std::size_t const state_bits = t * FieldT::modulus_bits;
                    constexpr static std::size_t const state_words = t;
                    typedef std::array<FieldT, t> state_type;

                    constexpr static std::size_t const block_bits = (t - 1) * FieldT::modulus_bits;
                    constexpr static std::size_t const block_words = t - 1;
                    typedef std::array<FieldT, t - 1> block_type;

                    constexpr static std::size_t const sec_level = M;

                    constexpr static std::size_t const modulus_bits = FieldT::modulus_bits;

                    struct iv_generator {
                        // TODO: return-value seems not to be const in reality
                        // TODO: maybe it would be done in constexpr way
                        state_type const &operator()() const {
                            static state_type const H0 = [](){
                                state_type H;
                                H.fill(FieldT(0));
                                return const_cast<state_type>(H);
                            }();
                            return H0;
                        }
                    };
                };


                template<typename FieldT, std::size_t t, std::size_t DigestBits, std::size_t M, bool strength>
                struct poseidon_policy;


                template<typename FieldT, std::size_t DigestBits, std::size_t M, bool strength>
                struct poseidon_policy<FieldT, 2, DigestBits, M, strength> :
                    base_poseidon_policy<FieldT, 2, DigestBits, M>
                {
                    constexpr static std::size_t const full_rounds = 8;
                    constexpr static std::size_t const half_full_rounds = 4;
                    constexpr static std::size_t const part_rounds = strength ? 69 : 55;
                };


                template<typename FieldT, std::size_t DigestBits, std::size_t M, bool strength>
                struct poseidon_policy<FieldT,3,DigestBits,M,strength> :
                    base_poseidon_policy<FieldT, 3, DigestBits, M>
                {
                    constexpr static std::size_t const full_rounds = 8;
                    constexpr static std::size_t const half_full_rounds = 4;
                    constexpr static std::size_t const part_rounds = strength ? 69 : 55;
                };


                template<typename FieldT, std::size_t DigestBits, std::size_t M, bool strength>
                struct poseidon_policy<FieldT, 4, DigestBits, M, strength> :
                    base_poseidon_policy< FieldT, 4, DigestBits, M>
                {
                    constexpr static std::size_t const full_rounds = 8;
                    constexpr static std::size_t const half_full_rounds = 4;
                    constexpr static std::size_t const part_rounds = strength ? 70 : 56;
                };

                template<typename FieldT, std::size_t DigestBits, std::size_t M, bool strength>
                struct poseidon_policy<FieldT, 5, DigestBits, M, strength> :
                    base_poseidon_policy< FieldT, 5, DigestBits, M>
                {
                    constexpr static std::size_t const full_rounds = 8;
                    constexpr static std::size_t const half_full_rounds = 4;
                    constexpr static std::size_t const part_rounds = strength ? 70 : 56;
                };

                // continue define partial specialized template classes for each arity separately...

            }         // namespace detail
        }             // namespace hashes
    }                 // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_POLICY_HPP
