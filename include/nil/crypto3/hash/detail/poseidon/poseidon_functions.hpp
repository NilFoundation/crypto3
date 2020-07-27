//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
#define CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>

#include <utility>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                template<
                    typename FieldT,
                    std::size_t t,
                    std::size_t c,
                    std::size_t DigestBits,
                    std::size_t M = 128,
                    bool strength = true
                >
                struct poseidon_functions {
                    typedef poseidon_policy<
                        FieldT,
                        t,
                        c,
                        DigestBits,
                        M,
                        strength
                    > policy_type;

                    constexpr static std::size_t const state_bits = policy_type::state_bits;
                    constexpr static std::size_t const state_words = policy_type::state_words;
                    typedef policy_type::state_type state_type;

                    // TODO: constexpr
                    // (full_rounds, partial_rounds)
                    std::pair<std::size_t, std::size_t> num_rounds = get_num_rounds();
                    typedef std::pair<std::size_t, std::size_t> rounds_type;

                    // TODO: constexpr
                    std::size_t const round_constants_size = (std::get<0>(num_rounds) + std::get<1>(num_rounds)) * t;
                    typedef typename std::array<FieldT, round_constants_size> round_constants_type;

                    

                    // static variant only for bls12-381 - filecoin oriented implementation
                    // this round numbers seems not to be right according current version of the script https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/c984df1034874adf5cb5784bf86b609b0a8d6f99
                    std::pair<std::size_t, std::size_t> get_num_rounds() {
                        std::size_t full_rounds = 6;
                        std::size_t part_rounds;
                        switch (t) {
                            case 2:
                            case 3:
                                part_rounds = 55;
                                break;
                            case 4:
                            case 5:
                            case 6:
                            case 7:
                                part_rounds = 56;
                                break;
                            case 8:
                            case 9:
                            case 10:
                            case 11:
                            case 12:
                                part_rounds = 57;
                                break;
                            case 17:
                            case 25:
                                part_rounds = 59;
                                break;
                            case 37:
                                part_rounds = 60;
                                break;
                            case 65:
                                part_rounds = 61;
                                break;
                            default:
                                BOOST_ASSERT_MSG(false, "invalid width of permutation");
                        }

                        if (strength) {
                            full_rounds += 2;
                            part_rounds = ceil(part_rounds * 1.075);
                        }

                        return std::make_pair(full_rounds, part_rounds);
                    }

                    static inline void permute(state_type &A) {
                        
                    }


                }

            }       // detail
        }       // hashes
    }       // crypto3
}       // nil


#endif      // CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
