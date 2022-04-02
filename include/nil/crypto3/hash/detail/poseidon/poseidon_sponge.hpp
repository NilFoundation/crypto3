//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_SPONGE_HPP
#define CRYPTO3_HASH_POSEIDON_SPONGE_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_mds_matrix.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_constants_operator.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Rate, std::size_t Capacity, std::size_t SBoxPower, std::size_t FullRounds, std::size_t PartRounds>
                struct poseidon_extended_policy {
                    typedef FieldType field_type;
                    typedef typename field_type::value_type element_type;

                    constexpr static const std::size_t word_bits = field_type::modulus_bits;
                    typedef element_type word_type;

                    constexpr static const std::size_t digest_bits = field_type::modulus_bits;
                    typedef element_type digest_type;

                    constexpr static const std::size_t state_bits = (Rate + Capacity) * field_type::modulus_bits;
                    constexpr static const std::size_t state_words = (Rate + Capacity);
                    typedef std::array<element_type, Rate + Capacity> state_type;

                    constexpr static const std::size_t block_bits = Rate * field_type::modulus_bits;
                    constexpr static const std::size_t block_words = Rate;
                    typedef std::array<element_type, Rate> block_type;

                    constexpr static const std::size_t full_rounds = FullRounds;
                    constexpr static const std::size_t half_full_rounds = PartRounds;
                    constexpr static const std::size_t part_rounds = PartRounds;

                    constexpr static const std::size_t rate = Rate;
                    constexpr static const std::size_t capacity = Capacity;
                    constexpr static const std::size_t sbox_power = SBoxPower;

                    struct iv_generator {
                        // TODO: maybe it would be done in constexpr way
                        const state_type &operator()() const {
                            static const state_type H0 = []() {
                                state_type H;
                                H.fill(element_type(0));
                                return H;
                            }();
                            return H0;
                        }
                    };
                };

                template<typename poseidon_policy>
                struct poseidon_sponge_construction {

                    private:
                        typedef detail::poseidon_functions<typename poseidon_policy::field_type,
                            poseidon_policy::rate, poseidon_policy::capacity, 
                            poseidon_policy::sbox_power, poseidon_policy::part_rounds> poseidon_functions;

                        std::size_t state_count = 0;
                        std::size_t state_absorbed = true;

                    public:

                    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words> state;

                    poseidon_sponge_construction() {
                        for (std::size_t i = 0; i < poseidon_policy::state_words; i++) {
                            this->state[i] = 0;
                        }

                        this->state_absorbed = true;
                        this->state_count = 0;
                    }

                    void absorb(std::vector<typename poseidon_policy::element_type> input) {
                        for (std::size_t i = 0; i < input.size(); i++) {
                            if (this->state_absorbed) {
                                if (this->state_count == poseidon_policy::rate) {
                                    poseidon_functions::permute(this->state);

                                    this->state[0] += input[i];

                                    this->state_count = 1;
                                } else {
                                    this->state[this->state_count] += input[i];

                                    this->state_count++;
                                }
                            } else {
                                this->state[0] += input[i];

                                this->state_absorbed = true;
                                this->state_count = 1;
                            }
                        }
                    }

                    typename poseidon_policy::element_type squeeze() {
                        if (!this->state_absorbed) { // state = squeezed
                            if (this->state_count == poseidon_policy::rate) {
                                poseidon_functions::permute(this->state);
                                this->state_count = 1;

                                return this->state[0];
                            } else {
                                this->state_count++;

                                return this->state[this->state_count];
                            }
                        } else {
                            poseidon_functions::permute(this->state);

                            this->state_absorbed = false;
                            this->state_count = 1;

                            return this->state[0];
                        }
                    }

                    void reset() {
                        for (std::size_t i = 0; i < poseidon_policy::state_words; i++) {
                            state[i] = 0;
                        }

                        this->state_absorbed = true;
                        this->state_count = 0;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_SPONGE_HPP