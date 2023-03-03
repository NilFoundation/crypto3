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
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename poseidon_policy>
                struct poseidon_sponge_construction {
                    private:
                        // typedef detail::field_type field_type
                        typedef poseidon_permutation<poseidon_policy> permutation_type;
                        std::size_t state_count = 0;
                        bool state_absorbed = true;

                    public:

                    std::array<typename poseidon_policy::element_type, poseidon_policy::state_words> state;

                    poseidon_sponge_construction() {
                        for (std::size_t i = 0; i < poseidon_policy::state_words; i++) {
                            this->state[i] = 0;
                        }

                        this->state_absorbed = true;
                        this->state_count = 0;
                    }

                    void absorb(std::vector<typename poseidon_policy::element_type>& inputs) {
                        for (auto &input : inputs) {
                            absorb(input);
                        }
                    }

                    void absorb(typename poseidon_policy::element_type &input){
                        if (this->state_absorbed) {
                            if (this->state_count == poseidon_policy::rate) {
                                permutation_type::permute(this->state);

                                this->state[0] += input;

                                this->state_count = 1;
                            } else {
                                this->state[this->state_count] += input;

                                this->state_count++;
                            }
                        } else {
                            this->state[0] += input;

                            this->state_absorbed = true;
                            this->state_count = 1;
                        }
                    }

                    typename poseidon_policy::element_type squeeze() {
                        if (!this->state_absorbed) { // state = squeezed
                            if (this->state_count == poseidon_policy::rate) {
                                permutation_type::permute(this->state);
                                this->state_count = 1;

                                return this->state[0];
                            } else {
                                return this->state[this->state_count++];
                            }
                        } else {
                            permutation_type::permute(this->state);

                            this->state_absorbed = false;
                            this->state_count = 1;

                            return this->state[0];
                        }
                    }

                    void reset() {
                        state.clear();

                        this->state_absorbed = true;
                        this->state_count = 0;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_SPONGE_HPP
