//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of auxiliary functions for FOORAM.
//---------------------------------------------------------------------------//

#ifndef FOORAM_AUX_HPP_
#define FOORAM_AUX_HPP_

#include <iostream>
#include <vector>

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                typedef std::vector<std::size_t> fooram_program;
                typedef std::vector<std::size_t> fooram_input_tape;
                typedef typename std::vector<std::size_t>::const_iterator fooram_input_tape_iterator;

                class fooram_architecture_params {
                public:
                    std::size_t w;
                    fooram_architecture_params(const std::size_t w = 16);

                    std::size_t num_addresses() const;
                    std::size_t address_size() const;
                    std::size_t value_size() const;
                    std::size_t cpu_state_size() const;
                    std::size_t initial_pc_addr() const;

                    memory_contents initial_memory_contents(const fooram_program &program,
                                                            const fooram_input_tape &primary_input) const;

                    std::vector<bool> initial_cpu_state() const;
                    void print() const;
                    bool operator==(const fooram_architecture_params &other) const;

                    friend std::ostream &operator<<(std::ostream &out, const fooram_architecture_params &ap);
                    friend std::istream &operator>>(std::istream &in, fooram_architecture_params &ap);
                };

                fooram_architecture_params::fooram_architecture_params(const std::size_t w) : w(w) {
                }

                std::size_t fooram_architecture_params::num_addresses() const {
                    return 1ul << w;
                }

                std::size_t fooram_architecture_params::address_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::value_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::cpu_state_size() const {
                    return w;
                }

                std::size_t fooram_architecture_params::initial_pc_addr() const {
                    return 0;
                }

                memory_contents
                    fooram_architecture_params::initial_memory_contents(const fooram_program &program,
                                                                        const fooram_input_tape &primary_input) const {
                    memory_contents m;
                    /* fooram memory contents do not depend on program/input. */
                    BOOST_ATTRIBUTE_UNUSED(program, primary_input);
                    return m;
                }

                std::vector<bool> fooram_architecture_params::initial_cpu_state() const {
                    std::vector<bool> state;
                    state.resize(w, false);
                    return state;
                }

                void fooram_architecture_params::print() const {
                    printf("w = %zu\n", w);
                }

                bool fooram_architecture_params::operator==(const fooram_architecture_params &other) const {
                    return (this->w == other.w);
                }

                std::ostream &operator<<(std::ostream &out, const fooram_architecture_params &ap) {
                    out << ap.w << "\n";
                    return out;
                }

                std::istream &operator>>(std::istream &in, fooram_architecture_params &ap) {
                    in >> ap.w;
                    algebra::consume_newline(in);
                    return in;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // FOORAM_AUX_HPP_
