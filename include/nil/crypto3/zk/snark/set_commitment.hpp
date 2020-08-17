//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SNARK_SET_COMMITMENT_HPP
#define CRYPTO3_ZK_SNARK_SET_COMMITMENT_HPP

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                typedef std::vector<bool> set_commitment;

                struct set_membership_proof {
                    std::size_t address;
                    merkle_authentication_path merkle_path;

                    bool operator==(const set_membership_proof &other) const;
                    std::size_t size_in_bits() const;
                    friend std::ostream &operator<<(std::ostream &out, const set_membership_proof &other);
                    friend std::istream &operator>>(std::istream &in, set_membership_proof &other);
                };

                template<typename HashT>
                class set_commitment_accumulator {
                private:
                    std::shared_ptr<merkle_tree<HashT>> tree;
                    std::map<std::vector<bool>, std::size_t> hash_to_pos;

                public:
                    std::size_t depth;
                    std::size_t digest_size;
                    std::size_t value_size;

                    set_commitment_accumulator(const std::size_t max_entries, const std::size_t value_size = 0);

                    void add(const std::vector<bool> &value);
                    bool is_in_set(const std::vector<bool> &value) const;
                    set_commitment get_commitment() const;

                    set_membership_proof get_membership_proof(const std::vector<bool> &value) const;
                };

                template<typename HashT>
                set_commitment_accumulator<HashT>::set_commitment_accumulator(const std::size_t max_entries,
                                                                              const std::size_t value_size) :
                    value_size(value_size) {
                    depth = static_cast<std::size_t>(std::ceil(std::log2(max_entries)));
                    digest_size = HashT::get_digest_len();

                    tree.reset(new merkle_tree<HashT>(depth, digest_size));
                }

                template<typename HashT>
                void set_commitment_accumulator<HashT>::add(const std::vector<bool> &value) {
                    assert(value_size == 0 || value.size() == value_size);
                    const std::vector<bool> hash = HashT::get_hash(value);
                    if (hash_to_pos.find(hash) == hash_to_pos.end()) {
                        const std::size_t pos = hash_to_pos.size();
                        tree->set_value(pos, hash);
                        hash_to_pos[hash] = pos;
                    }
                }

                template<typename HashT>
                bool set_commitment_accumulator<HashT>::is_in_set(const std::vector<bool> &value) const {
                    assert(value_size == 0 || value.size() == value_size);
                    const std::vector<bool> hash = HashT::get_hash(value);
                    return (hash_to_pos.find(hash) != hash_to_pos.end());
                }

                template<typename HashT>
                set_commitment set_commitment_accumulator<HashT>::get_commitment() const {
                    return tree->get_root();
                }

                template<typename HashT>
                set_membership_proof
                    set_commitment_accumulator<HashT>::get_membership_proof(const std::vector<bool> &value) const {
                    const std::vector<bool> hash = HashT::get_hash(value);
                    auto it = hash_to_pos.find(hash);
                    assert(it != hash_to_pos.end());

                    set_membership_proof proof;
                    proof.address = it->second;
                    proof.merkle_path = tree->get_path(it->second);

                    return proof;
                }

                bool set_membership_proof::operator==(const set_membership_proof &other) const {
                    return (this->address == other.address && this->merkle_path == other.merkle_path);
                }

                std::size_t set_membership_proof::size_in_bits() const {
                    if (merkle_path.empty()) {
                        return (8 * sizeof(address));
                    } else {
                        return (8 * sizeof(address) + merkle_path[0].size() * merkle_path.size());
                    }
                }

                std::ostream &operator<<(std::ostream &out, const set_membership_proof &proof) {
                    out << proof.address << "\n";
                    out << proof.merkle_path.size() << "\n";
                    for (std::size_t i = 0; i < proof.merkle_path.size(); ++i) {
                        algebra::output_bool_vector(out, proof.merkle_path[i]);
                    }

                    return out;
                }

                std::istream &operator>>(std::istream &in, set_membership_proof &proof) {
                    in >> proof.address;
                    algebra::consume_newline(in);
                    std::size_t tree_depth;
                    in >> tree_depth;
                    algebra::consume_newline(in);
                    proof.merkle_path.resize(tree_depth);

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        algebra::input_bool_vector(in, proof.merkle_path[i]);
                    }

                    return in;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_SET_COMMITMENT_HPP
