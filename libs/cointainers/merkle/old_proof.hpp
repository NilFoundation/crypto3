//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>

//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_PROOF_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_PROOF_HPP

#include <algorithm>
#include <vector>

#include <boost/variant.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/filecoin/storage/proofs/core/merkle/merkle.hpp>
#include <nil/filecoin/storage/proofs/core/proof/proof.hpp>
#include <nil/filecoin/storage/proofs/core/crypto/feistel.hpp>
#include <nil/filecoin/storage/proofs/core/path_element.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t base_path_length(std::size_t leaves) {
                std::size_t l;
                if (C > 0) {
                    l = leaves / C / B;
                } else if (B > 0) {
                    l = leaves / B;
                } else {
                    l = leaves;
                }

                return graph_height<A>(l) - 1;
            }

            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t compound_path_length(std::size_t leaves) {
                std::size_t len = base_path_length<A, B, C>(leaves);
                if (B > 0) {
                    len += 1;
                }

                if (C > 0) {
                    len += 1;
                }

                return len;
            }

            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t compound_tree_height(std::size_t leaves) {
                // base layer
                std::size_t a = graph_height<A>(leaves) - 1;

                // sub tree layer
                std::size_t b;
                if (B > 0) {
                    b = B - 1;
                } else {
                    b = 0;
                }

                // top tree layer
                std::size_t c;
                if (C > 0) {
                    c = C - 1;
                } else {
                    c = 0;
                }

                return a + b + c;
            }

            template<typename Hash>
            struct Proof_basic_policy {
                typedef std::array<uint8_t, Hash::digest_size> hash_result_type;
                constexpr static const std::size_t hash_digest_size = Hash::digest_size;
            };

            template<typename Hash, std::size_t BaseTreeArity = 2>
            struct Proof {

                typedef typename MerkleTree_basic_policy<Hash>::hash_result_type element;
                constexpr static const std::size_t element_size = MerkleTree_basic_policy<Hash>::hash_digest_size;

                // Optional proofs at immediate lower level from current.  Should
                // be None at the base layer.
                std::shared_ptr<Proof<element, BaseTreeArity>> sub_tree_proof;
                std::size_t top_layer_nodes;         // arity of top layer
                std::size_t sub_tree_layer_nodes;    // arity of sub-tree
                std::vector<element> lemma; // layer
                std::vector<std::size_t> path; // branch index

                /// Creates new MT inclusion proof
                template<std::size_t TopLayerArity, std::size_t SubTreeArity>
                Proof(std::shared_ptr<Proof<element, BaseTreeArity>> sub_tree_proof, const std::vector<element> &lemma, const
                      std::vector<std::size_t> &path) : sub_tree_proof(sub_tree_proof), top_layer_nodes(TopLayerArity),
                    sub_tree_layer_nodes(SubTreeArity), lemma(lemma), path(path){
                    if (TopLayerArity == 0 && SubTreeArity == 0) {
                        BOOST_ASSERT_MSG(lemma.size() > 2, "Invalid lemma length (short)");
                        BOOST_ASSERT_MSG(lemma.size() == utilities::get_merkle_proof_lemma_len(path.size() + 1, BaseTreeArity),
                            "Invalid lemma length");
                    }
                }

                /// Return proof target leaf
                element item() {
                    return *lemma.begin();
                }

                /// Return sub tree root
                element sub_tree_root() {
                    assert(sub_tree_layer_nodes > 0 && sub_tree_proof.is_some());
                    return sub_tree_proof.root();
                }

                /// Return tree root
                element root() {
                    return *(lemma.end() - 1);
                }

                /// Validates sub-tree proofs with the specified arity.
                bool validate_sub_tree_proof(std::size_t arity) {
                    // Ensure that the sub_tree validates to the root of that
                    // sub_tree.
                    bool valid = sub_tree_proof.unwrap().validate::<Algorithm<element>>();
                    if (!valid) {
                            return valid;
                        }

                    // Validate top-most/current layer
                    //
                    // Check that the remaining proof matches the tree root (note
                    // that Proof::validate at the base layer cannot handle a
                    // proof this small, so this is a version specific for what we
                    // know we have in this case).
                    auto a = Algorithm<T>::default();
                    a.reset();
                    const auto node_count = arity;
                    const auto h = {
                        std::vector<T> nodes;
                        nodes.reserve(node_count);

                        auto cur_index = 0;
                        for (const auto j = 0; j < node_count; ++j) {
                            if j == self.path()[0] {
                                nodes.push(self.sub_tree_root().clone());
                            } else {
                                nodes.push(self.lemma()[cur_index].clone());
                                cur_index += 1;
                            }
                        }

                        if cur_index != node_count - 1 {
                            return false;
                        }

                        a.multi_node(&nodes, 0)
                    };

                    return h == root();
                }

                /// Verifies MT inclusion proof
                bool validate() {
                    if (top_layer_nodes > 0) {
                        // Special Top layer handling here.
                        BOOST_ASSERT_MSG(sub_tree_proof,
                                "Sub tree proof must be present for validation");

                        return validate_sub_tree_proof<Algorithm>(top_layer_nodes);
                    }

                    if (sub_tree_layer_nodes > 0) {
                        // Sub-tree layer handling here.
                        BOOST_ASSERT_MSG(sub_tree_proof,
                                "Sub tree proof must be present for validation");

                        return validate_sub_tree_proof<Algorithm>(sub_tree_layer_nodes);
                    }

                    // Base layer handling here.
                    BOOST_ASSERT_MSG(sub_tree_layer_nodes == 0, "Base layer proof must have 0 as sub-tree layer node count");
                    BOOST_ASSERT_MSG(top_layer_nodes == 0, "Base layer proof must have 0 as top layer node count");
                    BOOST_ASSERT_MSG(!sub_tree_proof, "Sub tree proof must be None");

                    std::size_t size = lemma.size();
                    if (size < 2) {
                        return false;
                    }

                    std::size_t branches = BaseTreeArity;
                    auto a = Algorithm<element>::default();
                    auto h = this->item();
                    auto path_index = 1;

                    for (size_t i = 1; i < size - 1; i += branches - 1) {
                        a.reset();
                        h = {
                            std::vector<element> nodes;
                            nodes.reserve(branches);
                            auto cur_index = 0;
                            for (j = 0; j < branches; ++j) {
                                if j == self.path[path_index - 1] {
                                    nodes.push(h.clone());
                                } else {
                                    nodes.push(self.lemma[i + cur_index].clone());
                                    cur_index += 1;
                                }
                            }

                            if cur_index != branches - 1 {
                                return false;
                            }

                            path_index += 1;
                            a.multi_node(&nodes, i - 1)
                        };
                    }

                    return h == root();
                }

                    /// Verifies MT inclusion proof and that leaf_data is the original leaf data for which proof was generated.
                template<template<typename> class Algorithm>
                bool validate_with_data(leaf_data: &dyn Hashable<A>) {
                    auto a = Algorithm<T>::default();
                    leaf_data.hash(&a);
                    const auto item = a.hash();
                    a.reset();
                    const auto leaf_hash = a.leaf(item);

                    if (leaf_hash == item()) {
                        return validate<Algorithm>();
                    } else {
                        return false;
                    }
                }
            };

//            /// Interface to abstract over the concept of Merkle Proof.
//            template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity,
//                     typename FieldType = typename crypto3::algebra::curves::bls12<381>::scalar_field_type>
//            struct BasicMerkleProof {
//                typedef Hash hash_type;
//                typedef FieldType field_type;
//                typedef typename field_type::value_type fr_value_type;
//
//                constexpr static const std::size_t base_arity = BaseArity;
//                constexpr static const std::size_t sub_tree_arity = SubTreeArity;
//                constexpr static const std::size_t top_tree_arity = TopTreeArity;
//
//                /// Try to convert a merkletree proof into this structure.
//                static BasicMerkleProof<Hash, BaseArity, SubTreeArity, TopTreeArity>
//                    try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
//                }
//
//                std::vector<std::pair<std::vector<fr_value_type>, std::size_t>> as_options() {
//                    return path()
//                        .iter()
//                        .map(| v | {(v .0.iter().copied().map(Into::into).map(Some).collect(), Some(v .1), )})
//                        .collect::<Vec<_>>();
//                }
//
//                std::pair<fr_value_type, std::vector<std::pair<std::vector<fr_value_type>, std::size_t>>>
//                    into_options_with_leaf() {
//                    const auto leaf = leaf();
//                    const auto path = path();
//                    (Some(leaf.into()),
//                     path.into_iter()
//                         .map(| (a, b) | {(a.iter().copied().map(Into::into).map(Some).collect(), Some(b), )})
//                         .collect::<Vec<_>>(), )
//                }
//
//                std::vector<std::pair<std::vector<fr_value_type>, std::size_t>> as_pairs() {
//                    for (int i = 0; i < path().size(); i++) {
//
//                    }
//                        .iter()
//                        .map(| v | (v .0.iter().copied().map(Into::into).collect(), v .1))
//                        .collect::<Vec<_>>();
//                }
//
//                virtual bool verify() const = 0;
//
//                /// Validates the MerkleProof and that it corresponds to the supplied node.
//                ///
//                /// TODO: audit performance and usage in case verification is
//                /// unnecessary based on how it's used.
//                virtual bool validate(std::size_t node) {
//                    if (!verify()) {
//                        return false;
//                    }
//
//                    return node == path_index();
//                }
//
//                virtual bool validate_data(const typename Hash::digest_type &data) {
//                    if (!verify()) {
//                        return false;
//                    }
//
//                    return leaf() == data;
//                }
//
//                virtual typename Hash::digest_type leaf() = 0;
//                virtual typename Hash::digest_type root() = 0;
//                virtual std::size_t size() = 0;
//                virtual std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() = 0;
//
//                std::size_t path_index() {
//                    return std::accumulate(
//                        path().begin(), path().end(), 0,
//                        [&](std::size_t acc, typename std::vector<std::pair<std::vector<typename Hash::digest_type>,
//                                                                            std::size_t>>::value_type &val) -> std::size_t {
//                            return (acc + BaseArity) + val.second;
//                        });
//                }
//
//                bool proves_challenge(std::size_t challenge) {
//                    path_index() == challenge;
//                }
//
//                /// Calcluates the exected length of the full path, given the number of leaves in the base layer.
//                std::size_t expected_len(std::size_t leaves) {
//                    return compound_path_length<BaseArity, SubTreeArity, TopTreeArity>(leaves);
//                }
//            };
//
//            template<typename Hash, std::size_t BaseArity>
//            struct InclusionPath {
//                /// Calculate the root of this path, given the leaf as input.
//                typename Hash::digest_type root(const typename Hash::digest_type &leaf) {
//                    using namespace nil::crypto3;
//                    accumulator_set<Hash> acc;
//                    std::accumulate(path.begin(), path.end(), leaf,
//                                    [&](typename Hash::digest_type acc,
//                                        typename std::vector<PathElement<Hash, BaseArity>>::value_type &v) {
//
//                                    });
//                    auto a = H::Function::default();
//                    (0..self.path.len())
//                        .fold(
//                            leaf, | h, height | {
//                                a.reset();
//
//                                const auto index = self.path[height].index;
//                                auto nodes = self.path[height].hashes.clone();
//                                nodes.insert(index, h);
//
//                                a.multi_node(&nodes, height)
//                            })
//                }
//
//                std::size_t size() {
//                    return path.size();
//                }
//
//                bool empty() {
//                    return path.empty();
//                }
//
//                std::size_t path_index() {
//                    return std::accumulate(
//                        path.begin(), path.end(), 0,
//                        [&](std::size_t acc, typename std::vector<PathElement<Hash, BaseArity>>::value_type &v) {
//                            return (acc * BaseArity) + v.index;
//                        });
//                }
//
//                std::vector<PathElement<Hash, BaseArity>> path;
//            };
//
//            template<typename Hash, std::size_t BaseArity>
//            struct SingleProof {
//                template<template<typename, std::size_t> class Proof>
//                static SingleProof<Hash, BaseArity> try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
//                    return proof_to_single(p, 1);
//                }
//
//                bool verify() {
//                    return root == path.root(leaf);
//                }
//
//                std::size_t size() {
//                    return path.size() * (BaseArity - 1) + 2;
//                }
//
//                std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
//                    return path.iter().map(| x | (x.hashes.clone(), x.index)).collect::<Vec<_>>();
//                }
//
//                std::size_t path_index() {
//                    return path.path_index();
//                }
//
//                /// Root of the merkle tree.
//                typename Hash::digest_type root;
//                /// The original leaf data for this prof.
//                typename Hash::digest_type leaf;
//                /// The path from leaf to root.
//                InclusionPath<Hash, BaseArity> path;
//            };
//
//            template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity>
//            struct SubProof {
//                static SubProof<Hash, BaseArity, SubTreeArity>
//                    try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
//                    BOOST_ASSERT_MSG(p.sub_layer_nodes() == SubTreeArity, "sub arity mismatch");
//                    BOOST_ASSERT_MSG(p.sub_tree_proof, "Cannot generate sub proof without a base-proof");
//                    std::shared_ptr<Proof<typename Hash::digest_type, BaseArity>> base_p = p.sub_tree_proof;
//
//                    // Generate SubProof
//                    typename Hash::digest_type root = p.root();
//                    typename Hash::digest_type leaf = base_p.item();
//                    InclusionPath<Hash, BaseArity> base_proof =
//                        extract_path<typename Hash::digest_type, BaseArity>(base_p.lemma(), base_p.path(), 1);
//                    InclusionPath<Hash, SubTreeArity> sub_proof =
//                        extract_path<typename Hash::digest_type, SubTreeArity>(p.lemma(), p.path(), 0);
//
//                    return {base_proof, sub_proof, root, leaf};
//                }
//
//                bool verify() {
//                    root == sub_proof.root(base_proof.root(leaf));
//                }
//
//                std::size_t size() {
//                    return SubTreeArity;
//                }
//
//                std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
//                    return base_proof.iter()
//                        .map(| x | (x.hashes.clone(), x.index))
//                        .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
//                        .collect();
//                }
//
//                std::size_t path_index() {
//                    std::size_t base_proof_leaves = 1;
//                    for (int i = 0; i < base_proof.size(); i++) {
//                        base_proof_leaves *= BaseArity;
//                    }
//
//                    std::size_t sub_proof_index = sub_proof.path_index();
//
//                    return (sub_proof_index * base_proof_leaves) + base_proof.path_index();
//                }
//
//                InclusionPath<Hash, BaseArity> base_proof;
//
//                InclusionPath<Hash, SubTreeArity> sub_proof;
//
//                typename Hash::digest_type root;
//                /// The original leaf data for this prof.
//
//                typename Hash::digest_type leaf;
//            };
//
//            template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
//            struct TopProof {
//                TopProof<Hash, BaseArity, SubTreeArity, TopTreeArity>
//                    try_from_proof(const Proof<typename Hash::digest_type, BaseArity> &p) {
//                    BOOST_ASSERT_MSG(p.top_layer_nodes() == TopTreeArity, "top arity mismatch");
//                    BOOST_ASSERT_MSG(p.sub_layer_nodes() == SubTreeArity, "sub arity mismatch");
//
//                    BOOST_ASSERT_MSG(p.sub_tree_proof, "Cannot generate top proof without a sub-proof");
//                    const auto sub_p = p.sub_tree_proof;
//
//                    BOOST_ASSERT_MSG(sub_p.sub_tree_proof, "Cannot generate top proof without a base-proof");
//                    const auto base_p = sub_p.sub_tree_proof;
//
//                    const auto root = p.root();
//                    const auto leaf = base_p.item();
//
//                    return {extract_path<Hash, BaseArity>(base_p.lemma(), base_p.path(), 1), extract_path<Hash, SubTreeArity>(sub_p.lemma(), sub_p.path(), 0), extract_path<Hash, TopTreeArity>(p.lemma(), p.path(), 0), root, leaf};
//                }
//
//                bool verify() {
//                    root == top_proof.root(sub_proof.root(base_proof.root(leaf)));
//                }
//
//                std::size_t size() {
//                    return TopTreeArity;
//                }
//
//                std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() {
//                    return base_proof.iter()
//                        .map(| x | (x.hashes.clone(), x.index))
//                        .chain(self.sub_proof.iter().map(| x | (x.hashes.clone(), x.index)))
//                        .chain(self.top_proof.iter().map(| x | (x.hashes.clone(), x.index)))
//                        .collect();
//                }
//
//                std::size_t path_index() {
//                    std::size_t base_proof_leaves = 1;
//                    for (int i = 0; i < base_proof.size(); i++) {
//                        base_proof_leaves *= BaseArity;
//                    }
//
//                    return (sub_proof.path_index() * base_proof_leaves) +
//                           (top_proof.path_index() * base_proof_leaves * SubTreeArity) + base_proof.path_index();
//                }
//
//                InclusionPath<Hash, BaseArity> base_proof;
//
//                InclusionPath<Hash, SubTreeArity> sub_proof;
//
//                InclusionPath<Hash, TopTreeArity> top_proof;
//                /// Root of the merkle tree.
//
//                typename Hash::digest_type root;
//                /// The original leaf data for this prof.
//                typename Hash::digest_type leaf;
//            };
//
//            template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
//            using ProofData = boost::variant<SingleProof<Hash, BaseArity>, SubProof<Hash, BaseArity, SubTreeArity>,
//                                             TopProof<Hash, BaseArity, SubTreeArity, TopTreeArity>>;
//
//            template<typename Hash, std::size_t BaseArity, std::size_t SubTreeArity, std::size_t TopTreeArity>
//            struct MerkleProof : public BasicMerkleProof<Hash, BaseArity, SubTreeArity, TopTreeArity> {
//                typedef typename Hash::digest_type digest_type;
//                MerkleProof(std::size_t n) :
//                    data(SingleProof<Hash, BaseArity>(std::vector<PathElement<Hash, BaseArity>>(n), root, leaf)) {
//                }
//
//                virtual bool verify() const override {
//                    return false;
//                }
//                virtual bool validate(std::size_t node) override {
//                }
//                virtual bool validate_data(const digest_type &data) override {
//                }
//                virtual digest_type leaf() override {
//                    return nullptr;
//                }
//                virtual digest_type root() override {
//                    return nullptr;
//                }
//                virtual std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>> path() override {
//                    return std::vector<std::pair<std::vector<typename Hash::digest_type>, std::size_t>>();
//                }
//
//                ProofData<Hash, BaseArity, SubTreeArity, TopTreeArity> data;
//            };
//
//            /// 'lemma_start_index' is required because sub/top proofs start at
//            /// index 0 and base proofs start at index 1 (skipping the leaf at the
//            /// front)
//            template<typename Hash, std::size_t BaseArity>
//            InclusionPath<Hash, BaseArity> extract_path(const std::vector<typename Hash::digest_type> &lemma,
//                                                        const std::vector<std::size_t> &path,
//                                                        std::size_t lemma_start_index) {
//                std::vector<PathElement<Hash, BaseArity>> res;
//
//                for (int i = 0; i < path.size(); i++) {
//                    res.emplace_back(
//                        std::vector<typename Hash::digest_type>(lemma.begin() + lemma_start_index + BaseArity * i,
//                                                                lemma.begin() + lemma_start_index + BaseArity * (i + 1)),
//                        index);
//                }
//
//                return InclusionPath<Hash, BaseArity>(res);
//            }
//
//            /// Converts a merkle_light proof to a SingleProof
//            template<typename Hash, std::size_t BaseArity, std::size_t TargetArity,
//                     template<typename, std::size_t> class Proof>
//            SingleProof<Hash, TargetArity>
//                proof_to_single(const Proof<Hash, BaseArity> &proof, std::size_t lemma_start_index,
//                                typename Hash::digest_type &sub_root = typename Hash::digest_type()) {
//                typename Hash::digest_type root = proof.root();
//                typename Hash::digest_type leaf = sub_root.emplty() ? sub_root : proof.item();
//
//                InclusionPath<Hash, TargetArity> path =
//                    extract_path<Hash, TargetArity>(proof.lemma(), proof.path(), lemma_start_index);
//
//                return {path, root, leaf};
//            }
        }    // namespace merkletree    
    }    // namespace filecoin
}    // namespace nil

#endif
