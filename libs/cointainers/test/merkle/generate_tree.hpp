//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef FILECOIN_TEST_STORAGE_PROOFS_CORE_MERKLE_GENERATE_TREE_HPP
#define FILECOIN_TEST_STORAGE_PROOFS_CORE_MERKLE_GENERATE_TREE_HPP

#include <vector>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <nil/filecoin/storage/proofs/core/sector.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            namespace detail {

                template<typename MerkleTreeType>
                std::size_t get_base_tree_leafs(std::size_t base_tree_size) {
                    return get_merkle_tree_leafs(base_tree_size, MerkleTreeType::base_arity);
                }

                template<typename MerkleTreeType, typename UniformRandomGenerator>
                std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
                    generate_base_tree(UniformRandomGenerator &rng, std::size_t nodes,
                                       boost::optional<const boost::filesystem::path &> temp_path) {
                    const auto elements =
                        (0..nodes).map(| _ | typename MerkleTreeType::hash_type::digest_type::random(rng)).collect::<Vec<_>>();

                    std::vector<std::uint8_t> data;
                    for (el : elements) {
                        data.extend_from_slice(el);
                    }

                    if (temp_path) {
                        std::uint64_t id = rng.gen();
                        boost::filesystem::path replica_path = temp_path.join(std::format("replica-path-{}", id));
                        StoreConfig config(*temp_path, std::format("test-lc-tree-{}", id),
                                           default_rows_to_discard(nodes, MerkleTreeType::base_arity));

                        auto tree =
                            MerkleTreeWrapper::try_from_iter_with_config(elements.iter().map(| v | (Ok(*v))), config).unwrap();

                        // Write out the replica data.
                        auto f = std::fs::File::create(&replica_path).unwrap();
                        f.write_all(&data).unwrap();

                        
                        // Beware: evil dynamic downcasting RUST MAGIC down below.
                        use std::any::Any;

                        if (const auto
                            Some(lc_tree) =
                                Any::downcast_mut::<merkle::MerkleTree <typename MerkleTreeType::hash_type::digest_type,
                            <typename MerkleTreeType::hash_type>::Function,
                            merkletree::store::LevelCacheStore <typename MerkleTreeType::hash_type::digest_type,
                            std::fs::File, >, MerkleTreeType::base_arity, MerkleTreeType::sub_tree_arity,
                            MerkleTreeType::top_tree_arity, >, > (tree.inner) ) {
                                lc_tree.set_external_reader_path(&replica_path).unwrap();
                            }

                        (data, tree)
                    } else {
                        (data, MerkleTreeWrapper::try_from_iter(elements.iter().map(| v | Ok(*v))).unwrap())
                    }
                }

                template<typename MerkleTreeType, typename UniformRandomGenerator>
                std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
                    generate_sub_tree(UniformRandomGenerator &rng,
                                      std::size_t nodes,
                                      boost::optional<const boost::filesystem::path &>
                                          temp_path) {
                    std::size_t base_tree_count = MerkleTreeType::sub_tree_arity;
                    std::size_t base_tree_size = nodes / base_tree_count;
                    std::vector<MerkleTreeType> trees(base_tree_count);
                    std::vector<std::uint8_t> data;

                    for (int i = 0; i < base_tree_count) {
                        const auto(inner_data, tree) =
                            generate_base_tree<UniformRandomGenerator, MerkleTreeType>(rng, base_tree_size, temp_path);
                        trees.push_back(tree);
                        data.extend(inner_data);
                    }

                    return std::make_tuple(data, trees);
                }

            }    // namespace detail

            /// Only used for testing, but can't cfg-test it as that stops exports.
            template<typename MerkleTreeType, typename UniformRandomGenerator = boost::random::mt19937>
            std::tuple<std::vector<std::uint8_t>, MerkleTreeType>
                generate_tree(UniformRandomGenerator &rng, std::size_t nodes,
                              boost::optional<const boost::filesystem::path &> temp_path) {
                std::size_t sub_tree_arity = MerkleTreeType::sub_tree_arity;
                std::size_t top_tree_arity = MerkleTreeType::top_tree_arity;

                if (top_tree_arity > 0) {
                    BOOST_ASSERT_MSG(sub_tree_arity != 0, "malformed tree with TopTreeArity > 0 and SubTreeARity == 0");

                    std::vector<MerkleTreeType> sub_trees(top_tree_arity);
                    std::vector<std::uint8_t> data;
                    for (int i = 0; i < top_tree_arity; i++) {
                        const auto(inner_data, tree) = generate_sub_tree<
                            UniformRandomGenerator,
                            MerkleTreeWrapper<typename MerkleTreeType::hash_type, MerkleTreeType::Store, MerkleTreeType::base_arity,
                                              MerkleTreeType::sub_tree_arity, typenum::U0>>(rng, nodes / top_tree_arity,
                                                                                            temp_path.clone());

                        sub_trees.push(tree);
                        data.extend(inner_data);
                    }
                    return std::make_tuple(data, MerkleTreeWrapper::from_sub_trees(sub_trees));
                } else if (sub_tree_arity > 0) {
                    return generate_sub_tree<UniformRandomGenerator, MerkleTreeType>(rng, nodes, temp_path);
                } else {
                    return generate_base_tree<UniformRandomGenerator, MerkleTreeType>(rng, nodes, temp_path);
                }
            }
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif // FILECOIN_TEST_STORAGE_PROOFS_CORE_MERKLE_GENERATE_TREE_HPP
