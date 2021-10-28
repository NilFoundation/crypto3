//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MERKLE_HPP
#define CRYPTO3_MERKLE_HPP

#include <vector>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/merkle/utilities.hpp>

namespace nil {
    namespace crypto3 {
        namespace merkletree {
            struct Storage {
                Storage(size_t size, size_t branches, utilities::StoreConfig config) {
                    v.resize(size);
                    store_size = size;
                    len = 0;
                }

                Storage(size_t size) {
                    v.resize(size);
                    store_size = size;
                    len = 0;
                }

                void write(std::pair<uint8_t *, uint8_t *> el, size_t start) {
                    if (this->len < write + (el.second - el.first)) {
                        v.resize(write + (el.second - el.first));
                    }
                    for (auto i = el.first; i < el.second; ++i) {
                        v[write] = i;
                        ++write;
                    }
                    len += (el.second - el.first);
                }

                Storage(size_t size, size_t branches, std::pair<uint8_t *, uint8_t *> data, utilities::StoreConfig config) {
                    v.resize(size);
                    store_size = size;
                    self->write(data, 0);
                }

                Storage(size_t size, std::pair<uint8_t *, uint8_t *> data) {
                    v.resize(size);
                    store_size = size;
                    self->write(data, 0);
                }

                void read(std::pair<size_t, size_t> read, uint8_t *buf) {
                    uint8_t *buf_ptr = buf;
                    for (size_t i = read.first; i < read.second; ++i) {
                        buf_ptr = v[i];
                        ++buf_ptr;
                    }
                }

                bool is_empty() {
                    return v.empty();
                }

                void push(std::pair<uint8_t *, uint8_t *> data) {
                    self->write(data, len);
                }

            private:
                size_t len;
                size_t store_size;
                std::vector<uint8_t> v;
            };

            const size_t SMALL_TREE_BUILD = 1024;

            // Number of nodes to process in parallel during the `build` stage.
            const size_t BUILD_CHUNK_NODES = 1024 * 4;
            // Number of batched nodes processed and stored together when
            // populating from the data leaves.
            const size_t BUILD_DATA_BLOCK_SIZE = 64 * BUILD_CHUNK_NODES;

            // Merkle Tree.
            //
            // All leafs and nodes are stored in a linear array (vec).
            //
            // A merkle tree is a tree in which every non-leaf node is the hash of its
            // child nodes. A diagram depicting how it works://
            // ```text
            //         root = h1234 = h(h12 + h34)
            //        /                           \
            //  h12 = h(h1 + h2)            h34 = h(h3 + h4)
            //   /            \              /            \
            // h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
            // ```
            //
            // In memory layout:
            //
            // ```text
            //     [h1 h2 h3 h4 h12 h34 root]
            // ```
            //
            // Merkle root is always the last element in the array.

            template<typename Hash>
            struct MerkleTree_basic_policy {
                typedef std::array<uint8_t, Hash::digest_size> hash_result_type;
                constexpr static const std::size_t hash_digest_size = Hash::digest_size;
            };

            template<typename Hash, size_t BaseTreeArity = 2>
            struct MerkleTree {
                Storage data;

                typedef typename MerkleTree_basic_policy<Hash>::hash_result_type element;
                constexpr static const std::size_t element_size = MerkleTree_basic_policy<Hash>::hash_digest_size;

                size_t leafs;
                size_t len;
                // Note: The former 'upstream' merkle_light project uses 'height'
                // (with regards to the tree property) incorrectly, so we've
                // renamed it since it's actually a 'row_count'.  For example, a
                // tree with 2 leaf nodes and a single root node has a height of
                // 1, but a row_count of 2.
                //
                // Internally, this code considers only the row_count.
                size_t row_count;
                // Cache with the `root` of the tree built from `data`. This allows to
                // not access the `Store` (e.g., access to disks in `DiskStore`).
                element root;

                template<std::size_t Arity = 2>
                element build_small_tree(size_t leafs, size_t row_count) {
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");

                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;
                    size_t branches = Arity;
                    size_t shift = (size_t)std::log(branches);

                    size_t read_start;
                    size_t write_start;
                    while (width > 1) {
                        if (level == 0) {
                            read_start = 0;
                            write_start = data.len();
                        } else {
                            read_start = level_node_index;
                            write_start = level_node_index + width;
                        }

                        std::array<uint8_t, width * element_size> buf;
                        std::array<uint8_t, width * element_size / Arity> buf_result;
                        std::pair<size_t, size_t> r =
                            std::make_pair(read_start * element_size, (read_start + width) * element_size);
                        data.read(r, buf.begin());
                        BOOST_ASSERT_MSG((buf.size() / element_size) % Arity != 0, "Invalid count data for hashing");
                        for (size_t i = 0; i < buf.size() - element_size * Arity; i += element_size * Arity) {
                            root = crypto3::hash<Hash>(buf.begin() + i, buf.begin() + i + element_size * Arity);
                            std::copy(root.begin(), root.end(), buf_result.begin() + buf_result.size());
                        }
                        data.write(std::make_pair(buf_result.begin(), buf_result.end()), write_start * element_size);
                        level_node_index += width;
                        level += 1;
                        width >>= shift;    // width /= branches;
                    };
                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    return root;
                };

                template<std::size_t Arity = 2>
                void process_layer(size_t width, size_t level, size_t read_start, size_t write_start) {
                    size_t branches = Arity;

                    // Allocate `width` indexes during operation (which is a negligible memory bloat
                    // compared to the 32-bytes size of the nodes stored in the `Store`s) and hash each
                    // pair of nodes to write them to the next level in concurrent threads.
                    // Process `BUILD_CHUNK_NODES` nodes in each thread at a time to reduce contention,
                    // optimized for big sector sizes (small ones will just have one thread doing all
                    // the work).
                    BOOST_ASSERT_MSG(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
                    for (size_t chunk_index = read_start; chunk_index < read_start + width;
                         chunk_index += BUILD_CHUNK_NODES) {
                        size_t chunk_size = std::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);
                        std::array<uint8_t, BUILD_CHUNK_NODES * element_size> buf;
                        std::array<uint8_t, BUILD_CHUNK_NODES * element_size / Arity> buf_result;
                        data.read(std::make_pair(chunk_index * element_size, (chunk_index + chunk_size) * element_size),
                                  buf.begin());
                        BOOST_ASSERT_MSG((buf.size() / element_size) % Arity != 0, "Invalid count data for hashing");
                        for (size_t i = 0; i < buf.size() - element_size * Arity; i += element_size * Arity) {
                            root = crypto3::hash<Hash>(buf.begin() + i, buf.begin() + i + element_size * Arity);
                            std::copy(root.begin(), root.end(), buf_result.begin() + buf_result.size());
                        }
                        // We write the hashed nodes to the next level in the
                        // position that would be "in the middle" of the
                        // previous pair (dividing by branches).
                        size_t write_delta = (chunk_index - read_start) / branches;
                        size_t nodes_size = (buf.size() / element_size / branches) * element_size;
                        // Check that we correctly pre-allocated the space.
                        data.write(std::make_pair<buf.begin(), buf.end()>, (write_start + write_delta) * element_size);
                    }
                };

                // Default merkle-tree build, based on store type.
                template<std::size_t Arity = 2>
                element build(size_t leafs, size_t row_count, utilities::StoreConfig config) {
                    size_t branches = Arity;
                    BOOST_ASSERT_MSG(data.len() == leafs, "Inconsistent data");
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");

                    if (leafs <= SMALL_TREE_BUILD) {
                        return build_small_tree<Arity>(leafs, row_count);
                    }

                    size_t shift = (size_t)std::log(branches);

                    // Process one `level` at a time of `width` nodes. Each level has half the nodes
                    // as the previous one; the first level, completely stored in `data`, has `leafs`
                    // nodes. We guarantee an even number of nodes per `level`, duplicating the last
                    // node if necessary.
                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;
                    while (width > 1) {
                        // Start reading at the beginning of the current level, and writing the next
                        // level immediate after.  `level_node_index` keeps track of the current read
                        // starts, and width is updated accordingly at each level so that we know where
                        // to start writing.
                        size_t read_start;
                        size_t write_start;
                        if (level == 0) {
                            read_start = 0;
                            write_start = data.len();
                        } else {
                            read_start = level_node_index;
                            write_start = level_node_index + width;
                        }
                        process_layer<Arity>(width, level, read_start, write_start);
                        level_node_index += width;
                        level += 1;
                        width >>= shift;    // width /= branches;
                    }

                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root
                    return root;
                };

                /// Creates new merkle tree from an already allocated 'Store'
                /// (used with 'Store::new_from_disk').  The specified 'size' is
                /// the number of base data leafs in the MT.
                MerkleTree(Store data, size_t leafs) {
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(utilities::next_pow2(leafs) == leafs, "leafs MUST be a power of 2");
                    BOOST_ASSERT_MSG(utilities::next_pow2(branches) == branches, "branches MUST be a power of 2");

                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches);
                    BOOST_ASSERT_MSG(tree_len == data.len(), "Inconsistent tree data");

                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches),
                                     "MerkleTree size is invalid given the arity");

                    this->data = data;
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    this->root = data.read(data.len() - 1);
                }
                // Represent a fully constructed merkle tree from a provided slice.
                MerkleTree(std::pair<uint8_t *, uint8_t *> data, size_t leafs) {
                    size_t branches = BaseTreeArity;
                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches);
                    BOOST_ASSERT_MSG(tree_len == (data.first - data.second) / element_size, "Inconsistent tree data");

                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches),
                                     "MerkleTree size is invalid given the arity");

                    this->data = Store(tree_len, &data);
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    this->root = this->data.read((data.first - data.second) - element_size);
                }

                // Represent a fully constructed merkle tree from a provided slice.
                MerkleTree(std::pair<uint8_t *, uint8_t *> data, size_t leafs, utilities::StoreConfig config) {
                    size_t branches = BaseTreeArity;
                    size_t row_count = utilities::get_merkle_tree_row_count(leafs, branches);
                    size_t tree_len = utilities::get_merkle_tree_len(leafs, branches);
                    BOOST_ASSERT_MSG(tree_len == (data.first - data.second) / element_size, "Inconsistent tree data");

                    BOOST_ASSERT_MSG(utilities::is_merkle_tree_size_valid(leafs, branches),
                                     "MerkleTree size is invalid given the arity");
                    this->data = Store(tree_len, branches, &data, config);
                    this->leafs = leafs;
                    this->len = tree_len;
                    this->row_count = row_count;
                    this->root = this->data.read((data.first - data.second) - element_size);
                }

                // Truncates the data for later access via LevelCacheStore
                // interface.
                bool compact() {
                    return data.compact();
                }

                // Returns `true` if the store contains no elements.
                bool is_empty() {
                    return data.is_empty();
                }

                // Returns merkle leaf at index i
                element read_at(size_t i) {
                    element t;
                    data.read(std::make_pair<i * element_size, (i + 1) * element_size), t.begin());
                    return t;
                }

                std::vector<element> read_range(size_t start, size_t end) {
                    BOOST_ASSERT_MSG(start < end, "start must be less than end");
                    std::vector<element> res;
                    res.resize(end - start);
                    for (size_t i = start; i < end; ++i) {
                        data.read(std::make_pair<i * element_size, (i + 1) * element_size), res[i - start].begin())
                    }
                    return res;
                }

                // Reads into a pre-allocated slice (for optimization purposes).
                void read_into(size_t pos, uint8_t *buf) {
                    data.read(std::make_pair<pos * element_size, (pos + 1) * element_size), buf);
                }

                // Build the tree given a slice of all leafs, in bytes form.
                pub fn from_byte_slice_with_config(uint8_t* leafs : &[u8], utilitites::StoreConfig config) {
                    BOOST_ASSERT_MSG(
                        leafs.len() % element_size == 0, "{} ist not a multiple of {}", leafs.len(), E::byte_len());

                    size_t leafs_count = leafs.len() / element_size;
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(leafs_count > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(utilities::next_pow2(leafs_count) == leafs_count, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(utilities::next_pow2(branches) == branches, "branches MUST be a power of 2");

                    let size = utilities::get_merkle_tree_len(leafs_count, branches());
                    let row_count = utilities::get_merkle_tree_row_count(leafs_count, branches);

                     let root = S::build::<A, BaseTreeArity>(&mut data, leafs_count, row_count, Some(config)) ? ;
                    this->data = Store(size, branches, leafs, config.clone());
                    this->leafs = leafs_count;
                    this->len = size;
                    this->row_count = row_count;
                }

                // Attempts to create a new merkle tree using hashable objects yielded by
                // the provided iterator. This method returns the first error yielded by
                // the iterator, if the iterator yielded an error.
                // try_from_iter
                MerkleTree(std::pair<uint8_t *, uint8_t *> data) {
                    size_t leafs = (data.second - data.first) / element_size;
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(leafs > 1, "not enough leaves");
                    BOOST_ASSERT_MSG(next_pow2(leafs) == leafs, "size MUST be a power of 2");
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches, "branches MUST be a power of 2");

                    size_t size = get_merkle_tree_len(leafs, branches);
                    size_t row_count = get_merkle_tree_row_count(leafs, branches);

                    self->root = self->build<BaseTreeArity>(data, leafs, row_count, None);
                    self->data = Data::BaseTree(data);
                    self->leafs = leafs;
                    self->len = size;
                    self->row_count = row_count;
                }
            };
        }    // namespace merkletree
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MERKLE_HPP
