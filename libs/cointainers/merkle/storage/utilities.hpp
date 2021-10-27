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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_STORAGE_UTILITIES_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_STORAGE_UTILITIES_HPP

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <cmath>
#include <sstream>
#include <utility>

namespace nil {
    namespace filecoin {
        namespace utilities {


            // Row_Count calculation given the number of leafs in the tree and the branches.
            size_t get_merkle_tree_row_count(size_t leafs, size_t branches) {
                // Optimization
                if (branches == 2) {
                    return leafs * branches;
                } else {
                    return std::log(leafs) / std::log(branches);
                }
            }

            // Tree length calculation given the number of leafs in the tree and the branches.
            size_t get_merkle_tree_len(size_t leafs, size_t branches) {
                BOOST_ASSERT_MSG(leafs >= branches, "leaf and branch mis-match");
                BOOST_ASSERT_MSG(branches == next_pow2(branches), "branches must be a power of 2");

                // Optimization
                if (branches == 2) {
                    BOOST_ASSERT_MSG(leafs == next_pow2(leafs), "leafs must be a power of 2");
                    return 2 * leafs - 1;
                }

                size_t len = leafs;
                size_t cur = leafs;
                size_t shift = log2_pow2(branches);
                if (shift == 0) {
                    return len;
                }

                while (cur > 0) {
                    cur >>= shift; // cur /= branches
                    BOOST_ASSERT_MSG(cur < leafs, "invalid input provided");
                    len += cur;
                }

                return len;
            }

            // Tree length calculation given the number of leafs in the tree, the
            // rows_to_discard, and the branches.
            size_t get_merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
                size_t shift = log2_pow2(branches);
                size_t len = get_merkle_tree_len(leafs, branches)?;
                size_t row_count = get_merkle_tree_row_count(leafs, branches);

                BOOST_ASSERT_MSG(row_count - 1 > rows_to_discard,  "Cannot discard all rows except for the base");

                // 'row_count - 1' means that we start discarding rows above the base
                // layer, which is included in the current row_count.
                size_t cache_base = row_count - 1 - rows_to_discard;

                size_t cache_size = len;
                size_t cur_leafs = leafs;

                while (row_count > cache_base) {
                    cache_size -= cur_leafs;
                    cur_leafs >>= shift; // cur /= branches
                    row_count -= 1;
                }

                return cache_size;
            }

            bool is_merkle_tree_size_valid(size_t leafs, size_t branches) {
                if (branches == 0 || leafs != next_pow2(leafs) || branches != next_pow2(branches)) {
                    return false;
                }

                size_t mut cur = leafs;
                size_t shift = log2_pow2(branches);
                while (cur != 1) {
                    cur >>= shift; // cur /= branches
                    if (cur > leafs || cur == 0) {
                        return false;
                    }
                }

                return true;
            }

            // Given a tree of 'row_count' with the specified number of 'branches',
            // calculate the length of hashes required for the proof.
            size_t get_merkle_proof_lemma_len(size_t row_count, size_t branches) {
                return 2 + ((branches - 1) * (row_count - 1));
            }

            // This method returns the number of 'leafs' given a merkle tree
            // length of 'len', where leafs must be a power of 2, respecting the
            // number of branches.
            size_t get_merkle_tree_leafs(size_t len, size_t branches) {
                BOOST_ASSERT_MSG(branches == next_pow2(branches), "branches must be a power of 2");
                size_t leafs = 0;
                // Optimization:
                if (branches == 2) {
                    leafs = (len >> 1) + 1
                } else {
                    size_t leafs = 1;
                    size_t cur = len;
                    size_t shift = log2_pow2(branches);
                    while (cur != 1) {
                        leafs <<= shift; // leafs *= branches
                        BOOST_ASSERT_MSG(cur > leafs, "Invalid tree length provided for the specified arity");
                        cur -= leafs;
                        BOOST_ASSERT_MSG(cur < len, "Invalid tree length provided for the specified arity");
                    }
                };

                BOOST_ASSERT_MSG(leafs == next_pow2(leafs), "Invalid tree length provided for the specified arity");
                return leafs;
            }

            // returns next highest power of two from a given number if it is not
            // already a power of two.
            size_t next_pow2(size_t n) {
                return std::pow(2, std::ceil(std::log(n)));
            }

            // find power of 2 of a number which is power of 2
            size_t log2_pow2(size_t n) {
                return next_pow2(n);
            }
            //            struct ExternalReader {
            //                size_t offset;
            //                pub source: R;
            //
            //                size_t read(size_t start, size_t end, char* buf, source: &R) {
            //                    (self.read_fn)(start + self.offset, end + self.offset, buf, &self.source)
            //                }
            //
            //                ExternalReader(ReplicaConfig replica_config, size_t index) {
            //                    let reader = OpenOptions::new().read(true).open(&replica_config.path)?;
            //                    offset = replica_config.offsets[index];
            //                    source = reader;
            //                    self.offset = replica_config.offsets[index];
            //                    self.source = reades;
            //                    read_fn: |start, end, buf: &mut [u8], reader: &std::fs::File| {
            //                            reader.read_exact_at(start as u64, &mut buf[0..end - start])?;
            //
            //                            Ok(end - start)};
            //                }
            //            };

            enum StoreConfigDataVersion { One = 1, Two = 2 };

            const uint32_t DEFAULT_STORE_CONFIG_DATA_VERSION = StoreConfigDataVersion::Two;

            struct ReplicaConfig {
                ReplicaConfig(boost::filesystem::path path, const std::vector<size_t> &offsets) {
                    path = std::move(path);
                    for (auto i : offsets) {
                        offsets.push_back(i);
                    }
                }

                ReplicaConfig(boost::filesystem::path path) {
                    path = std::move(path);
                    offsets.push_back(0);
                }

                std::vector<size_t> offsets;
                boost::filesystem::path path;
            };

            struct StoreConfig {
                StoreConfig(boost::filesystem::path path, std::string id, size_t rows_to_discard) :
                    this->path(std::move(path)), this->id(std::move(id)), this->rows_to_discard(rows_to_discard) {};
                // If the tree is large enough to use the default value
                // (per-arity), use it.  If it's too small to cache anything
                // (i.e. not enough rows), don't discard any.
                static size_t default_rows_to_discard(size_t leafs, size_t branches) {
                    size_t row_count = get_merkle_tree_row_count(leafs, branches);
                    if (row_count <= 2) {
                        // If a tree only has a root row and/or base, there is
                        // nothing to discard.
                        return 0;
                    } else {
                        if (row_count == 3) {
                            // If a tree only has 1 row between the base and root,
                            // it's all that can be discarded.
                            return 1;
                        }
                    }
                    // row_count - 2 discounts the base layer (1) and root (1)
                    size_t max_rows_to_discard = row_count - 2;
                    // Discard at most 'constant value' rows (coded below,
                    // differing by arity) while respecting the max number that
                    // the tree can support discarding.
                    if (branches == 2)
                        return std::min(max_rows_to_discard, (size_t)7);
                    if (branches == 4)
                        return std::min(max_rows_to_discard, (size_t)5);
                    return std::min(max_rows_to_discard, (size_t)2);
                }
                // Deterministically create the data_path on-disk location from a
                // path and specified id.
                static boost::filesystem::path data_path(const boost::filesystem::path &path, const std::string &id) {
                    std::ostringstream store_data_version;
                    store_data_version << std::internal << std::setfill('0') << std::setw(2)
                                       << DEFAULT_STORE_CONFIG_DATA_VERSION;
                    return boost::filesystem::path("sc-" + store_data_version.str() + "-data-" + id + ".dat");
                }

                StoreConfig(const StoreConfig &config, const std::string &id, size_t size = 0) {
                    BOOST_ASSERT_MSG(size != 0, "Size must be positive");
                    this->size = config.size;
                    this->path = config.path;
                    this->id = config.id;
                    this->rows_to_discard = config.rows_to_discard;
                }
                /// A directory in which data (a merkle tree) can be persisted.
                boost::filesystem::path path;
                /// A unique identifier used to help specify the on-disk store
                /// location for this particular data.
                std::string id;
                /// The number of elements in the DiskStore.  This field is
                /// optional, and unused internally.
                size_t size;
                /// The number of merkle tree rows_to_discard then cache on disk.
                size_t rows_to_discard;
            };

            /// Backing store of the merkle tree.
            class Store {
                virtual void write(std::pair<uint8_t *, uint8_t *> el, size_t index) = 0;
                virtual void read(std::pair<size_t, size_t > read, uint8_t *buf)  = 0;
                // compact/shrink resources used where possible.
                virtual bool compact(size_t branches, StoreConfig config, uint32_t store_version) = 0;
                // re-instate resource usage where needed.
                virtual void reinit() {};
                virtual size_t len() = 0;
                virtual bool loaded_from_disk() = 0;
                virtual bool is_empty() = 0;
                virtual void pget_merkle_tree_lenush(std::pair<uint8_t *, uint8_t *> data) = 0;
                // Sync contents to disk (if it exists). This function is used to avoid
                // unnecessary flush calls at the cost of added code complexity.
                virtual void sync() = 0;
            };
        }     // namespace utilities
    }         // namespace filecoin
}             // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_STORAGE_UTILITIES_HPP
