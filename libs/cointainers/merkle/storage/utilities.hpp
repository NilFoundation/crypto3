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

namespace nil {
    namespace filecoin {
        namespace merkletree {
            struct ExternalReader {
                size_t offset;
                pub source: R;

                size_t read(size_t start, size_t end, char* buf, source: &R) {
                    (self.read_fn)(start + self.offset, end + self.offset, buf, &self.source)
                }

                ExternalReader(ReplicaConfig replica_config, size_t index) {
                    let reader = OpenOptions::new().read(true).open(&replica_config.path)?;
                    offset = replica_config.offsets[index];
                    source = reader;
                    self.offset = replica_config.offsets[index];
                    self.source = reades;
                    read_fn: |start, end, buf: &mut [u8], reader: &std::fs::File| {
                            reader.read_exact_at(start as u64, &mut buf[0..end - start])?;

                            Ok(end - start)};
                }
            }

            enum StoreConfigDataVersion {
                One = 1,
                Two = 2
            };

            const uint32_t DEFAULT_STORE_CONFIG_DATA_VERSION = StoreConfigDataVersion::Two;

            struct ReplicaConfig  {
                ReplicaConfig(boost::filesystem::path path, std::vector<size_t> offsets) {
                    self.path = path;
                    for (auto i: offsets) {
                        self.offsets.push_back(i);
                    }
                }
                ReplicaConfig(boost::filesystem::path path) {
                    self.path = path;
                    self.offsets.push_back(0);
                }
                std::vector<size_t> offsets;
                boost::filesystem::path path;
            };

            struct StoreConfig {
                StoreConfig(boost::filesystem::path path, std::string id, size_t rows_to_discard) :
                    path_(path), id_(id), rows_to_discard_(rows_to_discard) {};
                // If the tree is large enough to use the default value
                // (per-arity), use it.  If it's too small to cache anything
                // (i.e. not enough rows), don't discard any.
                size_t default_rows_to_discard(size_t leafs, size_t branches) {
                    size_t =  = get_merkle_tree_row_count(leafs, branches);
                    if (row_count <= 2) {
                        // If a tree only has a root row and/or base, there is
                        // nothing to discard.
                        return 0;
                    } else if row_count == 3 {
                        // If a tree only has 1 row between the base and root,
                        // it's all that can be discarded.
                        return 1;
                    }
                    // row_count - 2 discounts the base layer (1) and root (1)
                    size_t max_rows_to_discard = row_count - 2;
                    // Discard at most 'constant value' rows (coded below,
                    // differing by arity) while respecting the max number that
                    // the tree can support discarding.
                    if (branches == 2)
                        return std::min(max_rows_to_discard, 7);
                    if (branches == 4)
                        return std::min(max_rows_to_discard, 5);
                    return std::min(max_rows_to_discard, 2);
                }
                // Deterministically create the data_path on-disk location from a
                // path and specified id.
                boost::filesystem::path data_path(boost::filesystem::path path, std::string id) {
                    std::ostringstream store_data_version;
                    store_data_version << std::internal << std::setfill('0') << std::setw(2) << DEFAULT_STORE_CONFIG_DATA_VERSION;
                    return boost::filesystem::path("sc-" + store_data_version.str() + "-data-" + id + ".dat");
                }

                StoreConfig(StoreConfig config, std::string id, size_t size = 0) {
                    assert(size == 0);
                    size_ = config.size;
                    path_ = config.path;
                    id_ = config.id_;
                    rows_to_discard_ = config.rows_to_discard_;
                }
                /// A directory in which data (a merkle tree) can be persisted.
                boost::filesystem::path path_;
                /// A unique identifier used to help specify the on-disk store
                /// location for this particular data.
                std::string id_;
                /// The number of elements in the DiskStore.  This field is
                /// optional, and unused internally.
                size_t size_;
                /// The number of merkle tree rows_to_discard then cache on disk.
                size_t rows_to_discard_;
            }

            /// Backing store of the merkle tree.
            template <typename Element>
            class Store {
                /// Creates a new store which can store up to `size` elements.
                Store(size_t size, size_t branches, StoreConfig config);
                Store(size_t size);
                Store(size_t size, size_t branches, char *data, StoreConfig config);
                Store(size_t size, data: &[u8]);
                Store(size_t size, size_t branches, StoreConfig config);
                void write_at(el: E, size_t index);

                // Used to reduce lock contention and do the `E` to `u8`
                // conversion in `build` *outside* the lock.
                // `buf` is a slice of converted `E`s and `start` is its
                // position in `E` sizes (*not* in `u8`).
                void copy_from_slice(buf: &[u8], size_t start);

                // compact/shrink resources used where possible.
                bool compact(size_t branches, StoreConfig config, uint32_t store_version);

                // re-instate resource usage where needed.
                void reinit() {};

                // Removes the store backing (does not require a mutable reference
                // since the config should provide stateless context to what's
                // needed to be removed -- with the exception of in memory stores,
                // where this is arguably not important/needed).
                void delete(StoreConfig config);

                Element read_at(size_t index);
                std::vector<Element> read_range(r: ops::Range<usize>);
                void read_into(size_t pos, buf: &mut [u8]);
                void read_range_into(size_t start, size_t end, buf: &mut [u8]);

                size_t len();
                bool loaded_from_disk();
                bool is_empty();
                void push(Element el);
                Element last() {
                    self.read_at(self.len() - 1)
                }

                // Sync contents to disk (if it exists). This function is used to avoid
                // unnecessary flush calls at the cost of added code complexity.
                void sync();

                fn build_small_tree<A: Algorithm<E>, U: Unsigned>(size_t leafs, size_t row_count) {
                    assert(leafs % 2 == 0, "Leafs must be a power of two");

                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;
                    size_t = U::to_usize();
                    let shift = log2_pow2(branches);

                    while (width > 1) {
                        // Same indexing logic as `build`.
                        let (layer, write_start) = {
                        let (read_start, write_start) = if level == 0 {
                        // Note that we previously asserted that data.len() == leafs.
                            (0, Store::len(self))
                        } else {
                            (level_node_index, level_node_index + width)
                        };

                        let layer: Vec<_> = selfread_range(read_start..read_start + width)?.par_chunks(branches).map(|nodes| A::default().multi_node(&nodes, level)).collect();

                            (layer, write_start)
                        };

                        for (i, node) in layer.into_iter().enumerate() {
                            self.write_at(node, write_start + i)?;
                        }

                        level_node_index += width;
                        level += 1;
                        width >>= shift; // width /= branches;
                    }

                    assert(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    self.last()
                }

                void process_layer<A: Algorithm<E>, U: Unsigned>(size_t width, size_t level,
                                                                 size_t read_start, size_t write_start)  
                {
                    size_t branches = U::to_usize();
                    size_t data_lock = Arc::new(RwLock::new(self));

                    // Allocate `width` indexes during operation (which is a negligible memory bloat
                    // compared to the 32-bytes size of the nodes stored in the `Store`s) and hash each
                    // pair of nodes to write them to the next level in concurrent threads.
                    // Process `BUILD_CHUNK_NODES` nodes in each thread at a time to reduce contention,
                    // optimized for big sector sizes (small ones will just have one thread doing all
                    // the work).
                    assert(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
                    Vec::from_iter((read_start..read_start + width).step_by(BUILD_CHUNK_NODES))
                    .par_iter()
                    .try_for_each(|&chunk_index| -> Result<()> {
                    let chunk_size = std::cmp::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);

                    let chunk_nodes = {
                        // Read everything taking the lock once.
                        data_lock
                            .read()
                            .unwrap()
                            .read_range(chunk_index..chunk_index + chunk_size)?
                    };

                    // We write the hashed nodes to the next level in the
                    // position that would be "in the middle" of the
                    // previous pair (dividing by branches).
                    let write_delta = (chunk_index - read_start) / branches;
                    
                    let nodes_size = (chunk_nodes.len() / branches) * E::byte_len();
                    let hashed_nodes_as_bytes = chunk_nodes.chunks(branches).fold(
                            Vec::with_capacity(nodes_size),
                                                    |mut acc, nodes| {
                        let h = A::default().multi_node(&nodes, level);
                        acc.extend_from_slice(h.as_ref());
                        acc
                        },
                    );

                    // Check that we correctly pre-allocated the space.
                    assert!(hashed_nodes_as_bytes.len() == chunk_size / branches * E::byte_len(), "Invalid hashed node length");

                    // Write the data into the store.
                    data_lock.write().unwrap().copy_from_slice(&hashed_nodes_as_bytes, write_start + write_delta)})
                }

                // Default merkle-tree build, based on store type.
                Element build<A: Algorithm<E>, U: Unsigned>(size_t leafs, size_t row_count, StoreConfig _config) {
                    size_t branches = U::to_usize();
                    assert(next_pow2(branches) == branches, "branches MUST be a power of 2");
                    assert(Store::len(self) == leafs, "Inconsistent data");
                    assert(leafs % 2 == 0, "Leafs must be a power of two");
                
                    if (leafs <= SMALL_TREE_BUILD) {
                        return self.build_small_tree::<A, U>(leafs, row_count);
                    }
                
                    size_t shift = log2_pow2(branches);
                
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
                        let (read_start, write_start) = if level == 0 {
                            // Note that we previously asserted that data.len() == leafs.
                            //(0, data_lock.read().unwrap().len())
                            (0, Store::len(self))
                        } else {
                            (level_node_index, level_node_index + width)
                        };
                
                        self.process_layer::<A, U>(width, level, read_start, write_start)?;

                        level_node_index += width;
                        level += 1;
                        width >>= shift; // width /= branches;
                    }
                
                    assert(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root
                    return self.last()
                }

//                // Using a macro as it is not possible to do a generic implementation for all stores.
//
//                macro_rules! impl_parallel_iter {
//                    ($name:ident, $producer:ident, $iter:ident) => {
//                        impl<E: Element> ParallelIterator for $name<E> {
//                            type Item = E;
//
//                            fn drive_unindexed<C>(self, consumer: C) -> C::Result
//                            where
//                            C: UnindexedConsumer<Self::Item>,
//                            {
//                                bridge(self, consumer)
//                            }
//
//                            fn opt_len(&self) -> Option<usize> {
//                                Some(Store::len(self))
//                            }
//                        }
//                        impl<'a, E: Element> ParallelIterator for &'a $name<E> {
//                            type Item = E;
//
//                            fn drive_unindexed<C>(self, consumer: C) -> C::Result
//                            where
//                            C: UnindexedConsumer<Self::Item>,
//                            {
//                                bridge(self, consumer)
//                            }
//
//                            fn opt_len(&self) -> Option<usize> {
//                                Some(Store::len(*self))
//                            }
//                        }
//
//                        impl<E: Element> IndexedParallelIterator for $name<E> {
//                            fn drive<C>(self, consumer: C) -> C::Result
//                            where
//                            C: Consumer<Self::Item>,
//                            {
//                                bridge(self, consumer)
//                            }
//
//                            fn len(&self) -> usize {
//                                Store::len(self)
//                            }
//
//                            fn with_producer<CB>(self, callback: CB) -> CB::Output
//                            where
//                            CB: ProducerCallback<Self::Item>,
//                            {
//                                callback.callback(<$producer<E>>::new(0, Store::len(&self), &self))
//                            }
//                        }
//
//                        impl<'a, E: Element> IndexedParallelIterator for &'a $name<E> {
//                            fn drive<C>(self, consumer: C) -> C::Result
//                            where
//                            C: Consumer<Self::Item>,
//                            {
//                                bridge(self, consumer)
//                            }
//
//                            fn len(&self) -> usize {
//                                Store::len(*self)
//                            }
//
//                            fn with_producer<CB>(self, callback: CB) -> CB::Output
//                            where
//                            CB: ProducerCallback<Self::Item>,
//                            {
//                                callback.callback(<$producer<E>>::new(0, Store::len(self), self))
//                            }
//                        }
//
//#[derive(Debug, Clone)]
//                        pub struct $producer<'data, E: 'data + Element> {
//                            pub(crate) current: usize,
//                                pub(crate) end: usize,
//                                pub(crate) store: &'data $name<E>,
//                        }
//
//                        impl<'data, E: 'data + Element> $producer<'data, E> {
//                        pub fn new(current: usize, end: usize, store: &'data $name<E>) -> Self {
//                        Self {
//                            current,
//                            end,
//                            store,
//                        }
//                    }
//
//                    pub fn len(&self) -> usize {
//                        self.end - self.current
//                    }
//
//                    pub fn is_empty(&self) -> bool {
//                        self.len() == 0
//                    }
//                }
//
//                impl<'data, E: 'data + Element> Producer for $producer<'data, E> {
//                type Item = E;
//                type IntoIter = $iter<'data, E>;
//
//                fn into_iter(self) -> Self::IntoIter {
//                    let $producer {
//                        current,
//                        end,
//                        store,
//                    } = self;
//
//                    $iter {
//                        current,
//                        end,
//                        store,
//                        err: false,
//                    }
//                }
//
//                fn split_at(self, index: usize) -> (Self, Self) {
//                    let len = self.len();
//
//                    if len == 0 {
//                        return (
//                        <$producer<E>>::new(0, 0, &self.store),
//                        <$producer<E>>::new(0, 0, &self.store),
//                        );
//                    }
//
//                    let current = self.current;
//                    let first_end = current + std::cmp::min(len, index);
//
//                    debug_assert!(first_end >= current);
//                    debug_assert!(current + len >= first_end);
//
//                    (
//                    <$producer<E>>::new(current, first_end, &self.store),
//                    <$producer<E>>::new(first_end, current + len, &self.store),
//                    )
//                }
//            }
//            }
//                pub struct $iter<'data, E: 'data + Element> {
//                    current: usize,
//                        end: usize,
//                        err: bool,
//                        store: &'data $name<E>,
//                }
//
//                    impl<'data, E: 'data + Element> $iter<'data, E> {
//                fn is_done(&self) -> bool {
//                    !self.err && self.len() == 0
//                }
//            }
//
//                impl<'data, E: 'data + Element> Iterator for $iter<'data, E> {
//            type Item = E;
//
//            fn next(&mut self) -> Option<Self::Item> {
//            if self.is_done() {
//                return None;
//            }
//
//            match self.store.read_at(self.current) {
//            Ok(el) => {
//            self.current += 1;
//            Some(el)
//        }
//        _ => {
//        self.err = true;
//        None
//    }
//}
//}
//}
//
//impl<'data, E: 'data + Element> ExactSizeIterator for $iter<'data, E> {
//fn len(&self) -> usize {
//debug_assert!(self.current <= self.end);
//self.end - self.current
//}
//}
//
//impl<'data, E: 'data + Element> DoubleEndedIterator for $iter<'data, E> {
//fn next_back(&mut self) -> Option<Self::Item> {
//if self.is_done() {
//    return None;
//}
//
//match self.store.read_at(self.end - 1) {
//Ok(el) => {
//self.end -= 1;
//Some(el)
//}
//_ => {
//self.err = true;
//None
//}
//}
//}
//}
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_STORAGE_UTILITIES_HPP

