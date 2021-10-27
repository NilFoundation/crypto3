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


#ifndef FILECOIN_LEVEL_CACHE_HPP
#define FILECOIN_LEVEL_CACHE_HPP
/// The LevelCacheStore is used to reduce the on-disk footprint even
/// further to the minimum at the cost of build time performance.
/// Each LevelCacheStore is created with a StoreConfig object which
/// contains the number of binary tree levels above the base that are
/// 'cached'.  This implementation has hard requirements about the on
/// disk file size based on that number of levels, so on-disk files
/// are tied, structurally to the configuration they were built with
/// and can only be accessed with the same number of levels.

#include <stdio.h>
#include <vector>

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>


#include <nil/filecoin/storage/proofs/core/merkle/processing/storage/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace storage {
            class LevelCacheStore: public Store {
                size_t len;
                size_t elem_len;
                FILE* file;

                // The number of base layer data items.
                size_t data_width;

                // The byte index of where the cached data begins.
                size_t cache_index_start;

                // This flag is useful only immediate after instantiation, which
                // is false if the store was newly initialized and true if the
                // store was loaded from already existing on-disk data.
                bool loaded_from_disk;,

                // We cache the on-disk file size to avoid accessing disk
                // unnecessarily.
                size_t store_size;

                // If provided, the store will use this method to access base
                // layer data.
                reader: Option<ExternalReader<R>>;

                /// Used for opening v2 compacted DiskStores.
                LevelCacheStore(size_t store_range, size_t branches, StoreConfig config, reader: ExternalReader<R>) {
                    boost::filesystem::path  data_path =StoreConfig::data_path(&config.path_, &config.id_);

                    let file = OpenOptions::new().write(true).read(true).open(data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;

                    // The LevelCacheStore base data layer must already be a
                    // massaged next pow2 (guaranteed if created with
                    // DiskStore::compact, which is the only supported method at
                    // the moment).
                    size_t size = get_merkle_tree_leafs(store_range, branches)?;
                    BOOST_ASSERT_MSG(size == next_pow2(size), "Inconsistent merkle tree row_count detected");

                    // Values below in bytes.
                    // Convert store_range from an element count to bytes.
                    let store_range = store_range * Element::byte_len();

                    // LevelCacheStore on disk file is only the cached data, so
                    // the file size dictates the cache_size.  Calculate cache
                    // start and the updated size with repect to the file size.
                    size_t cache_size = get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * Element::byte_len();
                    si cache_index_start = store_range - cache_size;

                    // Sanity checks that the StoreConfig rows_to_discard matches this
                    // particular on-disk file.  Since an external reader *is*
                    // set, we check to make sure that the data on disk is *only*
                    // the cached element data.
                    BOOST_ASSERT_MSG(store_size == cache_size, "Inconsistent store size detected with external reader ({} != {})",
                        store_size, cache_size);
                    this->len = store_range / Element::byte_len();
                    this->elem_len = Element::byte_len();
                    this->file = file;
                    this->data_width = size;
                    this->cache_index_start = cache_index_start;
                    this->store_size = store_size;
                    this->loaded_from_disk = false;
                    this->reader = reader;
                }

                void set_external_reader(reader: ExternalReader<R>) {
                    this->reader = Some(reader);
                }

                LevelCacheStore(size_t size, size_t branches, StoreConfig config) {
                    boost::filesystem::path data_path =StoreConfig::data_path(&config.path_, &config.id_);

                    // If the specified file exists, load it from disk.  This is
                    // the only supported usage of this call for this type of
                    // Store.
                    if Path::new(&data_path).exists() {
                        return Self::new_from_disk(size, branches, &config);
                    }

                    // Otherwise, create the file and allow it to be the on-disk store.
                    let file = OpenOptions::new().write(true).read(true).create_new(true).open(data_path)?;

                    size_t store_size = Element::byte_len() * size;
                    let leafs = get_merkle_tree_leafs(size, branches)?;

                    BOOST_ASSERT_MSG(leafs == next_pow2(leafs), "Inconsistent merkle tree row_count detected");

                    // Calculate cache start and the updated size with repect to
                    // the data size.
                    size_t cache_size = get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)? * E::byte_len();
                    let cache_index_start = store_size - cache_size;

                    file.set_len(store_size as u64)?;
                    this->len = 0;
                    this->elem_len = Element::byte_len();
                    this->file = file;
                    this->data_width = leafs;
                    this->cache_index_start = cache_index_start;
                    this->store_size = store_size;
                    this->loaded_from_disk = false;
                    this->reader = None;
                }

                LevelCacheStore(size_t size) {
                    size_t store_size = Element::byte_len() * size;
                    let file = tempfile()?;
                    file.set_len(store_size as u64)?;
                    this->len = 0;
                    this->elem_len = Element::byte_len();
                    this->file = file;
                    this->cache_index_start = 0;
                    this->store_size = store_size;
                    this->loaded_from_disk = false;
                    this->reader = None;
                }

                LevelCacheStore(size_t size, size_t branches, data: &[u8], StoreConfig config) {
                    BOOST_ASSERT_MSG(data.len() % E::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    let mut store = Self::new_with_config(size, branches, config)?;

                    // If the store was loaded from disk (based on the config
                    // information, avoid re-populating the store at this point
                    // since it can be assumed by the config that the data is
                    // already correct).
                    if (!store.loaded_from_disk) {
                        store.store_copy_from_slice(0, data)?;
                        store.len = data.len() / store.elem_len;
                    }

                    Ok(store)
                }

                LevelCacheStore(size_t size, data: &[u8]) {
                    BOOST_ASSERT_MSG(data.len() % E::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    let mut store = Self::new(size)?;
                    store.store_copy_from_slice(0, data)?;
                    store.len = data.len() / store.elem_len;

                    Ok(store)
                }

                // Used for opening v1 compacted DiskStores.
                LevelCacheStore(size_t store_range, size_t branches, StoreConfig config) {
                    let data_path =StoreConfig::data_path(&config.path_, &config.id_);

                    FILE* file = OpenOptions::new().write(true).read(true).open(data_path)?;
                    let metadata = file.metadata()?;
                    size_t store_size = metadata.len() as usize;

                    // The LevelCacheStore base data layer must already be a
                    // massaged next pow2 (guaranteed if created with
                    // DiskStore::compact, which is the only supported method at
                    // the moment).
                    size_t size = get_merkle_tree_leafs(store_range, branches)?;
                    BOOST_ASSERT_MSG(size == next_pow2(size), "Inconsistent merkle tree row_count detected");

                    // Values below in bytes.
                    // Convert store_range from an element count to bytes.
                    size_t store_range = store_range * Element::byte_len();

                    // Calculate cache start and the updated size with repect to
                    // the data size.
                    size_t cache_size =
                        get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * Element::byte_len();
                    let cache_index_start = store_range - cache_size;

                    // For a true v1 compatible store, this check should remain,
                    // but since the store structure is identical otherwise this
                    // method can be re-used to open v2 stores, so long as an
                    // external_reader is set afterward.

                    // Sanity checks that the StoreConfig rows_to_discard matches this
                    // particular on-disk file.
                    this->len =  store_range / Element::byte_len();
                    this->file = file;
                    this->data_width = size;
                    this->cache_index_start = cache_index_start;
                    this->loaded_from_disk = true;
                    this->store_size = store_size;
                    this->reader = None;
                }

                void write_at(Element el, size_t index) {
                    this->store_copy_from_slice(index * this->elem_len, el.as_ref())?;
                    this->len = std::cmp::max(this->len, index + 1);
                }

                void copy_from_slice(buf: &[u8], size_t start) {
                    BOOST_ASSERT_MSG(buf.len() % this->elem_len == 0, "buf size must be a multiple of {}", this->elem_len);
                    this->store_copy_from_slice(start * this->elem_len, buf)?;
                    this->len = std::cmp::max(this->len, start + buf.len() / this->elem_len);
                }

                Element read_at(size_t index) {
                    let start = index * this->elem_len;
                    let end = start + this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start,  "out of bounds");

                    return Element::from_slice(&this->store_read_range(start, end)?));
                }

                void read_into(size_t index, buf: &mut [u8]) {
                    let start = index * this->elem_len;
                    let end = start + this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");

                    this->store_read_into(start, end, buf)
                }

                void read_range_into(size_t start, size_t end, buf: &mut [u8]) {
                    let start = start * this->elem_len;
                    let end = end * this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");

                    this->store_read_into(start, end, buf)
                }

                std::vector<Element> read_range(r: ops::Range<usize>) {
                    let start = r.start * this->elem_len;
                    let end = r.end * this->elem_len;

                    let len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");
                    return this->store_read_range(start, end)?.chunks(this->elem_len).map(E::from_slice).collect())
                }

                size_t len() {
                    return this->len;
                }

                bool loaded_from_disk() {
                    return this->loaded_from_disk;
                }

                bool compact(size_t _branches, StoreConfig _config, uint32_t _store_version) {
                    BOOST_ASSERT_MSG(false, "Cannot compact this type of Store");
                }

                void delete(StoreConfig config) {
                    boost::filesystem::path path = StoreConfig::data_path(&config.path, &config.id);
                    remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))
                }

                bool is_empty() {
                    return (this->len == 0);
                }

                void push(Element el) {
                    size_t len = this->len;
                    BOOST_ASSERT_MSG((len + 1) * this->elem_len <= this->store_size(), "not enough space, len: {}, E size {}, store len {}", len, this->elem_len, this->store_size());

                    this->write_at(el, len)
                }

                void sync() {
                    this->file.sync_all().context("failed to sync file")
                }


                void process_layer<A: Algorithm<E>, U: Unsigned>(size_t width, size_t level, size_t read_start, size_t write_start) {
                    // Safety: this operation is safe becase it's a limited
                    // writable region on the backing store managed by this type.
                    let mut mmap = unsafe {
                        let mut mmap_options = MmapOptions::new();
                        mmap_options.offset((write_start * E::byte_len()) as u64).len(width * E::byte_len())
                        .map_mut(&this->file)
                    }?;

                    let data_lock = Arc::new(RwLock::new(self));
                    let branches = U::to_usize();
                    let shift = log2_pow2(branches);
                    let write_chunk_width = (BUILD_CHUNK_NODES >> shift) * E::byte_len();

                    BOOST_ASSERT_MSG(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
                    Vec::from_iter((read_start..read_start + width).step_by(BUILD_CHUNK_NODES))
                        .into_par_iter()
                        .zip(mmap.par_chunks_mut(write_chunk_width))
                        .try_for_each(|(chunk_index, write_mmap)| -> Result<()> {
                        let chunk_size = std::cmp::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);

                        let chunk_nodes = {
                            // Read everything taking the lock once.
                            data_lock.read().unwrap().read_range_internal(chunk_index..chunk_index + chunk_size)?
                        };

                        let nodes_size = (chunk_nodes.len() / branches) * Element::byte_len();
                        let hashed_nodes_as_bytes = chunk_nodes.chunks(branches).fold(
                        Vec::with_capacity(nodes_size),
                        |mut acc, nodes| {
                            let h = A::default().multi_node(&nodes, level);
                            acc.extend_from_slice(h.as_ref());
                            acc
                        },
                        );

                        // Check that we correctly pre-allocated the space.
                        let hashed_nodes_as_bytes_len = hashed_nodes_as_bytes.len();
                        BOOST_ASSERT_MSG(hashed_nodes_as_bytes.len() == chunk_size / branches * Element::byte_len(),
                               "Invalid hashed node length");

                        write_mmap[0..hashed_nodes_as_bytes_len].copy_from_slice(&hashed_nodes_as_bytes);
                    })
                }

                // LevelCacheStore specific merkle-tree build.
                Element build(size_t leafs, size_t row_count, StoreConfig config) {
                    size_t branches = U::to_usize();
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches, "branches MUST be a power of 2");
                    BOOST_ASSERT_MSG(Store::len(self) == leafs, "Inconsistent data");
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");
                    BOOST_ASSERT_MSG(config.is_some(),  "LevelCacheStore build requires a valid config");

                    // Process one `level` at a time of `width` nodes. Each level has half the nodes
                    // as the previous one; the first level, completely stored in `data`, has `leafs`
                    // nodes. We guarantee an even number of nodes per `level`, duplicating the last
                    // node if necessary.
                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;

                    let config = config.unwrap();
                    let shift = log2_pow2(branches);

                    // Both in terms of elements, not bytes.
                    size_t cache_size = get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)?;
                    let cache_index_start = (get_merkle_tree_len(leafs, branches)?) - cache_size;

                    while (width > 1) {
                        // Start reading at the beginning of the current level, and writing the next
                        // level immediate after.  `level_node_index` keeps track of the current read
                        // starts, and width is updated accordingly at each level so that we know where
                        // to start writing.
                        let (read_start, write_start) = if level == 0 {
                            // Note that we previously BOOST_ASSERT_MSGed that data.len() == leafs.
                            (0, Store::len(self))
                        } else if level_node_index < cache_index_start {
                                (0, width)
                            } else {
                            (
                                level_node_index - cache_index_start,
                                    (level_node_index + width) - cache_index_start,
                            )
                        };

                        this->process_layer::<A, U>(width, level, read_start, write_start)?;

                        if level_node_index < cache_index_start {
                                this->front_truncate(&config, width)?;
                            }

                        level_node_index += width;
                        level += 1;
                        width >>= shift; // width /= branches;

                        // When the layer is complete, update the store length
                        // since we know the backing file was updated outside of
                        // the store interface.
                        this->set_len(level_node_index);
                    }

                    // Account for the root element.
                    this->set_len(Store::len(self) + 1);
                    // Ensure every element is accounted for.
                    BOOST_ASSERT_MSG(Store::len(self) == get_merkle_tree_len(leafs, branches)?, "Invalid merkle tree length");

                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root.  Note that the offset is adjusted because
                    // we've just built a store that says that it has the full
                    // length of elements, when in fact only the cached portion is
                    // on disk.
                    this->read_at_internal(this->len() - cache_index_start - 1)
                }

                void set_len(size_t len) {
                    this->len = len;
                }

                // Remove 'len' elements from the front of the file.
                void front_truncate(StoreConfig config, size_t len) {
                    let metadata = this->file.metadata()?;
                    let store_size = metadata.len();
                    let len = (len * Element::byte_len()) as u64;

                    BOOST_ASSERT_MSG(store_size >= len, "Invalid truncation length");

                    // Seek the reader past the length we want removed.
                    let mut reader = OpenOptions::new().read(true).open(StoreConfig::data_path(&config.path, &config.id))?;
                    reader.seek(SeekFrom::Start(len))?;

                    // Make sure the store file is opened for read/write.
                    this->file = OpenOptions::new().read(true).write(true).open(StoreConfig::data_path(&config.path, &config.id))?;

                    // Seek the writer.
                    this->file.seek(SeekFrom::Start(0))?;

                    let written = copy(&mut reader, &mut this->file)?;
                    BOOST_ASSERT_MSG(written == store_size - len, "Failed to copy all data");

                    this->file.set_len(written)?;
                }

                size_t store_size() {
                    return this->store_size;
                }

                // 'store_range' must be the total number of elements in the store (e.g. tree.len()).
                bool is_consistent_v1(size_t store_range, size_t branches, StoreConfig config) {
                    boost::filesystem::path  data_path = StoreConfig::data_path(&config.path, &config.id);

                    let file = File::open(data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;

                    // The LevelCacheStore base data layer must already be a
                    // massaged next pow2 (guaranteed if created with
                    // DiskStore::compact, which is the only supported method at
                    // the moment).
                    size_t size = get_merkle_tree_leafs(store_range, branches)?;
                    BOOST_ASSERT_MSG(size == next_pow2(size),  "Inconsistent merkle tree row_count detected");

                    // Calculate cache start and the updated size with repect to
                    // the data size.
                    size_t cache_size = get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * Element::byte_len();

                    // Sanity checks that the StoreConfig rows_to_discard matches this
                    // particular on-disk file.
                    return (store_size == size * Element::byte_len() + cache_size)
                }

                // Note that v2 is now the default compaction mode, so this isn't a versioned call.
                // 'store_range' must be the total number of elements in the store (e.g. tree.len()).
                bool is_consistent(size_t store_range, size_t branches, StoreConfig config) {
                    boost::filesystem::path data_path = StoreConfig::data_path(&config.path, &config.id);

                    let file = File::open(data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;

                    // The LevelCacheStore base data layer must already be a
                    // massaged next pow2 (guaranteed if created with
                    // DiskStore::compact, which is the only supported method at
                    // the moment).
                    size_t size = get_merkle_tree_leafs(store_range, branches)?;
                    BOOST_ASSERT_MSG(size == next_pow2(size), "Inconsistent merkle tree row_count detected");

                    // LevelCacheStore on disk file is only the cached data, so
                    // the file size dictates the cache_size.  Calculate cache
                    // start and the updated size with repect to the file size.
                    size_t cache_size = get_merkle_tree_cache_size(size, branches, config.rows_to_discard)? * E::byte_len();

                    // Sanity checks that the StoreConfig rows_to_discard matches this
                    // particular on-disk file.  Since an external reader *is*
                    // set, we check to make sure that the data on disk is *only*
                    // the cached element data.
                    return (store_size == cache_size)
                }

                std::vector<char> store_read_range(size_t start, size_t end) {
                    let read_len = end - start;
                    let mut read_data = vec![0; read_len];
                    let mut adjusted_start = start;

                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");

                    // If an external reader was specified for the base layer, use it.
                    if (start < this->data_width * this->elem_len && this->reader.is_some()) {
                        this->reader.as_ref()..unwrap()..read(start, end, &mut read_data)
                            .with_context(|| {
                                format!(
                                "failed to read {} bytes from file at offset {}",
                                end - start,
                                start
                                )
                            })?;
                        return read_data;
                    }

                    // Adjust read index if in the cached ranged to be shifted
                    // over since the data stored is compacted.
                    if (start >= this->cache_index_start) {
                        let v1 = this->reader.is_none();
                        adjusted_start = if v1 {
                                start - this->cache_index_start + (this->data_width * this->elem_len)
                            } else {
                            start - this->cache_index_start
                        };
                    }

                    this->file.read_exact_at(adjusted_start as u64, &mut read_data).with_context(|| {
                            format!(
                            "failed to read {} bytes from file at offset {}",
                            read_len, start
                            )
                        })?;
                    return read_data;
                }

                // This read is for internal use only during the 'build' process.
                std::vector<char> store_read_range_internal(size_t start, size_t end) {
                    let read_len = end - start;
                    let mut read_data = vec![0; read_len];

                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");

                    this->file.read_exact_at(start as u64, &mut read_data).with_context(|| {
                            format!(
                            "failed to read {} bytes from file at offset {}",
                            read_len, start
                            )
                        })?;
                    return read_data;
                }

                std::vector<Element> read_range_internal(r: ops::Range<usize>) {
                    let start = r.start * this->elem_len;
                    let end = r.end * this->elem_len;

                    let len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");
                    return this->store_read_range_internal(start, end)?.chunks(this->elem_len).map(E::from_slice).collect())
                }

                Element read_at_internal(size_t index) {
                    let start = index * this->elem_len;
                    let end = start + this->elem_len;

                    let len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "out of bounds");

                    return (Element::from_slice(&this->store_read_range_internal(start, end)?));
                }

                void store_read_into(size_t start, size_t end, buf: &mut [u8]) {
                    BOOST_ASSERT_MSG(start <= this->data_width * this->elem_len || start >= this->cache_index_start, "Invalid read start");

                    // If an external reader was specified for the base layer, use it.
                    if (start < this->data_width * this->elem_len && this->reader.is_some()) {
                        this->reader.as_ref().unwrap().read(start, end, buf).with_context(|| {
                                format!(
                                "failed to read {} bytes from file at offset {}",
                                end - start,
                                start
                                )
                            })?;
                    } else {
                        // Adjust read index if in the cached ranged to be shifted
                        // over since the data stored is compacted.
                        let adjusted_start = if start >= this->cache_index_start {
                            if this->reader.is_none() {
                                // if v1
                                start - this->cache_index_start + (this->data_width * this->elem_len)
                            } else {
                                start - this->cache_index_start
                            }
                        } else {
                            start
                        };

                        this->file.read_exact_at(adjusted_start as u64, buf).with_context(|| {
                                format!(
                                "failed to read {} bytes from file at offset {}",
                                end - start,
                                start
                                )
                            })?;
                    }
                }

                void store_copy_from_slice(size_t start, slice: &[u8]) {
                    BOOST_ASSERT_MSG(start + slice.len() <= this->store_size,  "Requested slice too large (max: {})", this->store_size);
                    this->file.write_all_at(start as u64, slice)?;
                }
            }
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_LEVEL_CACHE_HPP