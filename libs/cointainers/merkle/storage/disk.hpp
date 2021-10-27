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

#ifndef FILECOIN_DISK_HPP
#define FILECOIN_DISK_HPP

#include <iostream>
#include <fstream>

#include <nil/filecoin/storage/proofs/core/metkle/storage/utilities.hpp>

namespace nil {
    namespace filecoin {
        namespace storage {
            class DiskStore: public Storage {
                size_t len;
                size_t elem_len;
                ifstream file;
                // This flag is useful only immediate after instantiation, which
                // is false if the store was newly initialized and true if the
                // store was loaded from already existing on-disk data.
                bool loaded_from_disk;
                // We cache the `store.len()` call to avoid accessing disk unnecessarily.
                // Not to be confused with `len`, this saves the total size of the `store`
                // in bytes and the other one keeps track of used `E` slots in the `DiskStore`.
                size_t store_size;

                DiskStore(size_t size, size_t branches, StoreConfig config) {
                    boost::filesystem::path data_path = StoreConfig::data_path(&config.path, &config.id);
                    // If the specified file exists, load it from disk.
                    // Otherwise, create the file and allow it to be the on-disk store.
                    file.open(data_path.string().c_str(), ios::in | ios::out | ios::app | ios::binary);

                    if (data_path.exists()) {
                        this->store_size = boost::filesystem::file_size(data_path);
                        this->len = size;
                    } else {
                        this->store_size = Element::byte_len() * size - 1;
                        this->len = 0;
                        fbuf.pubseekoff(store_size, std::ios_base::beg);
                        fbuf.sputc(0);
                    }

                    this->elem_len = Element::byte_len();
                    this->file = file;
                    this->loaded_from_disk = false;
                }

                DiskStore(size_t size) {
                    size_t store_size = Element::byte_len() * size;
                    BOOST_ASSERT_MSG(false, "Not valid");
                }

                DiskStore new_from_slice_with_config(size_t size, size_t branches, uint8_t *data, StoreConfig config) {
                    BOOST_ASSERT_MSG(data.len() % Element::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    DiskStoret store(size, branches, config);

                    // If the store was loaded from disk (based on the config
                    // information, avoid re-populating the store at this point
                    // since it can be assumed by the config that the data is
                    // already correct).
                    if (!store.loaded_from_disk) {
                        store.store_copy_from_slice(0, data);
                        store.len = data.len() / store.elem_len;
                    }

                    return store;
                }

                DiskStore new_from_slice(size_t size, uint8_t *data) {
                    BOOST_ASSERT_MSG(data.len() % Element::byte_len() == 0, "data size must be a multiple of {}", Element::byte_len());

                    DiskStore store(size);
                    store.store_copy_from_slice(0, data);
                    store.len = data.len() / store.elem_len;

                    return store;
                }

                void write_at(Element el, size_t index) {
                    this->store_copy_from_slice(index * this->elem_len, el.as_ref())?;
                    this->len = std::cmp::max(this->len, index + 1);
                }

                void copy_from_slice(uint8_t *buf, size_t start) {
                    BOOST_ASSERT_MSG(buf.len() % this->elem_len == 0, "buf size must be a multiple of {}", this->elem_len);
                    this->store_copy_from_slice(start * this->elem_len, buf)?;
                    this->len = std::max(this->len, start + buf.len() / this->elem_len);
                }

                void read(std::pair<size_t, size_t> read, uint8_t *buf) {
                    BOOST_ASSERT_MSG(read.first >= len || read.second >= len, "Invalid read range");
                    memcpy(buf, static_cast<char *>(addr) + read.first, read.second - read.first);
                }

                Element read_at(size_t index) {
                    size_t start = index * this->elem_len;
                    size_t end = start + this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);

                    return Element::from_slice(&this->store_read_range(start, end)?))
                }

                void read_into(size_t index, buf: &mut [u8]) {
                    size_t start = index * this->elem_len;
                    size_t end = start + this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);

                    this->store_read_into(start, end, buf)
                }

                void read_range_into(size_t start, size_t end, buf: &mut [u8]) {
                    size_t start = start * this->elem_len;
                    size_t end = end * this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);

                    this->store_read_into(start, end, buf)
                }

                std::vector<Element> read_range(r: ops::Range<usize>) {
                    size_t start = r.start * this->elem_len;
                    size_t end = r.end * this->elem_len;

                    size_t len = this->len * this->elem_len;
                    BOOST_ASSERT_MSG(start < len, "start out of range {} >= {}", start, len);
                    BOOST_ASSERT_MSG(end <= len, "end out of range {} > {}", end, len);

                    return this->store_read_range(start, end)?.chunks(this->elem_len).map(E::from_slice).collect())
                }

                size_t len() {
                    return this->len;
                }

                boool loaded_from_disk() {
                    return this->loaded_from_disk;
                }

                // Specifically, this method truncates an existing DiskStore and
                // formats the data in such a way that is compatible with future
                // access using LevelCacheStore::new_from_disk.
                bool compact(size_t branches, StoreConfig config, uint32_t store_version) {
                    // Determine how many base layer leafs there are (and in bytes).
                    size_t leafs = get_merkle_tree_leafs(this->len, branches);
                    size_t data_width = leafs * this->elem_len;

                    // Calculate how large the cache should be (based on the
                    // config.rows_to_discard param).
                    size_t cache_size = get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard) * this->elem_len;

                    // The file cannot be compacted if the specified configuration
                    // requires either 1) nothing to be cached, or 2) everything
                    // to be cached.  For #1, create a data store of leafs and do
                    // not use that store as backing for the MT.  For #2, avoid
                    // calling this method.  To resolve, provide a sane
                    // configuration.
                    BOOST_ASSERT_MSG(cache_size < this->len * this->elem_len && cache_size != 0, "Cannot compact with this configuration");

                    uint32_t v1 = store_version == StoreConfigDataVersion::One as u32;
                    size_t start = 0;
                    if (v1) {
                        start = data_width;
                    }
                    // Calculate cache start and updated size with repect to the
                    // data size.
                    size_t cache_start = this->store_size - cache_size;

                    // Seek the reader to the start of the cached data.
                    let mut reader = OpenOptions::new().read(true)
                         .open(StoreConfig::data_path(&config.path, &config.id))?;
                    reader.seek(SeekFrom::Start(cache_start as u64))?;

                    // Make sure the store file is opened for read/write.
                    this->file = OpenOptions::new().read(true).write(true)
                         .open(StoreConfig::data_path(&config.path, &config.id))?;

                    // Seek the writer.
                    this->file.seek(SeekFrom::Start(start))?;

                    // Copy the data from the cached region to the writer.
                    let written = copy(&mut reader, &mut this->file)?;
                    BOOST_ASSERT_MSG(written == cache_size as u64, "Failed to copy all data");
                    if (v1) {
                            // Truncate the data on-disk to be the base layer data
                            // followed by the cached data.
                            this->file.set_len((data_width + cache_size) as u64)?;
                            // Adjust our length for internal consistency.
                            this->len = (data_width + cache_size) / this->elem_len;
                        } else {
                        // Truncate the data on-disk to be only the cached data.
                        this->file.set_len(cache_size as u64)?;

                        // Adjust our length to be the cached elements only for
                        // internal consistency.
                        this->len = cache_size / this->elem_len;
                    }

                    // Sync and sanity check that we match on disk (this can be
                    // removed if needed).
                    this->sync()?;
                    let metadata = this->file.metadata()?;
                    let store_size = metadata.len() as usize;
                    BOOST_ASSERT_MSG(this->len * this->elem_len == store_size, "Inconsistent metadata detected");
                    return true;
                }

                void delete(StoreConfig config) {
                    boost::filesystem::path  path = StoreConfig::data_path(&config.path, &config.id);
                    remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))
                }

                bool is_empty() {
                    return (this->len == 0);
                }

                void push(Element el) {
                    size_t len = this->len;
                    BOOST_ASSERT_MSG((len + 1) * this->elem_len <= this->store_size(),
                           "not enough space, len: {}, E size {}, store len {}",
                            len, this->elem_len, this->store_size());

                    this->write_at(el, len)
                }

                void sync() {
                    this->file.sync_all().context("failed to sync file");
                }

                template<typename Algorithm<Element>, typename Unsigned>
                void process_layer(size_t width, size_t level, size_t read_start, size_t write_start) {
                    // Safety: this operation is safe becase it's a limited
                    // writable region on the backing store managed by this type.
                    let mut mmap = unsafe {
                        let mut mmap_options = MmapOptions::new();
                        mmap_options.offset((write_start * E::byte_len()) as u64).len(width * E::byte_len()).map_mut(&this->file)
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
                            data_lock.read().unwrap().read_range(chunk_index..chunk_index + chunk_size)?
                        };

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
                        let hashed_nodes_as_bytes_len = hashed_nodes_as_bytes.len();
                        ensure!(
                        hashed_nodes_as_bytes.len() == chunk_size / branches * E::byte_len(),
                        "Invalid hashed node length"
                        );

                        write_mmap[0..hashed_nodes_as_bytes_len].copy_from_slice(&hashed_nodes_as_bytes);
                    })
                }

                // DiskStore specific merkle-tree build.
                template<typename Algorithm<Element>, typename Unsigned>
                Element build(size_t leafs, size_t row_count, StoreConfig _config) {
                    let branches = Unsigned::to_usize();
                    BOOST_ASSERT_MSG(next_pow2(branches) == branches, "branches MUST be a power of 2");
                    BOOST_ASSERT_MSG(Store::len(self) == leafs, "Inconsistent data");
                    BOOST_ASSERT_MSG(leafs % 2 == 0, "Leafs must be a power of two");

                    // Process one `level` at a time of `width` nodes. Each level has half the nodes
                    // as the previous one; the first level, completely stored in `data`, has `leafs`
                    // nodes. We guarantee an even number of nodes per `level`, duplicating the last
                    // node if necessary.
                    size_t level = 0;
                    size_t width = leafs;
                    size_t level_node_index = 0;

                    size_t shift = log2_pow2(branches);

                    while (width > 1) {
                        // Start reading at the beginning of the current level, and writing the next
                        // level immediate after.  `level_node_index` keeps track of the current read
                        // starts, and width is updated accordingly at each level so that we know where
                        // to start writing.
                        let(read_start, write_start) = if level == 0 {
                            // Note that we previously BOOST_ASSERT_MSGed that data.len() == leafs.
                            (0, Store::len(self))
                        }
                        else {(level_node_index, level_node_index + width)};

                        this->process_layer::<A, U>(width, level, read_start, write_start) ? ;

                        level_node_index += width;
                        level += 1;
                        width >>= shift;    // width /= branches;

                        // When the layer is complete, update the store length
                        // since we know the backing file was updated outside of
                        // the store interface.
                        this->set_len(Store::len(self) + width);
                    }

                    // Ensure every element is accounted for.
                    BOOST_ASSERT_MSG(Store::len(self) == get_merkle_tree_len(leafs, branches)?, "Invalid merkle tree length");

                    BOOST_ASSERT_MSG(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root
                    return this->last()
                }

                void set_len(size_t len) {
                    this->len = len;
                }

                // 'store_range' must be the total number of elements in the store
                // (e.g. tree.len()).  Arity/branches is ignored since a
                // DiskStore's size is related only to the number of elements in
                // the tree.
                bool is_consistent(size_t store_range, size_t _branches, StoreConfig config) {
                    boost::filesystem::path  data_path = StoreConfig::data_path(&config.path, &config.id);

                    let file = File::open(&data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;
                    return (store_size == store_range * Element::byte_len());
                }

                size_t store_size() {
                    return this->store_size;
                }

                std::vector<char> store_read_range(size_t start, size_t end) {
                    size_t read_len = end - start;
                    let mut read_data = vec![0; read_len];
                    this->file.read_exact_at(start as u64, &mut read_data).with_context(|| {
                        format!(
                        "failed to read {} bytes from file at offset {}",
                        read_len, start)})?;

                    BOOST_ASSERT_MSG(read_data.len() == read_len, "Failed to read the full range");

                    return read_data;
                }

                void store_read_into(size_t start, size_t end, buf: &mut [u8]) {
                    this->file.read_exact_at(start as u64, buf).with_context(|| {
                        format!("failed to read {} bytes from file at offset {}", end - start, start)})?;
                }

                void store_copy_from_slice(size_t start, slice: &[u8]) {
                    BOOST_ASSERT_MSG(start + slice.len() <= this->store_size,  "Requested slice too large (max: {})",
                            this->store_size);
                    this->file.write_all_at(start as u64, slice)?;
                }
            }
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_DISK_HPP
