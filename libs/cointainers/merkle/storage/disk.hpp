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
namespace nil {
    namespace filecoin {
        namespace storage {
            template <typename Element>
            struct DiskStore {
                size_t len;
                size_t elem_len;
                FILE* file;
                // This flag is useful only immediate after instantiation, which
                // is false if the store was newly initialized and true if the
                // store was loaded from already existing on-disk data.
                bool loaded_from_disk;
                // We cache the `store.len()` call to avoid accessing disk unnecessarily.
                // Not to be confused with `len`, this saves the total size of the `store`
                // in bytes and the other one keeps track of used `E` slots in the `DiskStore`.
                size_t store_size;

                DiskStore(size_t size; size_t branches; StoreConfig config) {
                    boost::filesystem::path data_path = StoreConfig::data_path(&config.path, &config.id);
                    // If the specified file exists, load it from disk.
                    if (Path::new(&data_path).exists()) {
                        return Self::new_from_disk(size, branches, &config);
                    }

                    // Otherwise, create the file and allow it to be the on-disk store.
                    let file = OpenOptions::new().write(true).read(true).create_new(true).open(data_path)?;

                    let store_size = Element::byte_len() * size;
                    file.set_len(store_size as u64)?;

                    self.len = 0;
                    self.elem_len = Element::byte_len();
                    self.file = file;
                    self.loaded_from_disk = false;
                    self.store_size = store_size;
                }

                DiskStore(size_t size) {
                    size_t store_size = Element::byte_len() * size;
                    FILE *file = tempfile()?;
                    file.set_len(store_size as u64)?;
                    self.len = 0;
                    self.elem_len = Element::byte_len();
                    self.file = file;
                    self.loaded_from_disk = false;
                    self.store_size = store_size;
                }

                DiskStore(size_t size, size_t branches, data: &[u8], StoreConfig config) {
                    assert(data.len() % Element::byte_len() == 0,
                           "data size must be a multiple of {}", Element::byte_len());

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

                StoreConfig(size_t size, data: &[u8]) {
                    assert(data.len() % Element::byte_len() == 0,
                            "data size must be a multiple of {}", Element::byte_len());

                    let mut store = Self::new(size)?;
                    store.store_copy_from_slice(0, data)?;
                    store.len = data.len() / store.elem_len;

                    Ok(store)
                }

                StoreConfig(size_t size, size_t _branches, StoreConfig config) {
                    let data_path = StoreConfig::data_path(&config.path, &config.id);

                    let file = OpenOptions::new().write(true).read(true).open(data_path)?;
                    let metadata = file.metadata()?;
                    let store_size = metadata.len() as usize;

                    // Sanity check.
                    assert(store_size == size * Element::byte_len(),
                            "Invalid formatted file provided. Expected {} bytes, found {} bytes",
                            size * Element::byte_len(), store_size);
                    self.len = size;
                    self.elem_len = Element::byte_len();
                    self.file = file;
                    self.loaded_from_disk = true;
                    self.store_size = store_size;
                }

                void write_at(Element el, size_t index) {
                    self.store_copy_from_slice(index * self.elem_len, el.as_ref())?;
                    self.len = std::cmp::max(self.len, index + 1);
                }

                void copy_from_slice(buf: &[u8], size_t start) {
                    assert(buf.len() % self.elem_len == 0, "buf size must be a multiple of {}", self.elem_len);
                    self.store_copy_from_slice(start * self.elem_len, buf)?;
                    self.len = std::cmp::max(self.len, start + buf.len() / self.elem_len);
                }

                Element read_at(size_t index) {
                    size_t start = index * self.elem_len;
                    size_t end = start + self.elem_len;

                    size_t len = self.len * self.elem_len;
                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    return Element::from_slice(&self.store_read_range(start, end)?))
                }

                void read_into(size_t index, buf: &mut [u8]) {
                    size_t start = index * self.elem_len;
                    size_t end = start + self.elem_len;

                    size_t len = self.len * self.elem_len;
                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    self.store_read_into(start, end, buf)
                }

                void read_range_into(size_t start, size_t end, buf: &mut [u8]) {
                    size_t start = start * self.elem_len;
                    size_t end = end * self.elem_len;

                    size_t len = self.len * self.elem_len;
                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    self.store_read_into(start, end, buf)
                }

                std::vector<Element> read_range(r: ops::Range<usize>) {
                    size_t start = r.start * self.elem_len;
                    size_t end = r.end * self.elem_len;

                    size_t len = self.len * self.elem_len;
                    assert(start < len, "start out of range {} >= {}", start, len);
                    assert(end <= len, "end out of range {} > {}", end, len);

                    return self.store_read_range(start, end)?.chunks(self.elem_len).map(E::from_slice).collect())
                }

                size_t len() {
                    return self.len;
                }

                boool loaded_from_disk() {
                    return self.loaded_from_disk;
                }

                // Specifically, this method truncates an existing DiskStore and
                // formats the data in such a way that is compatible with future
                // access using LevelCacheStore::new_from_disk.
                bool compact(size_t branches, StoreConfig config, uint32_t store_version) {
                    // Determine how many base layer leafs there are (and in bytes).
                    let leafs = get_merkle_tree_leafs(self.len, branches)?;
                    let data_width = leafs * self.elem_len;

                    // Calculate how large the cache should be (based on the
                    // config.rows_to_discard param).
                    let cache_size =
                        get_merkle_tree_cache_size(leafs, branches, config.rows_to_discard)? * self.elem_len;

                    // The file cannot be compacted if the specified configuration
                    // requires either 1) nothing to be cached, or 2) everything
                    // to be cached.  For #1, create a data store of leafs and do
                    // not use that store as backing for the MT.  For #2, avoid
                    // calling this method.  To resolve, provide a sane
                    // configuration.
                    assert(cache_size < self.len * self.elem_len && cache_size != 0, "Cannot compact with this configuration");

                    let v1 = store_version == StoreConfigDataVersion::One as u32;
                    let start: u64 = if v1 { data_width as u64 } else { 0 };

                    // Calculate cache start and updated size with repect to the
                    // data size.
                    let cache_start = self.store_size - cache_size;

                    // Seek the reader to the start of the cached data.
                    let mut reader = OpenOptions::new().read(true)
                         .open(StoreConfig::data_path(&config.path, &config.id))?;
                    reader.seek(SeekFrom::Start(cache_start as u64))?;

                    // Make sure the store file is opened for read/write.
                    self.file = OpenOptions::new().read(true).write(true)
                         .open(StoreConfig::data_path(&config.path, &config.id))?;

                    // Seek the writer.
                    self.file.seek(SeekFrom::Start(start))?;

                    // Copy the data from the cached region to the writer.
                    let written = copy(&mut reader, &mut self.file)?;
                    assert(written == cache_size as u64, "Failed to copy all data");
                    if (v1) {
                            // Truncate the data on-disk to be the base layer data
                            // followed by the cached data.
                            self.file.set_len((data_width + cache_size) as u64)?;
                            // Adjust our length for internal consistency.
                            self.len = (data_width + cache_size) / self.elem_len;
                        } else {
                        // Truncate the data on-disk to be only the cached data.
                        self.file.set_len(cache_size as u64)?;

                        // Adjust our length to be the cached elements only for
                        // internal consistency.
                        self.len = cache_size / self.elem_len;
                    }

                    // Sync and sanity check that we match on disk (this can be
                    // removed if needed).
                    self.sync()?;
                    let metadata = self.file.metadata()?;
                    let store_size = metadata.len() as usize;
                    assert(self.len * self.elem_len == store_size, "Inconsistent metadata detected");
                    return true;
                }

                void delete(StoreConfig config) {
                    boost::filesystem::path  path = StoreConfig::data_path(&config.path, &config.id);
                    remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))
                }

                bool is_empty() {
                    return (self.len == 0);
                }

                void push(Element el) {
                    size_t len = self.len;
                    assert((len + 1) * self.elem_len <= self.store_size(),
                           "not enough space, len: {}, E size {}, store len {}",
                            len, self.elem_len, self.store_size());

                    self.write_at(el, len)
                }

                void sync() {
                    self.file.sync_all().context("failed to sync file");
                }

                template<typename Algorithm<Element>, typename Unsigned>
                void process_layer(size_t width, size_t level, size_t read_start, size_t write_start) {
                    // Safety: this operation is safe becase it's a limited
                    // writable region on the backing store managed by this type.
                    let mut mmap = unsafe {
                        let mut mmap_options = MmapOptions::new();
                        mmap_options.offset((write_start * E::byte_len()) as u64).len(width * E::byte_len()).map_mut(&self.file)
                    }?;

                    let data_lock = Arc::new(RwLock::new(self));
                    let branches = U::to_usize();
                    let shift = log2_pow2(branches);
                    let write_chunk_width = (BUILD_CHUNK_NODES >> shift) * E::byte_len();

                    assert(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
                    Vec::from_iter((read_start..read_start + width).step_by(BUILD_CHUNK_NODES))
                        .into_par_iter()
                        .zip(mmap.par_chunks_mut(write_chunk_width))
                        .try_for_each(|(chunk_index, write_mmap)| -> Result<()> {
                        let chunk_size = std::cmp::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);

                        let chunk_nodes = {
                            // Read everything taking the lock once.
                            data_lock
                                .read()
                                .unwrap()
                                .read_range(chunk_index..chunk_index + chunk_size)?
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
                    assert(next_pow2(branches) == branches, "branches MUST be a power of 2");
                    assert(Store::len(self) == leafs, "Inconsistent data");
                    assert(leafs % 2 == 0, "Leafs must be a power of two");

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
                            // Note that we previously asserted that data.len() == leafs.
                            (0, Store::len(self))
                        }
                        else {(level_node_index, level_node_index + width)};

                        self.process_layer::<A, U>(width, level, read_start, write_start) ? ;

                        level_node_index += width;
                        level += 1;
                        width >>= shift;    // width /= branches;

                        // When the layer is complete, update the store length
                        // since we know the backing file was updated outside of
                        // the store interface.
                        self.set_len(Store::len(self) + width);
                    }

                    // Ensure every element is accounted for.
                    assert(Store::len(self) == get_merkle_tree_len(leafs, branches)?, "Invalid merkle tree length");

                    assert(row_count == level + 1, "Invalid tree row_count");
                    // The root isn't part of the previous loop so `row_count` is
                    // missing one level.

                    // Return the root
                    return self.last()
                }

                void set_len(size_t len) {
                    self.len = len;
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
                    return self.store_size;
                }

                std::vector<char> store_read_range(size_t start, size_t end) {
                    size_t read_len = end - start;
                    let mut read_data = vec![0; read_len];
                    self.file.read_exact_at(start as u64, &mut read_data).with_context(|| {
                        format!(
                        "failed to read {} bytes from file at offset {}",
                        read_len, start)})?;

                    assert(read_data.len() == read_len, "Failed to read the full range");

                    return read_data;
                }

                void store_read_into(size_t start, size_t end, buf: &mut [u8]) {
                    self.file.read_exact_at(start as u64, buf).with_context(|| {
                        format!("failed to read {} bytes from file at offset {}", end - start, start)})?;
                }

                void store_copy_from_slice(size_t start, slice: &[u8]) {
                    assert(start + slice.len() <= self.store_size,  "Requested slice too large (max: {})",
                            self.store_size);
                    self.file.write_all_at(start as u64, slice)?;
                }
            }
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_DISK_HPP
