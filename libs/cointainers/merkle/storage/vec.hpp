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


#ifndef FILECOIN_VEC_HPP
#define FILECOIN_VEC_HPP
namespace nil {
    namespace filecoin {
        namespace merkletree {
            template <typename Element>
            struct VecStore {
                VecStore(size: usize, _branches: usize, _config: StoreConfig) {
                    VecStore(size);
                }

                VecStore(size: usize) {
                    Ok(VecStore(Vec::with_capacity(size)))
                }

                void write_at(Element el, size_t index) {
                    if self.0.len() <= index {
                        self.0.resize(index + 1, E::default());
                    }

                    self.0[index] = el;
                }

                // NOTE: Performance regression. To conform with the current API we are
                // unnecessarily converting to and from `&[u8]` in the `VecStore` which
                // already stores `E` (in contrast with the `mmap` versions). We are
                // prioritizing performance for the `mmap` case which will be used in
                // production (`VecStore` is mainly for testing and backwards compatibility).
                void copy_from_slice(buf: &[u8], size_t start) {
                    assert(buf.len() % Element::byte_len() == 0, "buf size must be a multiple of {}", Element::byte_len());
                    let num_elem = buf.len() / Element::byte_len();

                    if (self.0.len() < start + num_elem) {
                        self.0.resize(start + num_elem, Element::default());
                    }

                    self.0.splice(
                        start..start + num_elem,
                        buf.chunks_exact(E::byte_len()).map(E::from_slice),
                    );
                }

                VecStore(size_t size, size_t _branches, data: &[u8], StoreConfig _config) {
                    Self::new_from_slice(size, &data)
                }

                VecStore(size_t size, data: &[u8]) {
                    let mut v: Vec<_> = data.chunks_exact(E::byte_len()).map(E::from_slice).collect();
                    let additional = size - v.len();
                    v.reserve(additional);
                    Ok(VecStore(v))
                }

                VecStore(size_t _size, size_t _branches, StoreConfig _config) {
                    assert(false, "Cannot load a VecStore from disk");
                }

                Element read_at(size_t index) {
                   return self.0[index].clone();
                }

                void read_into(size_t index, buf: &mut [u8]) {
                    self.0[index].copy_to_slice(buf);
                }

                void read_range_into(size_t _start, size_t _end, _buf: &mut [u8]) {
                    assert(false, "Not required here");
                }

                std::vector<Element> read_range(r: ops::Range<usize>) {
                    Ok(self.0.index(r).to_vec())
                }

                size_t len() {
                    self.0.len()
                }

                bool loaded_from_disk() {
                    return false;
                }

                bool compact(size_t _branches, StoreConfig _config, uint32_t _store_version: u32) {
                    self.0.shrink_to_fit();
                    return true;
                }

                bool is_empty() {
                    self.0.is_empty()
                }

                void push(Element el) {
                    self.0.push(el);
                }
            };
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_VEC_HPP
