//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_PROCESSING_INTERGRAL_HPP
#define CRYPTO3_MARSHALLING_PROCESSING_INTERGRAL_HPP

#include <iterator>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <limits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace processing {

                /// @brief Write part of integral value into the output area using big
                ///     endian notation.
                /// @tparam TSize Number of bytes to write.
                /// @param[in] value Integral type value to be written.
                /// @param[in, out] iter Output iterator.
                /// @pre TSize <= sizeof(T).
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least TSize times.
                /// @post The iterator is advanced.
                template<typename T, typename TIter>
                void write_big_endian(T value, TIter &iter) {
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;

                    export_bits(value, iter, chunk_bits, true);
                }

                /// @brief Write part of integral value into the output area using big
                ///     endian notation.
                /// @tparam TSize Number of bytes to write.
                /// @param[in] value Integral type value to be written.
                /// @param[in, out] iter Output iterator.
                /// @pre TSize <= sizeof(T).
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least TSize times.
                /// @post The iterator is advanced.
                template<std::size_t TSize, typename T, typename TIter>
                void write_big_endian(T value, TIter &iter) {
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (TSize / chunk_bits) + ((TSize % chunk_bits) ? 1 : 0);

                    if (value > 0) {
                        std::size_t begin_index =
                            chunks_count - ((nil::crypto3::multiprecision::msb(value) + 1) / chunk_bits +
                                            (((nil::crypto3::multiprecision::msb(value) + 1) % chunk_bits) ? 1 : 0));

                        std::fill(iter, iter + begin_index, 0);

                        export_bits(value, iter + begin_index, chunk_bits, true);
                    } else {
                        std::fill(iter, iter + chunks_count, 0);
                    }
                }

                /// @brief Read part of integral value from the input area using big
                ///     endian notation.
                /// @tparam T Type to read.
                /// @tparam TSize Number of bytes to read.
                /// @param[in, out] iter Input iterator.
                /// @return Read value
                /// @pre TSize <= sizeof(T).
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least TSize times.
                /// @post The iterator is advanced.
                template<typename T, typename TIter>
                T read_big_endian(TIter &iter, std::size_t value_size) {
                    T serializedValue;
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (value_size / chunk_bits) + ((value_size % chunk_bits) ? 1 : 0);

                    multiprecision::import_bits(serializedValue, iter, iter + chunks_count, chunk_bits, true);
                    return serializedValue;
                }

                /// @brief Read part of integral value from the input area using big
                ///     endian notation.
                /// @tparam T Type to read.
                /// @tparam TSize Number of bytes to read.
                /// @param[in, out] iter Input iterator.
                /// @return Read value
                /// @pre TSize <= sizeof(T).
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least TSize times.
                /// @post The iterator is advanced.
                template<std::size_t TSize, typename T, typename TIter>
                T read_big_endian(TIter &iter) {
                    T serializedValue;
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (TSize / chunk_bits) + ((TSize % chunk_bits) ? 1 : 0);

                    multiprecision::import_bits(serializedValue, iter, iter + chunks_count, chunk_bits, true);
                    return serializedValue;
                }

                /// @brief Write integral value into the output area using big
                ///     endian notation.
                /// @param[in] value Integral type value to be written.
                /// @param[in, out] iter Output iterator.
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least sizeof(T) times.
                /// @post The iterator is advanced.
                template<typename T, typename TIter>
                void write_little_endian(T value, TIter &iter) {
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;

                    export_bits(value, iter, chunk_bits, false);
                }

                /// @brief Write integral value into the output area using big
                ///     endian notation.
                /// @param[in] value Integral type value to be written.
                /// @param[in, out] iter Output iterator.
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least sizeof(T) times.
                /// @post The iterator is advanced.
                template<std::size_t TSize, typename T, typename TIter>
                void write_little_endian(T value, TIter &iter) {
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (TSize / chunk_bits) + ((TSize % chunk_bits) ? 1 : 0);

                    if (value > 0) {
                        std::size_t begin_index = ((nil::crypto3::multiprecision::msb(value) + 1) / chunk_bits +
                                            (((nil::crypto3::multiprecision::msb(value) + 1) % chunk_bits) ? 1 : 0));

                        if (begin_index < chunks_count) {
                            std::fill(iter + begin_index, iter + chunks_count, 0x00);
                        }

                        export_bits(value, iter, chunk_bits, false);
                    } else {
                        std::fill(iter, iter + chunks_count, 0);
                    }
                }

                /// @brief Read integral value from the input area using little
                ///     endian notation.
                /// @tparam T Type to read.
                /// @param[in, out] iter Input iterator.
                /// @return Read value
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least sizeof(T) times.
                /// @post The iterator is advanced.
                template<typename T, typename TIter>
                T read_little_endian(TIter &iter, std::size_t value_size) {
                    T serializedValue;
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (value_size / chunk_bits) + ((value_size % chunk_bits) ? 1 : 0);

                    multiprecision::import_bits(serializedValue, iter, iter + chunks_count, chunk_bits, false);
                    return serializedValue;
                }

                /// @brief Read integral value from the input area using little
                ///     endian notation.
                /// @tparam T Type to read.
                /// @param[in, out] iter Input iterator.
                /// @return Read value
                /// @pre The iterator must be valid and can be successfully dereferenced
                ///      and incremented at least sizeof(T) times.
                /// @post The iterator is advanced.
                template<std::size_t TSize, typename T, typename TIter>
                T read_little_endian(TIter &iter) {
                    T serializedValue;
                    std::size_t units_bits = std::is_same_v<typename std::iterator_traits<TIter>::value_type, bool> ? 
                                        1 : sizeof(typename std::iterator_traits<TIter>::value_type) * 8;
                    std::size_t chunk_bits = sizeof(typename std::iterator_traits<TIter>::value_type) * units_bits;
                    std::size_t chunks_count = (TSize / chunk_bits) + ((TSize % chunk_bits) ? 1 : 0);

                    multiprecision::import_bits(serializedValue, iter, iter + chunks_count, chunk_bits, false);
                    return serializedValue;
                }

                /// @brief Same as write_big_endian<T, TIter>()
                template<typename Endianness, typename T, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::big_endian>::value,
                                        void>::type
                    write_data(T value, TIter &iter) {

                    write_big_endian(value, iter);
                }

                /// @brief Same as write_big_endian<TSize, T, TIter>()
                template<std::size_t TSize, typename Endianness, typename T, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::big_endian>::value,
                                        void>::type
                    write_data(T value, TIter &iter) {

                    write_big_endian<TSize>(value, iter);
                }

                /// @brief Same as write_little_endian<T, TIter>()
                template<typename Endianness, typename T, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::little_endian>::value,
                                        void>::type
                    write_data(T value, TIter &iter) {

                    write_little_endian(value, iter);
                }

                /// @brief Same as write_little_endian<TSize, T, TIter>()
                template<std::size_t TSize, typename Endianness, typename T, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::little_endian>::value,
                                        void>::type
                    write_data(T value, TIter &iter) {

                    write_little_endian<TSize>(value, iter);
                }

                /// @brief Same as read_big_endian<T, TIter>()
                template<typename T, typename Endianness, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::big_endian>::value, T>::type
                    read_data(TIter &iter, std::size_t value_size) {

                    return read_big_endian<T>(iter, value_size);
                }

                /// @brief Same as read_little_endian<T, TIter>()
                template<typename T, typename Endianness, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::little_endian>::value,
                                        T>::type
                    read_data(TIter &iter, std::size_t value_size) {

                    return read_little_endian<T>(iter, value_size);
                }

                /// @brief Same as read_big_endian<TSize, T, TIter>()
                template<std::size_t TSize, typename T, typename Endianness, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::big_endian>::value, T>::type
                    read_data(TIter &iter) {

                    return read_big_endian<TSize, T>(iter);
                }

                /// @brief Same as read_little_endian<TSize, T, TIter>()
                template<std::size_t TSize, typename T, typename Endianness, typename TIter>
                typename std::enable_if<std::is_same<Endianness, nil::marshalling::endian::little_endian>::value,
                                        T>::type
                    read_data(TIter &iter) {

                    return read_little_endian<TSize, T>(iter);
                }
            }    // namespace processing
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_PROCESSING_INTERGRAL_HPP
