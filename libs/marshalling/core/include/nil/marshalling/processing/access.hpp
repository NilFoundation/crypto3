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

#ifndef MARSHALLING_PROCESSING_ACCESS_HPP
#define MARSHALLING_PROCESSING_ACCESS_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <limits>
#include <iterator>

#include <nil/marshalling/processing/detail/access.hpp>
#include <nil/marshalling/endianness.hpp>

namespace nil {
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
            template<std::size_t TSize, typename T, typename TIter>
            void write_big_endian(T value, TIter &iter) {
                detail::writer<detail::write_helper>::template write<endian::big_endian, TSize>(value, iter);
            }

            /// @brief Write integral value into the output area using big
            ///     endian notation.
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            template<typename T, typename TIter>
            void write_big_endian(T value, TIter &iter) {
                using value_type = typename std::decay<T>::type;
                write_big_endian<sizeof(value_type)>(static_cast<value_type>(value), iter);
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
            template<typename T, std::size_t TSize, typename TIter>
            T read_big_endian(TIter &iter) {
                return detail::reader<detail::read_helper>::template read<endian::big_endian, T, TSize>(iter);
            }

            /// @brief Read integral value from the input area using big
            ///     endian notation.
            /// @tparam T Type to read.
            /// @param[in, out] iter Input iterator.
            /// @return Read value
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least sizeof(T) times.
            /// @post The iterator is advanced.
            template<typename T, typename TIter>
            T read_big_endian(TIter &iter) {
                using value_type = typename std::decay<T>::type;
                return static_cast<T>(read_big_endian<value_type, sizeof(value_type)>(iter));
            }

            /// @brief Write part of integral value into the output area using little
            ///     endian notation.
            /// @tparam TSize Number of bytes to write.
            /// @param[in] value Integral type value to be written.
            /// @param[in, out] iter Output iterator.
            /// @pre TSize <= sizeof(T).
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The iterator is advanced.
            template<std::size_t TSize, typename T, typename TIter>
            void write_little_endian(T value, TIter &iter) {
                detail::writer<detail::write_helper>::template write<endian::little_endian, TSize>(value, iter);
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
                using value_type = typename std::decay<T>::type;
                write_little_endian<sizeof(value_type)>(static_cast<value_type>(value), iter);
            }

            /// @brief Read part of integral value from the input area using little
            ///     endian notation.
            /// @tparam T Type to read.
            /// @tparam TSize Number of bytes to read.
            /// @param[in, out] iter Input iterator.
            /// @return Read value
            /// @pre TSize <= sizeof(T).
            /// @pre The iterator must be valid and can be successfully dereferenced
            ///      and incremented at least TSize times.
            /// @post The iterator is advanced.
            template<typename T, std::size_t TSize, typename TIter>
            T read_little_endian(TIter &iter) {
                return detail::reader<detail::read_helper>::template read<endian::little_endian, T, TSize>(iter);
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
            T read_little_endian(TIter &iter) {
                using value_type = typename std::decay<T>::type;
                return static_cast<T>(read_little_endian<value_type, sizeof(value_type)>(iter));
            }

            /// @brief Same as writeBig<T, TIter>()
            template<typename T, typename TIter>
            void write_data(T value, TIter &iter, const endian::big_endian &endian) {
                static_cast<void>(endian);
                write_big_endian(value, iter);
            }

            /// @brief Same as writeBig<TSize, T, TIter>()
            template<std::size_t TSize, typename T, typename TIter>
            void write_data(T value, TIter &iter, const endian::big_endian &endian) {
                static_cast<void>(endian);
                write_big_endian<TSize>(value, iter);
            }

            /// @brief Same as writeLittle<T, TIter>()
            template<typename T, typename TIter>
            void write_data(T value, TIter &iter, const endian::little_endian &endian) {
                static_cast<void>(endian);
                write_little_endian(value, iter);
            }

            /// @brief Same as writeLittle<TSize, T, TIter>()
            template<std::size_t TSize, typename T, typename TIter>
            void write_data(T value, TIter &iter, const endian::little_endian &endian) {
                static_cast<void>(endian);
                return write_little_endian<TSize>(value, iter);
            }

            /// @brief Same as readBig<T, TIter>()
            template<typename T, typename TIter>
            T read_data(TIter &iter, const endian::big_endian &endian) {
                static_cast<void>(endian);
                return read_big_endian<T>(iter);
            }

            /// @brief Same as readBig<T, TSize, TIter>()
            template<typename T, std::size_t TSize, typename TIter>
            T read_data(TIter &iter, const endian::big_endian &endian) {
                static_cast<void>(endian);
                return read_big_endian<T, TSize>(iter);
            }

            /// @brief Same as readLittle<T, TIter>()
            template<typename T, typename TIter>
            T read_data(TIter &iter, const endian::little_endian &endian) {
                static_cast<void>(endian);
                return read_little_endian<T>(iter);
            }

            /// @brief Same as read_data<T, TSize, TIter>()
            template<typename T, std::size_t TSize, typename TIter>
            T read_data(TIter &iter, const endian::little_endian &endian) {
                static_cast<void>(endian);
                return read_little_endian<T, TSize>(iter);
            }

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_ACCESS_HPP
