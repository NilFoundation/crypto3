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

#ifndef MARSHALLING_PROCESSING_ACCESS_DETAIL_HPP
#define MARSHALLING_PROCESSING_ACCESS_DETAIL_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <limits>
#include <iterator>

#include <nil/marshalling/endianness.hpp>

namespace nil {
    namespace marshalling {
        namespace processing {
            namespace detail {

                template<typename T, bool TMakeIntSize>
                struct type_optimiser;

                template<typename T>
                struct type_optimiser<T, false> {
                    using type = typename std::decay<T>::type;
                };

                template<typename T>
                struct type_optimiser<T, true> {
                    using type = typename std::conditional<std::is_signed<T>::value, int, unsigned>::type;
                };

                template<typename T>
                using optimised_value_type = typename type_optimiser<T, (sizeof(T) < sizeof(int))>::type;

                template<typename TUnsignedByteType, typename T>
                typename std::decay<T>::type sign_ext_common(T value, std::size_t size) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_unsigned<value_type>::value, "type T must be unsigned");
                    static_assert(std::is_unsigned<TUnsignedByteType>::value,
                                  "type TUnsignedByteType must be unsigned");

                    static const std::size_t binary_digits = std::numeric_limits<TUnsignedByteType>::digits;
                    static_assert(binary_digits % 8 == 0, "Byte size assumption is not valid");

                    value_type mask = (static_cast<value_type>(1) << ((size * binary_digits) - 1));
                    if (value & mask) {
                        return value | (~((mask << 1) - 1));
                    }
                    return value;
                }

                template<typename T, std::size_t TSize, typename TByteType>
                class sign_ext {
                    struct full_size { };
                    struct partial_size { };

                public:
                    using value_type = typename std::decay<T>::type;

                    static value_type value(T val) {
                        using tag =
                            typename std::conditional<sizeof(value_type) == TSize, full_size, partial_size>::type;

                        return value_internal(val, tag());
                    }

                private:
                    static value_type value_internal(T val, full_size) {
                        return val;
                    }

                    static value_type value_internal(T val, partial_size) {
                        using UnsignedValueType = typename std::make_unsigned<value_type>::type;
                        static_assert(std::is_integral<value_type>::value, "T must be integer type");
                        using UnsignedByteType = typename std::make_unsigned<TByteType>::type;

                        auto castedValue = static_cast<UnsignedValueType>(val);
                        return static_cast<value_type>(sign_ext_common<UnsignedByteType>(castedValue, TSize));
                    }
                };

                template<typename TIter, bool TIsPointer>
                struct byte_type_retriever;

                template<typename TIter>
                struct byte_type_retriever<TIter, true> {
                    using type = typename std::decay<decltype(*(TIter()))>::type;
                };

                template<typename TIter>
                struct byte_type_retriever<TIter, false> {
                    using decayed_iterator = typename std::decay<TIter>::type;
                    using type = typename decayed_iterator::value_type;
                };

                template<typename TContainer>
                struct byte_type_retriever<std::back_insert_iterator<TContainer>, false> {
                    using decayed_container_type = typename std::decay<TContainer>::type;
                    using type = typename decayed_container_type::value_type;
                };

                template<typename TContainer>
                struct byte_type_retriever<std::front_insert_iterator<TContainer>, false> {
                    using decayed_container_type = typename std::decay<TContainer>::type;
                    using type = typename decayed_container_type::value_type;
                };

                template<typename TIter>
                using byte_type = typename byte_type_retriever<TIter, std::is_pointer<TIter>::value>::type;

                template<typename T, typename TIter>
                void write_big_endian_unsigned(T value, std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_unsigned<value_type>::value, "T type must be unsigned");
                    static_assert(std::is_integral<value_type>::value, "T must be integral type");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;
                    static const std::size_t BinDigits = std::numeric_limits<UnsignedByteType>::digits;
                    static_assert(BinDigits % 8 == 0, "Byte size assumption is not valid");

                    std::size_t remainingSize = size;
                    while (remainingSize > 0) {
                        std::size_t remaingShift = ((remainingSize - 1) * BinDigits);
                        auto byte = static_cast<byte_type>(value >> remaingShift);
                        *iter = byte;
                        ++iter;
                        --remainingSize;
                    }
                }

                template<typename T, typename TIter>
                void write_little_endian_unsigned(T value, std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    static_assert(std::is_unsigned<value_type>::value, "T type must be unsigned");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;
                    static const std::size_t BinDigits = std::numeric_limits<UnsignedByteType>::digits;
                    static_assert(BinDigits % 8 == 0, "Byte size assumption is not valid");

                    std::size_t remainingSize = size;
                    while (remainingSize > 0) {
                        std::size_t remaingShift = ((size - remainingSize) * BinDigits);

                        auto byte = static_cast<byte_type>(value >> remaingShift);
                        *iter = byte;
                        ++iter;
                        --remainingSize;
                    }
                }

                template<typename TEndian>
                struct write_unsigned_func_wrapper;

                template<>
                struct write_unsigned_func_wrapper<endian::big_endian> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        write_big_endian_unsigned(value, size, iter);
                    }
                };

                template<>
                struct write_unsigned_func_wrapper<endian::little_endian> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        write_little_endian_unsigned(value, size, iter);
                    }
                };

                template<typename TEndian, typename T, typename TIter>
                void write(T value, std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    using UnsignedType = typename std::make_unsigned<value_type>::type;
                    UnsignedType unsignedValue = static_cast<UnsignedType>(value);
                    write_unsigned_func_wrapper<TEndian>::write(unsignedValue, size, iter);
                }

                template<typename TEndian, typename T, typename TIter>
                void write_random_access(T value, std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;

                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    static_assert(std::is_same<typename std::iterator_traits<TIter>::iterator_category,
                                               std::random_access_iterator_tag>::value,
                                  "TIter must be random access iterator");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;
                    static_assert(!std::is_const<UnsignedByteType>::value, "value must be updatable");

                    auto startPtr = reinterpret_cast<UnsignedByteType *>(&(*iter));
                    auto endPtr = startPtr;
                    write<TEndian>(value, size, endPtr);
                    iter += (endPtr - startPtr);
                }

                template<typename TEndian, bool TIsPointerToUnsigned>
                struct write_random_access_helper;

                template<typename TEndian>
                struct write_random_access_helper<TEndian, false> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        write_random_access<TEndian>(value, size, iter);
                    }
                };

                template<typename TEndian>
                struct write_random_access_helper<TEndian, true> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        detail::write<TEndian>(value, size, iter);
                    }
                };

                template<typename TEndian, bool TIsRandomAccess>
                struct write_helper;

                template<typename TEndian>
                struct write_helper<TEndian, false> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        detail::write<TEndian>(value, size, iter);
                    }
                };

                template<typename TEndian>
                struct write_helper<TEndian, true> {
                    template<typename T, typename TIter>
                    static void write(T value, std::size_t size, TIter &iter) {
                        using byte_type = byte_type<TIter>;
                        static const bool IsPointerToUnsigned
                            = std::is_pointer<TIter>::value && std::is_unsigned<byte_type>::value;
                        return write_random_access_helper<TEndian, IsPointerToUnsigned>::write(value, size, iter);
                    }
                };

                template<typename T, typename TIter>
                T read_big_endian_unsigned(std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    static_assert(std::is_unsigned<value_type>::value, "T type must be unsigned");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;
                    static const std::size_t BinDigits = std::numeric_limits<UnsignedByteType>::digits;
                    static_assert(BinDigits % 8 == 0, "Byte size assumption is not valid");

                    value_type value = 0;
                    std::size_t remainingSize = size;
                    while (remainingSize > 0) {
                        auto byte = *iter;
                        value <<= BinDigits;
                        value |= static_cast<decltype(value)>(static_cast<UnsignedByteType>(byte));
                        ++iter;
                        --remainingSize;
                    }
                    return value;
                }

                template<typename T, typename TIter>
                T read_little_endian_unsigned(std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;
                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    static_assert(std::is_unsigned<value_type>::value, "T type must be unsigned");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;
                    static const std::size_t BinDigits = std::numeric_limits<UnsignedByteType>::digits;
                    static_assert(BinDigits % 8 == 0, "Byte size assumption is not valid");

                    value_type value = 0;
                    std::size_t remainingSize = size;
                    while (remainingSize > 0) {
                        auto byte = *iter;
                        value |= static_cast<value_type>(static_cast<UnsignedByteType>(byte))
                                 << ((size - remainingSize) * BinDigits);
                        ++iter;
                        --remainingSize;
                    }

                    return static_cast<T>(value);
                }

                template<typename TEndian>
                struct read_unsigned_func_wrapper;

                template<>
                struct read_unsigned_func_wrapper<endian::big_endian> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return read_big_endian_unsigned<T>(size, iter);
                    }
                };

                template<>
                struct read_unsigned_func_wrapper<endian::little_endian> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return read_little_endian_unsigned<T>(size, iter);
                    }
                };

                template<typename TEndian, typename T, typename TIter>
                T read(std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;

                    static_assert(std::is_integral<value_type>::value, "T must be integral type");

                    using UnsignedType = typename std::make_unsigned<value_type>::type;
                    auto value = read_unsigned_func_wrapper<TEndian>::template read<UnsignedType>(size, iter);
                    return static_cast<T>(static_cast<value_type>(value));
                }

                template<typename TEndian, typename T, typename TIter>
                T read_from_pointer_to_signed(std::size_t size, TIter &iter) {
                    using value_type = typename std::decay<T>::type;

                    static_assert(std::is_integral<value_type>::value, "T must be integral type");
                    static_assert(std::is_same<typename std::iterator_traits<TIter>::iterator_category,
                                               std::random_access_iterator_tag>::value,
                                  "TIter must be random access iterator");

                    using byte_type = byte_type<TIter>;
                    using UnsignedByteType = typename std::make_unsigned<byte_type>::type;

                    auto startPtr = reinterpret_cast<const UnsignedByteType *>(&(*iter));
                    auto endPtr = startPtr;
                    auto value = detail::read<TEndian, value_type>(size, endPtr);
                    iter += (endPtr - startPtr);
                    return static_cast<T>(static_cast<value_type>(value));
                }

                template<typename TEndian, bool TIsPointer, bool TIsUnsignedConst>
                struct read_random_access_helper;

                template<typename TEndian>
                struct read_random_access_helper<TEndian, true, false> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return read_from_pointer_to_signed<TEndian, T>(size, iter);
                    }
                };

                template<typename TEndian>
                struct read_random_access_helper<TEndian, true, true> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return detail::read<TEndian, T>(size, iter);
                    }
                };

                template<typename TEndian, bool TIsUnsignedConst>
                struct read_random_access_helper<TEndian, false, TIsUnsignedConst> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return detail::read<TEndian, T>(size, iter);
                    }
                };

                template<typename TEndian, bool TIsRandomAccess>
                struct read_helper;

                template<typename TEndian>
                struct read_helper<TEndian, false> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        return detail::read<TEndian, T>(size, iter);
                    }
                };

                template<typename TEndian>
                struct read_helper<TEndian, true> {
                    template<typename T, typename TIter>
                    static T read(std::size_t size, TIter &iter) {
                        using byte_type = byte_type<TIter>;
                        static const bool IsPointer = std::is_pointer<TIter>::value;

                        static const bool IsUnsignedConstData
                            = std::is_const<byte_type>::value && std::is_unsigned<byte_type>::value;
                        return read_random_access_helper<TEndian, IsPointer, IsUnsignedConstData>::template read<T>(
                            size, iter);
                    }
                };

                template<template<typename, bool> class THelper>
                struct writer {
                    template<typename TEndian, std::size_t TSize, typename T, typename TIter>
                    static void write(T value, TIter &iter) {
                        using value_type = typename std::decay<T>::type;
                        using optimised_value_type = detail::optimised_value_type<value_type>;

                        static_assert(TSize <= sizeof(value_type), "Precondition failure");
                        static const bool IsRandomAccess
                            = std::is_same<typename std::iterator_traits<TIter>::iterator_category,
                                           std::random_access_iterator_tag>::value;
                        THelper<TEndian, IsRandomAccess>::write(static_cast<optimised_value_type>(value), TSize, iter);
                    }
                };

                template<template<typename, bool> class THelper>
                struct reader {
                    template<typename TEndian, typename T, std::size_t TSize, typename TIter>
                    static T read(TIter &iter) {
                        using value_type = typename std::decay<T>::type;
                        using optimised_value_type = detail::optimised_value_type<value_type>;
                        using byte_type = detail::byte_type<TIter>;

                        static_assert(TSize <= sizeof(value_type), "Precondition failure");
                        static const bool IsRandomAccess
                            = std::is_same<typename std::iterator_traits<TIter>::iterator_category,
                                           std::random_access_iterator_tag>::value;
                        auto retval = static_cast<value_type>(
                            THelper<TEndian, IsRandomAccess>::template read<optimised_value_type>(TSize, iter));

                        if (std::is_signed<value_type>::value) {
                            retval = detail::sign_ext<decltype(retval), TSize, byte_type>::value(retval);
                        }
                        return static_cast<T>(retval);
                    }
                };
            }    // namespace detail
        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_ACCESS_DETAIL_HPP
