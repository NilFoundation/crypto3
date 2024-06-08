//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STATIC_DIGEST_HPP
#define CRYPTO3_STATIC_DIGEST_HPP

#include <boost/static_assert.hpp>
#include <boost/assert.hpp>

#include <array>
#include <string>
#include <cstring>
#include <iostream>

#include <nil/crypto3/detail/octet.hpp>
#include <nil/crypto3/detail/pack.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * The digest class template stores a DigestBits-bit message digest as a sequence of 8-bit octets.
         * Octets are stored in the smallest std::size_t type able to hold 8 bits, hereinafter referred to as
         * octet_type. DigestBits must be a multiple of 8.
         *
         * It is independent of any particular algorithm; For example sha2<224> and cubehash<224> both produce a
         * digest<224>. Each algorithm generates its digest such that it will be displayed in the canonical order
         * for that algorithm. The truncate and resize function templates are provided to handle digests with
         * lengths other than you're expecting. For instance, generating name-based UUIDs uses only 128 bits but
         * SHA-1 provides a 160-bit digest, so it would be truncated. (Using truncate instead of resize means
         * that a compilation error will result from trying to use a hash algorithm with too small an output.) On
         * the other hand, for storing as much as possible of the results of various algorithms, resize allows
         * you to pad them out to a large size, such as a digest<512>.
         *
         * digest<DigestBits> derives publicly from std::array<octet_type, DigestBits/8> and supports all of
         * its operations in order to provide direct access to the contained octets. Note that a digest is not
         * an aggregate; A default-constructed digest has all its contained octets set to zero. The base_array()
         * member function provides a reference to the std::array sub-object.
         *
         * digests with different numbers of bits may be compared. For the comparison, the smaller is considered
         * as though it were padded with 0s out to the size of the larger. The operator< provides a strict total
         * order. For convenience, equality comparison with narrow c-style strings is also provided.
         *
         * Always stored internally as a sequence of octets in display order.
         * This allows digests from different algorithms to have the same type,
         * allowing them to be more easily stored and compared.
         *
         * @tparam DigestBits
         */

        template<std::size_t DigestBits>
        class static_digest : public std::array<octet_type, DigestBits / octet_bits> { };

        namespace detail {
            template<std::size_t DigestBits, typename OutputIterator>
            OutputIterator to_ascii(const static_digest<DigestBits> &d, OutputIterator it) {
                for (std::size_t j = 0; j < DigestBits / octet_bits; ++j) {
                    octet_type b = d[j];
                    *it++ = "0123456789abcdef"[(b >> 4) & 0xF];
                    *it++ = "0123456789abcdef"[(b >> 0) & 0xF];
                }
                return it;
            }

            template<std::size_t DigestBits>
            std::array<char, DigestBits / 4 + 1> c_str(const static_digest<DigestBits> &d) {
                std::array<char, DigestBits / 4 + 1> s;
                char *p = to_ascii<DigestBits>(d, s.data());
                *p++ = '\0';
                return s;
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

namespace std {
    template<std::size_t DigestBits>
    std::string to_string(const nil::crypto3::static_digest<DigestBits> &d) {
        std::array<char, DigestBits / 4 + 1> cstr = nil::crypto3::detail::c_str(d);
        return std::string(cstr.data(), cstr.size() - 1);
    }
}    // namespace std

namespace nil {
    namespace crypto3 {

        /*!
         *
         * @tparam NewBits
         * @tparam OldBits
         * @param od
         * @return Digest containing the first min(NewBits, OldBits) bits of the argument digest followed by max
         * (0, NewBits - OldBits) bits.
         */
        template<std::size_t NewBits, std::size_t OldBits>
        static_digest<NewBits> resize(const static_digest<OldBits> &od) {
            static_digest<NewBits> nd;
            nd.fill(0);
            std::size_t bytes = sizeof(octet_type) * (NewBits < OldBits ? NewBits : OldBits) / octet_bits;
            std::memcpy(nd.data(), od.data(), bytes);
            return nd;
        }

        /*!
         * @tparam NewBits
         * @tparam OldBits
         * @return Digest containing only the first NewBits bits of the argument digest.
         *
         * Requires that NewBits <= OldBits.
         *
         * Truncating a message digest generally does not weaken the hash algorithm beyond the
         * amount necessitated by the shorted output size.
         */
        template<std::size_t NewBits, std::size_t OldBits>
        static_digest<NewBits> truncate(const static_digest<OldBits> &od) {
            BOOST_STATIC_ASSERT(NewBits <= OldBits);
            return resize<NewBits>(od);
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator==(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            // TODO: Think about size of static_digest. We can't use resize here because
            //  it's change element which we compare
            return static_cast<bool>(DB1 == DB2 ? std::equal(std::begin(a), std::end(a), std::begin(b), std::end(b)) :
                                                  0);
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator!=(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            return !(a == b);
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator<(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            // #TODO: Implement this right
            return DB1 < DB2;
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator>(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            return b < a;
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator<=(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            return !(b < a);
        }

        template<std::size_t DB1, std::size_t DB2>
        bool operator>=(const static_digest<DB1> &a, const static_digest<DB2> &b) {
            return !(b > a);
        }

        template<std::size_t DB>
        bool operator!=(const static_digest<DB> &a, char const *b) {
            BOOST_ASSERT(std::strlen(b) == DB / 4);
            return std::to_string(a) != b;
        }

        template<std::size_t DB>
        bool operator==(const static_digest<DB> &a, char const *b) {
            return !(a != b);
        }

        template<std::size_t DB>
        bool operator!=(char const *b, const static_digest<DB> &a) {
            return a != b;
        }

        template<std::size_t DB>
        bool operator==(char const *b, const static_digest<DB> &a) {
            return a == b;
        }

        template<std::size_t DigestBits>
        std::ostream &operator<<(std::ostream &sink, const static_digest<DigestBits> &d) {
            detail::to_ascii<DigestBits>(d, std::ostream_iterator<char>(sink));
            return sink;
        }

        template<std::size_t DigestBits>
        std::istream &operator>>(std::istream &source, static_digest<DigestBits> &d) {
            std::array<char, DigestBits / 4> a = {{}};
            for (unsigned i = 0; i < a.size(); ++i) {
                char c;
                if (!source.get(c)) {
                    source.setstate(std::ios::failbit);
                    break;
                }
                if (!std::isxdigit(c, source.getloc())) {
                    source.unget();
                    source.setstate(std::ios::failbit);
                    break;
                }

                if (std::isdigit(c, source.getloc())) {
                    a[i] = (c - '0');
                } else {
                    a[i] = std::toupper(c, source.getloc()) - 'A' + 0xA;
                }
            }
            detail::pack<stream_endian::big_bit, stream_endian::big_bit, 4, 8>(a.begin(), a.end(), d.begin());
            return source;
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DIGEST_HPP
