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

#ifndef CRYPTO3_DIGEST_HPP
#define CRYPTO3_DIGEST_HPP

#include <iostream>

#include <boost/static_assert.hpp>
#include <boost/assert.hpp>

#include <boost/container/small_vector.hpp>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/octet.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * The digest class template stores a DigestBits-bit message digest as a sequence of 8-bit octets.
         * Octets are stored in the smallest unsigned type able to hold 8 bits, hereinafter referred to as
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
        using digest = boost::container::small_vector<octet_type, DigestBits / octet_bits>;

        namespace detail {
            template<std::size_t DigestBits, typename OutputIterator>
            OutputIterator to_ascii(const boost::container::small_vector<octet_type, DigestBits / octet_bits> &d,
                                    OutputIterator it) {
                for (std::size_t j = 0; j < d.size(); ++j) {
                    octet_type b = d[j];
                    *it++ = "0123456789abcdef"[(b >> 4) & 0xF];
                    *it++ = "0123456789abcdef"[(b >> 0) & 0xF];
                }
                return it;
            }

            template<std::size_t DigestBits>
            digest<DigestBits / 4 + 1>
                c_str(const boost::container::small_vector<octet_type, DigestBits / octet_bits> &d) {
                digest<DigestBits / 4 + 1> s;
                to_ascii<DigestBits>(d, std::back_inserter(s));
                s.push_back('\0');
                return s;
            }
        }    // namespace detail


        /*!
         *
         * @tparam NewBits
         * @tparam OldBits
         * @param od
         * @return Digest containing the first min(NewBits, OldBits) bits of the argument digest followed by max
         * (0, NewBits - OldBits) bits.
         */
        template<unsigned NewBits, unsigned OldBits>
        digest<NewBits> reserve(const boost::container::small_vector<octet_type, OldBits / octet_bits> &od) {
            digest<NewBits> nd;
            unsigned bytes = sizeof(octet_type) * (NewBits < OldBits ? NewBits : OldBits) / octet_bits;
            std::memcpy(nd.data(), od.data(), bytes);
            return nd;
        }

        /*!
         *
         * @tparam DigestBits
         * @param od
         * @param new_size
         * @return Digest containing the first min(od.size(), new_size) octets of the argument digest followed by max
         * (0, new_size - od.size()) zero octets.
         */
        template<std::size_t DigestBits>
        digest<DigestBits> resize(const digest<DigestBits> &od, std::size_t new_size) {
            
            std::size_t old_size = od.size();

            if (new_size == old_size)
                return od;

            digest<DigestBits> nd(new_size, octet_type());
            std::size_t bytes = sizeof(octet_type) * (old_size < new_size ? old_size : new_size);
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
        template<unsigned NewBits, unsigned OldBits>
        digest<NewBits> truncate(const boost::container::small_vector<octet_type, OldBits / octet_bits> &od) {
            BOOST_STATIC_ASSERT(NewBits <= OldBits);
            return resize<NewBits>(od);
        }

        template<unsigned DB1, unsigned DB2>
        bool operator==(const digest<DB1> &a, const digest<DB2> &b) {
            unsigned const DB = DB1 < DB2 ? DB2 : DB1;
            return resize<DB>(a).base_array() == resize<DB>(b).base_array();
        }

        template<unsigned DB1, unsigned DB2>
        bool operator!=(const digest<DB1> &a, const digest<DB2> &b) {
            return !(a == b);
        }

        template<unsigned DB1, unsigned DB2>
        bool operator<(const digest<DB1> &a, const digest<DB2> &b) {
            unsigned const DB = DB1 < DB2 ? DB2 : DB1;
            return resize<DB>(a).base_array() < resize<DB>(b).base_array();
        }

        template<unsigned DB1, unsigned DB2>
        bool operator>(const digest<DB1> &a, const digest<DB2> &b) {
            return b < a;
        }

        template<unsigned DB1, unsigned DB2>
        bool operator<=(const digest<DB1> &a, const digest<DB2> &b) {
            return !(b < a);
        }

        template<unsigned DB1, unsigned DB2>
        bool operator>=(const digest<DB1> &a, const digest<DB2> &b) {
            return !(b > a);
        }

        template<unsigned DB>
        bool operator!=(digest<DB> const &a, char const *b) {
            BOOST_ASSERT(std::strlen(b) == DB / 4);
            return static_cast<bool>(std::strcmp(a.cstring().data(), b));
        }

        template<unsigned DB>
        bool operator==(digest<DB> const &a, char const *b) {
            return !(a != b);
        }

        template<unsigned DB>
        bool operator!=(char const *b, digest<DB> const &a) {
            return a != b;
        }

        template<unsigned DB>
        bool operator==(char const *b, digest<DB> const &a) {
            return a == b;
        }

        template<unsigned DB>
        std::ostream &operator<<(std::ostream &sink, digest<DB> const &d) {
            d.to_ascii(std::ostream_iterator<char>(sink));
            return sink;
        }

        template<unsigned DB>
        std::istream &operator>>(std::istream &source, digest<DB> &d) {
            std::array<char, DB / 4> a = {{}};
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

namespace std {
    template<std::size_t DigestBits>
    std::string to_string(const nil::crypto3::digest<DigestBits> &d) {
        nil::crypto3::digest<DigestBits / 4 + 1> cstr = nil::crypto3::detail::c_str(d);
        return std::string(cstr.begin(), cstr.begin() + cstr.size() - 1);
    }
}    // namespace std

#endif    // CRYPTO3_DIGEST_HPP
