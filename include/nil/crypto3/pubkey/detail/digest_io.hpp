#ifndef CRYPTO3_PUBKEY_DIGEST_IO_HPP
#define CRYPTO3_PUBKEY_DIGEST_IO_HPP

#include <nil/crypto3/pubkey/digest.hpp>
#include <nil/crypto3/pubkey/pack.hpp>

#include <istream>
#include <iterator>
#include <ostream>

#include <cctype>

namespace nil {
    namespace crypto3 {
        namespace pubkey {

            template<unsigned DB>
            std::ostream &operator<<(std::ostream &sink, digest <DB> const &d) {
                d.to_ascii(std::ostream_iterator<char>(sink));
                return sink;
            };

            template<unsigned DB>
            std::istream &operator>>(std::istream &source, digest <DB> &d) {
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
                pack<stream_endian::big_bit, 4, 8>(a, d);
                return source;
            };

        }
    }
} // namespace nil

#endif // CRYPTO3_PUBKEY_DIGEST_IO_HPP
