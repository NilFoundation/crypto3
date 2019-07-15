#ifndef CRYPTO3_PUBKEY_DETAIL_STATE_ADDER_HPP
#define CRYPTO3_PUBKEY_DETAIL_STATE_ADDER_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {

                struct state_adder {
                    template<typename T>
                    void operator()(T &s1, T const &s2) {
                        typedef typename T::size_type size_type;
                        size_type n = (s2.size() < s1.size() ? s2.size() : s1.size());
                        for (typename T::size_type i = 0; i < n; ++i) {
                            s1[i] += s2[i];
                        }
                    }
                };

            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_DETAIL_STATE_ADDER_HPP
