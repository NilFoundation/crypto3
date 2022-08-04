///////////////////////////////////////////////////////////////
//  Copyright 2013 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_MP_CPP_INT_VP_HPP
#define BOOST_MP_CPP_INT_VP_HPP

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            namespace literals {
                namespace detail {

#ifndef TVM
                    using limb_pack_type = limb_type;
#else
                    using limb_pack_type = unsigned int;
#endif

                    template<limb_pack_type... VALUES>
                    struct value_pack {
                        constexpr value_pack() {
                        }

                        using next_type = value_pack<0, VALUES...>;
                    };
                    template<class T>
                    struct is_value_pack {
                        static constexpr bool value = false;
                    };
                    template<limb_type... VALUES>
                    struct is_value_pack<value_pack<VALUES...>> {
                        static constexpr bool value = true;
                    };

                    struct negate_tag { };

                    constexpr negate_tag make_negate_tag() {
                        return negate_tag();
                    }
                }    // namespace detail
            }        // namespace literals
        }            // namespace multiprecision
    }                // namespace crypto3
}    // namespace nil

#endif    // BOOST_MP_CPP_INT_CORE_HPP
