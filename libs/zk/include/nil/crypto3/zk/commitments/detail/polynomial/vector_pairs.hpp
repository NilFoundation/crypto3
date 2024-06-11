#ifndef CRYPTO3_ZK_VECTOR_PAIRS_HPP
#define CRYPTO3_ZK_VECTOR_PAIRS_HPP

#include<vector>
#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {

                    // Computes a random linear combination over v1/v2.
                    //
                    // Checking that many pairs of elements are exponentiated by
                    // the same `x` can be achieved (with high probability) with
                    // the following technique:
                    //
                    // Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
                    // (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
                    // random r1, r2, r3. Given (g, g^s)...
                    //
                    // e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
                    //
                    // ... with high probability.

                    template<typename FieldType, typename PointIterator>
                    std::pair<typename PointIterator::value_type, typename PointIterator::value_type>
                        merge_pairs(
                            const PointIterator &v1_begin,
                            const PointIterator &v1_end,
                            const PointIterator &v2_begin,
                            const PointIterator &v2_end) {
                        using scalar_field_type = FieldType;
                        using scalar_field_value_type = typename scalar_field_type::value_type;
                        BOOST_ASSERT(std::distance(v1_begin, v1_end) == std::distance(v2_begin, v2_end));

                        std::size_t size = std::distance(v1_begin, v1_end);
                        std::vector<scalar_field_value_type> r;
                        for(std::size_t i = 0; i < size; ++i) {
                            r.emplace_back(algebra::random_element<scalar_field_type>());
                        }

                        typename PointIterator::value_type res1 =
                            algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                v1_begin,
                                v1_end,
                                r.begin(),
                                r.end(),
                                1);

                        typename PointIterator::value_type res2 =
                                algebra::multiexp<algebra::policies::multiexp_method_BDLO12>(
                                    v2_begin,
                                    v2_end,
                                    r.begin(),
                                    r.end(),
                                    1);

                        return std::make_pair(res1, res2);
                    }

                    // Construct a single pair (s, s^x) for a vector of
                    // the form [1, x, x^2, x^3, ...].
                    template<typename FieldType, typename GroupValueType>
                    static std::pair<GroupValueType, GroupValueType> power_pairs(
                        const std::vector<GroupValueType> &v) {

                        return merge_pairs<FieldType>(v.begin(), v.end() - 1, v.begin() + 1, v.end());
                    }
                } // detail
            }   // commitments
        }   // zk
    }   // crypto3
}   // nil

#endif  // CRYPTO3_ZK_VECTOR_PAIRS_HPP
