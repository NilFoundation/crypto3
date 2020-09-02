#ifndef ALGEBRA_DETAIL_TMP_HPP
#define ALGEBRA_DETAIL_TMP_HPP

namespace nil {
    namespace algebra {
        namespace detail {

            template <typename T, T... v> struct all_same_value {};

            template <typename T, T v1, T v2, T... rest>
            struct all_same_value<T, v1, v2, rest...> : all_same_value<T, v2, rest...> {
                static_assert(v1 == v2,
                            "All values in the template parameter list must be equal");
                static constexpr T value = v1;
            };

            template <typename T, T v> struct all_same_value<T, v> {
                static constexpr T value = v;
            };

        } // namespace detail
    } // namespace algebra
} // namespace nil

#endif // ALGEBRA_DETAIL_TMP_HPP
