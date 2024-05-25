// #define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE reinforced_concrete_test

#include <iostream>
#include <array>
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include "nil/crypto3/algebra/fields/bls12/scalar_field.hpp"
#include "nil/crypto3/algebra/fields/field.hpp"
#include "nil/crypto3/hash/reinforced_concrete.hpp"
// #include "nil/crypto3/algebra/fields/maxprime.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;


// namespace nil {
//     namespace crypto3 {
//         namespace hashes {
//             namespace detail {
//                 template <>
//                 struct reinforced_concrete_policy<nil::crypto3::algebra::fields::maxprime<64>> : 
//                     public base_reinforced_concrete_policy<nil::crypto3::algebra::fields::maxprime<64>> {
//                     constexpr static const std::size_t bucket_size = 7;
//                     typedef std::array<element_type, bucket_size> bucket_type;

//                     constexpr static const alphas_type alphas = {element_type(integral_type(1)), element_type(integral_type(3))};
//                     constexpr static const betas_type betas = {element_type(integral_type(2)), element_type(integral_type(4))};
//                     constexpr static const std::size_t d = 3;
//                     constexpr static const bucket_type bucket = {element_type(integral_type(570)), element_type(integral_type(577)), element_type(integral_type(549)), 
//                                                                 element_type(integral_type(579)), element_type(integral_type(553)), element_type(integral_type(577)), 
//                                                                 element_type(integral_type(553))};
//                     constexpr static const element_type p_min = element_type(integral_type(541));
//                 };
//             }
//         }
//     }
// }

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<typename FieldParams>
            struct print_log_value<typename fields::detail::element_fp<FieldParams>> {
                void operator()(std::ostream &os, typename fields::detail::element_fp<FieldParams> const &e) {
                    print_field_element(os, e);
                }
            };

            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream &, P<K, V> const &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

using rc_default_field_t = fields::bls12_fr<381>;
using rc_functions_t = hashes::detail::reinforced_concrete_functions<rc_default_field_t>;
using operators = rc_functions_t::reinforced_concrete_operators_type;
using element_type = rc_functions_t::element_type;
using integral_type = rc_functions_t::integral_type;
using state_type = rc_functions_t::state_type;

template <typename rc_functions>
void test_permute(std::array<std::pair<typename rc_functions::element_type, typename rc_functions::element_type>, 3>& test_set){
    using state_type = typename rc_functions::state_type;

    state_type in = {test_set[0].first, test_set[1].first, test_set[2].first};
    state_type out = {test_set[0].second, test_set[1].second, test_set[2].second};

    rc_functions::permute(in);
    BOOST_CHECK_EQUAL(in[0], out[0]);
    BOOST_CHECK_EQUAL(in[1], out[1]);
    BOOST_CHECK_EQUAL(in[2], out[2]);

}
BOOST_AUTO_TEST_CASE(check_inversity_of_compose_decompose_for_0){
    element_type zero = element_type(integral_type(0));
    operators::bucket_type after_decompose = operators::decompose(zero);
    element_type zero_after = operators::compose(after_decompose);
    BOOST_CHECK_EQUAL(zero, zero_after);
}

BOOST_AUTO_TEST_CASE(check_inversity_of_compose_decompose_for_1){
    element_type one = element_type(integral_type(1));
    operators::bucket_type after_decompose = operators::decompose(one);
    element_type one_after = operators::compose(after_decompose);
    BOOST_CHECK_EQUAL(one, one_after);
}

BOOST_AUTO_TEST_CASE(bricks_for_bls12fr381){
    operators::state_vector_type state = {{2, 2, 2}};

    operators::bricks(state);
    BOOST_CHECK_EQUAL(state[0], element_type(integral_type(32)));
    BOOST_CHECK_EQUAL(state[1], element_type(integral_type(16)));
    BOOST_CHECK_EQUAL(state[2], element_type(integral_type(28)));
}

BOOST_AUTO_TEST_CASE(permute){
    typedef std::array<std::pair<element_type, element_type>, 3> states_type;
    std::vector<states_type> test_sets;
    test_sets.emplace_back(states_type({
        std::pair<element_type, element_type>(element_type(integral_type("50917230419308163733470192369465914281470471790130294745848939712028772983060")), 
                                            element_type(integral_type("24739598089584454475621966183939257820166234533866965673492546376895264019128"))),

        std::pair<element_type, element_type>(element_type(integral_type("29642283130329487301988235868162751576403275281027830771209987540575428383637")), 
                                            element_type(integral_type("37521142756452916806081885515487491075534340094499376737812166523163578355714"))),

        std::pair<element_type, element_type>(element_type(integral_type("23663775015144813469379634606587938210554610024644297430818232620868959459552")), 
                                            element_type(integral_type("28549386537327608580836266150865810307117966330419940567643306094099488987233")))
                                           }));
                                            
    test_sets.emplace_back(states_type({
        std::pair<element_type, element_type>(element_type(integral_type("33510179140755347895375425370352023727694444228069440239293572206565074736884")), 
                                            element_type(integral_type("18174659052144177138751950570163950544332769998004183128651038977303979699219"))),

        std::pair<element_type, element_type>(element_type(integral_type("21603135348740703879430592411306870931346051097828213275497380996270715042141")), 
                                            element_type(integral_type("45812904386624376072737388526521613814601111711231627564052185515112943150536"))),

        std::pair<element_type, element_type>(element_type(integral_type("18632482287926004637041478199651776515736102069097516336082032841334185966107")), 
                                            element_type(integral_type("37231969806958808374977231216847168420099752393260010793385011955298357714262")))
                                           }));
                                            
    for(auto &test_set : test_sets)
        test_permute<rc_functions_t>(test_set);
}


// BOOST_AUTO_TEST_CASE(permute_in_FP64){
//     using rc_functions_t = hashes::detail::reinforced_concrete_functions<fields::maxprime<64>>;
//     using element_type = rc_functions_t::element_type;
//     using integral_type = rc_functions_t::integral_type;
//     using state_type = rc_functions_t::state_type;

//     // typedef std::array<std::pair<element_type, element_type>, 3> states_type;
//     // std::vector<states_type> test_sets;
//     // test_sets.emplace_back(states_type({
//     //     std::pair<element_type, element_type>(element_type(integral_type(0x00000000000000000000000000000000ull)), 
//     //                                         element_type(integral_type(0x000000000000000046c0b8fcb05a39ebull))),

//     //     std::pair<element_type, element_type>(element_type(integral_type(0x00000000000000000000000000000000ull)), 
//     //                                         element_type(integral_type(0x0000000000000000054581b45d897fcbull))),

//     //     std::pair<element_type, element_type>(element_type(integral_type(0x00000000000000000000000000000000ull)), 
//     //                                         element_type(integral_type(0x00000000000000009a68e1181bd6971dull)))
//     //                                        }));
                                            
//     // for(auto &test_set : test_sets)
//     //     test_permute<rc_functions_t>(test_set);
// }
