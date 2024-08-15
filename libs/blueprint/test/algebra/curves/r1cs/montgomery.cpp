//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_montgomery_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/blueprint/components/algebra/curves/montgomery/element_g1.hpp>

#include "test_utils.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

// TODO: extend tests
BOOST_AUTO_TEST_SUITE(blueprint_montgomery_operations_manual_test_suite)

BOOST_AUTO_TEST_CASE(babyjubjub_test) {
    using curve_type = curves::babyjubjub;
    using element_component =
        components::element_g1<curve_type, curves::forms::montgomery, curves::coordinates::affine>;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    group_value_type p1(integral_type("13229275355733428112095997489641024783055769870913646006080868652901570030764"),
                        integral_type("11134533164006840987080284949303064671639289755466531605577535852885854976142"));
    group_value_type p2(integral_type("7117928050407583618111176421555214756675765419608405867398403713213306743542"),
                        integral_type("14577268218881899420966779687690205425227431577728659819975198491127179315626"));
    group_value_type p1_plus_p2(
        integral_type("15566970094137508604402505312544881598484695740314362381445040160425553677096"),
        integral_type("6669854856059550313288855374895200898734184719090215367165264323940796559798"));

    check_affine_montgomery_g1_operations<curve_type>({p1, p2, p1_plus_p2});
    // TODO: there is a little cheat applied, twisted Edwards equivalent points had better calculate separately and
    //  hard-code into the test
    check_montgomery_to_twisted_edwards_component<curve_type>(
        {p1, p2, p1_plus_p2}, {p1.to_twisted_edwards(), p2.to_twisted_edwards(), p1_plus_p2.to_twisted_edwards()});
}

BOOST_AUTO_TEST_CASE(jubjub_test) {
    using curve_type = curves::jubjub;
    using element_component =
        components::element_g1<curve_type, curves::forms::montgomery, curves::coordinates::affine>;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    group_value_type p1(integral_type("5587996947380639047162049858166730204103969545442236298644831829013577070405"),
                        integral_type("3353220127577076936794824489270300729183005062496343538855887806046831862653"));
    group_value_type p2(integral_type("37380265172535953876205871964221324158436172047572074969815349807835370906304"),
                        integral_type("26055707688826178243212294438612447599848256944592175663688341250454494541524"));
    group_value_type p1_plus_p2(
        integral_type("31338886305606494662271397096913232944110804555543936006670599257012320678243"),
        integral_type("50113340805577397178918081218860537289046253010504685476128585225439863641470"));

    check_affine_montgomery_g1_operations<curve_type>({p1, p2, p1_plus_p2});
    // TODO: there is a little cheat applied, twisted Edwards equivalent points had better calculate separately and
    //  hard-code into the test
    check_montgomery_to_twisted_edwards_component<curve_type>(
        {p1, p2, p1_plus_p2}, {p1.to_twisted_edwards(), p2.to_twisted_edwards(), p1_plus_p2.to_twisted_edwards()});
}

BOOST_AUTO_TEST_SUITE_END()
