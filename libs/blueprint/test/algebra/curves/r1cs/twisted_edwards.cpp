//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_twisted_edwards_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>

#include <nil/blueprint/components/algebra/curves/twisted_edwards/element_g1.hpp>

#include "test_utils.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

// TODO: extend tests
BOOST_AUTO_TEST_SUITE(blueprint_twisted_edwards_operations_manual_test_suite)

BOOST_AUTO_TEST_CASE(babyjubjub_test) {
    using curve_type = curves::babyjubjub;
    using element_component =
        components::element_g1<curve_type, curves::forms::twisted_edwards, curves::coordinates::affine>;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    group_value_type p1(integral_type("10031262171927540148667355526369034398030886437092045105752248699557385197826"),
                        integral_type("633281375905621697187330766174974863687049529291089048651929454608812697683"));
    group_value_type p2(integral_type("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
                        integral_type("16950150798460657717958625567821834550301663161624707787222815936182638968203"));
    group_value_type p1_plus_p2(
        integral_type("2763488322167937039616325905516046217694264098671987087929565332380420898366"),
        integral_type("15305195750036305661220525648961313310481046260814497672243197092298550508693"));
    check_affine_twisted_edwards_g1_operations<curve_type>({p1, p2, p1_plus_p2});

    // from ethsnark - test_jubjub_add.cpp
    p1 =
        group_value_type(integral_type("16838670147829712932420991684129000253378636928981731224589534936353716235035"),
                         integral_type("4937932098257800452675892262662102197939919307515526854605530277406221704113"));
    p2 =
        group_value_type(integral_type("1538898545681068144632304956674715144385644913102700797899565858629154026483"),
                         integral_type("2090866097726307108368399316617534306721374642464311386024657526409503477525"));
    p1_plus_p2 =
        group_value_type(integral_type("6973964026021872993461206321838264291006454903617648820964060641444266170799"),
                         integral_type("5058405786102109493822166715025707301516781386582502239931016782220981024527"));
    check_affine_twisted_edwards_g1_operations<curve_type>({p1, p2, p1_plus_p2});
}

BOOST_AUTO_TEST_CASE(jubjub_test) {
    using curve_type = curves::jubjub;
    using element_component =
        components::element_g1<curve_type, curves::forms::twisted_edwards, curves::coordinates::affine>;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    group_value_type p1(integral_type("29927994414980659866747158113976867771786823169860303107907009997724489194957"),
                        integral_type("462950763047385854792912911337076492277172577361226262929952084963852328241"));
    group_value_type p2(integral_type("8076246640662884909881801758704306714034609987455869804520522091855516602923"),
                        integral_type("13262374693698910701929044844600465831413122818447359594527400194675274060458"));
    group_value_type p1_plus_p2(
        integral_type("45763976842262823160295807685326507554022491488280968540559802656136203717715"),
        integral_type("28613822079681605882499475341323216283573790414551935851064205296797669937565"));
    check_affine_twisted_edwards_g1_operations<curve_type>({p1, p2, p1_plus_p2});
}

BOOST_AUTO_TEST_SUITE_END()
