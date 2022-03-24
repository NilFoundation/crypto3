//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_TEST_MODULE pickles_struct_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(pickles_proof_struct_test_suite)

BOOST_AUTO_TEST_CASE(pickles_proof_struct_test_suite) {
    nil::crypto3::zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta::g1_type<>> proof;
    // w_comm
    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x29C11510848CF79EA9D58C2E7B2F9EABDE5470AB0C7D8051DB68B6A597844291_cppui256,
        0x29A084D99207EE0ADE9471C2101682E8DB5E470231B1FEB7CDEC1A515447E762_cppui256};
    proof.commitments.w_comm[0].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x2347E650C19A43EA430EB8EF103F42A98B8BBAB41693BA604E762015C90F6B15_cppui256,
        0x2D5E94480F83FBE47282CBD39A46022B90842A442FBA79002AE6811BAE48ADD7_cppui256};
    proof.commitments.w_comm[1].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x3A38CC8840CBC1C0E9CB2BE5AEA65569391B35932C4F632208FFB76683FD559D_cppui256,
        0x0F6124FC989DFAAACD41531AB7A75E9F68150C1EC659338FF4E2340DC46591DA_cppui256};
    proof.commitments.w_comm[2].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x1E86CC275E88EE0EE3384B5D6641A9A6D4E3CF08DCE181D7FF9E2934B6406086_cppui256,
        0x06CF0E315DC60DF5551A872E6C6531706506DB19A6425E1A4803BBDD1074A0C4_cppui256};
    proof.commitments.w_comm[3].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x0F695898DA469CF121E1E704B4B717AA6BC12EFCEF4F1418B42FE7A5437082B6_cppui256,
        0x3BA7967BE5E834EAD6C4B2D8B7FC9533B1B830DDDCA7305B4EF1F7D1CE6F0EE8_cppui256};
    proof.commitments.w_comm[4].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x1F15E1FAA6E5A22F3B2DA293E52386FE81792BC7D956F797BEDFB11CD3A1A3D4_cppui256,
        0x184919D8F8AE9E1A81CDF386C65454296917E5A26B5FB0040137AF77D4D6AE14_cppui256};
    proof.commitments.w_comm[5].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x29844A1A0AA89F411287AD425C3B4B84E1A78F04F888056E4C986242E0289EBB_cppui256,
        0x08A4673C07F4E5F5EEAF76708589B110EAF49B76FB37EDAC5BDE5C29433B9188_cppui256};
    proof.commitments.w_comm[6].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x364ECE69E21835EAE10B1AA9CCBD74305E29C369ED250C0EE49CCD8F24795D03_cppui256,
        0x1C5A4242982EB6E6D1BA1D5E118C46D758DC2AB6AC3E1ECBFD136B1BF5C7270E_cppui256};
    proof.commitments.w_comm[7].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x38934EBFC2667F0925DDBF006FBC361FE152FD2CDA59D8E2D9F3CBEDD9F6DC42_cppui256,
        0x0583B9CA4362B661B2A4E78D811690B752564B5B60BB4C7F710D16BD098E5481_cppui256};
    proof.commitments.w_comm[8].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x3232CC46F6A60E0217926D058728DE33D8331CF44E9D589E8AAFFFEBB2FACDED_cppui256,
        0x1DA9F1A0E3F493F5D873469CCD4A860A8564A3776EFC4C00E80916B5A6663CD7_cppui256};
    proof.commitments.w_comm[9].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x2F96277B56B8779865BB9CB646D9F2F45EAFFDD32F146B957354922B76944F61_cppui256,
        0x2F49E80702D36688FF505B4E2CD848D461EEDCD7B6DE610A72392E05AE889010_cppui256};
    proof.commitments.w_comm[10].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x09F20586641CC98E68CF252A59480CE50A8C6C6AECE986A676221CD1E8613BC3_cppui256,
        0x2DCC43E7FE9F1CBE4C2FAF0969D7A788C3636FF65466A2A8E8CAD429CB47BA28_cppui256};
    proof.commitments.w_comm[11].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x25147529907262C1F67F1C8C62B3136C9FF495727F59A5E534A3E257E9A06DE3_cppui256,
        0x30B8453232FF14019691D8A749BD88D0E2FD1D39FE9A66A01165E71EDBA46411_cppui256};
    proof.commitments.w_comm[12].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x35B38418B473A631CC399723113765268A1F953D8ED9D41D5DD615026E636421_cppui256,
        0x2BEEDE237F3D3ED3942323AA402318C8866BE8DFA31FE9506580846C284DB4D2_cppui256};
    proof.commitments.w_comm[13].shifted = {0x0, 0x0};

    proof.commitments.w_comm[0].proof.commitments.w_comm[0].shifted = {
        0x3FFD762B06C4DFB4FD8FED560C84F9E9DE699620B6FB4D0ED3089042FE8127E9_cppui256,
        0x2A7B651BE02C61AF87651107F8F43BE53DD2541CDDBD17BA7B316C939109598E_cppui256};
    proof.commitments.w_comm[14].shifted = {0x0, 0x0};
}

BOOST_AUTO_TEST_SUITE_END()