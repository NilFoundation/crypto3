//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_keccak_test

#include <array>
#include <cstdlib>
#include <ctime>
#include <random>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

// #include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
// #include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_round.hpp>

#include "../../test_plonk_component.hpp"

const int r[5][5] = {{0, 36, 3, 41, 18},
                    {1, 44, 10, 45, 2},
                    {62, 6, 43, 15, 61},
                    {28, 55, 25, 21, 56},
                    {27, 20, 39, 8, 14}};

template<typename BlueprintFieldType>
typename BlueprintFieldType::value_type to_sparse(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.data);
    integral_type result_integral = 0;
    integral_type power = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 1;
        power = power << 3;
    }
    return value_type(result_integral);
}
template<typename BlueprintFieldType, bool xor_with_mes, bool last_round_call>
std::array<typename BlueprintFieldType::value_type, 25> sparse_round_function(std::array<typename BlueprintFieldType::value_type, 25> inner_state,
                                                            std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
                                                            typename BlueprintFieldType::value_type RC) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::array<std::array<integral_type, 5>, 5> inner_state_integral;
    std::array<integral_type, 17> padded_message_chunk_integral;
    integral_type RC_integral = integral_type(RC.data);
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] = integral_type(inner_state[x + 5 * y].data);
        }
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk_integral[i] = integral_type(padded_message_chunk[i].data);
    }

    auto rot = [](integral_type x, const int s) {
        return ((x << (3 * s)) | (x >> (192 - 3 * s))) & ((integral_type(1) << 192) - 1);
    };

    if (xor_with_mes) {
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                if (last_round_call && (x + 5 * y == 16)) {
                    continue;
                }
                if (x + 5 * y < 17) {
                    inner_state_integral[x][y] = inner_state_integral[x][y] ^ padded_message_chunk_integral[x + 5 * y];
                }
            }
        }
        if (last_round_call) {
            value_type last_round_const = to_sparse<BlueprintFieldType>(value_type(0x8000000000000000));
            integral_type last_round_const_integral = integral_type(last_round_const.data);
            inner_state_integral[1][3] = inner_state_integral[1][3] ^ padded_message_chunk_integral[16] ^ last_round_const_integral;
        }
    }

    // theta
    std::array<integral_type, 5> C;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            C[x] ^= inner_state_integral[x][y];
        }
    }
    std::array<integral_type, 5> D;
    for (int x = 0; x < 5; ++x) {
        D[x] = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
    }
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] ^= D[x];
        }
    }

    // rho and pi
    std::array<std::array<integral_type, 5>, 5> B;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            B[y][(2 * x + 3 * y) % 5] = rot(inner_state_integral[x][y], r[x][y]);
        }
    }

    // chi
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state_integral[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
        }
    }

    // iota
    inner_state_integral[0][0] = inner_state_integral[0][0] ^ RC_integral;
    for (int x = 0; x < 5; ++x) {
        for (int y = 0; y < 5; ++y) {
            inner_state[x + 5 * y] = value_type(inner_state_integral[x][y]);
        }
    }
    return inner_state;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount,
         bool xor_with_mes, bool last_round_call, std::size_t last_perm_col = 7>
auto test_keccak_round_inner(std::array<typename BlueprintFieldType::value_type, 25> inner_state,
                             std::array<typename BlueprintFieldType::value_type, 17> padded_message_chunk,
                             typename BlueprintFieldType::value_type RC,
                             std::array<typename BlueprintFieldType::value_type, 25> expected_result) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 30;
    constexpr std::size_t SelectorColumns = 50;
    nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::blueprint::components::keccak_round<ArithmetizationType>;
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (int i = 0; i < 25; ++i) {
        public_input.push_back(inner_state[i]);
    }
    for (int i = 0; i < 17; ++i) {
        public_input.push_back(padded_message_chunk[i]);
    }
    public_input.push_back(RC);

    std::array<var, 25> inner_state_vars;
    std::array<var, 17> padded_message_chunk_vars;
    var RC_var;
    for (int i = 0; i < 25; ++i) {
        inner_state_vars[i] = var(0, i, false, var::column_type::public_input);
    }
    for (int i = 0; i < 17; ++i) {
        padded_message_chunk_vars[i] = var(0, i + 25, false, var::column_type::public_input);
    }
    RC_var = var(0, 42, false, var::column_type::public_input);
    typename component_type::input_type instance_input = {inner_state_vars, padded_message_chunk_vars, RC_var};

    auto result_check = [expected_result]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        for (int i = 0; i < 25; ++i) {
            // std::cout << expected_result[i] << ' ' << var_value(assignment, real_res.inner_state[i]) << std::endl;
            assert(expected_result[i] == var_value(assignment, real_res.inner_state[i]));
        }
    };

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }
    std::array<std::uint32_t, WitnessesAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessesAmount; i++) {
        witnesses[i] = i;
    }
    component_type component_instance =
        component_type(witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0},
                        xor_with_mes, last_round_call, last_perm_col);

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        boost::get<component_type>(component_instance), desc, public_input, result_check, instance_input,
                                xor_with_mes ? nil::blueprint::connectedness_check_type::type::STRONG :  nil::blueprint::connectedness_check_type::type::NONE,
                                xor_with_mes, last_round_call, last_perm_col);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount>
void test_keccak_round_not_random() {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wimplicitly-unsigned-literal"

    using value_type = typename BlueprintFieldType::value_type;
    std::array<value_type, 17> padded_message_chunk = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    //call 1
    std::array<value_type, 25> inner_state = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    value_type RC = to_sparse<BlueprintFieldType>(value_type(1));
    std::array<value_type, 25> expected_result = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    //call 2
    inner_state = expected_result;
    RC = to_sparse<BlueprintFieldType>(value_type(0x8082));
    expected_result = {32899, 17592186044416, 32768, 1, 17592186077184, 0, 35184374185984, 0, 35184372088832, 2097152,
                        2, 512, 0, 514, 0, 268436480, 0, 1024, 268435456, 0, 1099511627776, 0, 1099511627780, 0, 4};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    //call 3
    inner_state = expected_result;
    RC = to_sparse<BlueprintFieldType>(value_type(0x800000000000808a));
    expected_result = {9236970796698600460, 4092250545529553158, 626057523912327425, 2306538108895626371, 1173341635645358336,
                        1293304092434976, 1266393375296193026, 4612686711565066480, 3572814934320349200, 6918386853474468034,
                        181437471070544, 17451689225912448, 14123431978033217603, 9612137362626578, 14131171423402623105,
                        109225863298950544, 4469910934709993472, 291608492588557700, 4143342752895270928, 722898250671538564,
                        9260980282462904729, 14339470011802853602, 37581858268459548, 4683770000893804961, 432358761588732518};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    //call 4
    inner_state = expected_result;
    RC = to_sparse<BlueprintFieldType>(value_type(0x8000000080008000));
    expected_result = {592319258926211651, 14940587067404002452, 6163873250186209783, 9133172271835791495, 13983250434949586883,
                        10037245043040796116, 14625807227073111006, 9517639169617348992, 10802803781493464979, 1170967630360556906,
                        4833658608200494670, 14411270558251773425, 10413092914151648788, 6324505867985343017, 15456637871614865798,
                        15961727220218474669, 12219779720573097889, 13453918774002596887, 11249665490274026413, 16763947842887530834,
                        9348458261315236693, 11269932799224724130, 5725669273397430228, 16793563075160212879, 7296601056617420707};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    //call 5
    inner_state = expected_result;
    RC = to_sparse<BlueprintFieldType>(value_type(0x808b));
    expected_result = {7638250137956199023, 17990125325728205105, 7906499215270811140, 10861036725959346835, 11195520138696188958,
                        8358174899797462070, 8135952663530915624, 1143978644753002443, 15662404937588594201, 16535557756827863490,
                        2821756897662528488, 12114361851460063201, 8845673958919045506, 13942698502943567537, 11656387723772272466,
                        13322614738909770079, 2086432298574777049, 17543636310180418713, 1178364895537752846, 10832164025006223835,
                        2030143342952750111, 12360607886846421348, 10479039689777663018, 16563260862735374768, 7279885679800479721};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    //call 6
    inner_state = expected_result;
    RC = to_sparse<BlueprintFieldType>(value_type(0x80000001));
    expected_result = {4891766363406797400, 15439122233753343804, 13823342620960621853, 11746433691194652646, 4017314498112237324,
                        815207819430446539, 4967747420293129338, 3818588911347179217, 12982395987346120149, 8831006501622048216,
                        3273200702990303769, 11925911941096385939, 11818410238024184151, 6855937196075990472, 6813782227838587502,
                        5749709705375199086, 198532287281302992, 3986921420170929948, 2084732521627207926, 3955984847012879536,
                        17540298648724239738, 14973796877054370773, 9207394463793105740, 13336242423054526618, 2223831538796077986};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    // call 12
    inner_state = {8317352591327817587, 3347101423491892088, 13812284588227636790, 6672945709382097013, 14828349229463845968,
                17723229868831098326, 17401130588186959855, 16478565068789518457, 6492452647977334912, 11881899180789479218,
                16234817029224417455, 15219752985751753243, 7353976000907867650, 14188031598247865105, 15212311666827251122,
                11629652489896499652, 9435989968869629838, 3918343313233240239, 7628695717460153542, 12309003921403265649,
                345338872853187944, 12040357248728011954, 3576113714317971609, 6768822272106030756, 5816751084285246094};
    for (int i = 0; i < 25; ++i) {
        inner_state[i] = to_sparse<BlueprintFieldType>(inner_state[i]);
    }
    RC = to_sparse<BlueprintFieldType>(value_type(0x8000000a));
    expected_result = {4650443609753860646, 9514407034135748299, 1325603491995511509, 5593257647634540243, 4316689694591141959,
                        7056436588513633967, 3922974518795920519, 9361284003398536963, 12348570714043139801, 9410505497913992340,
                        3614675582850630850, 6265106893083717952, 15812212848177019826, 5971330993120196744, 10998285978683370913,
                        11166777828240479175, 7385351289822635840, 13873470266315090419, 6746683412968993695, 16204117485081817578,
                        8627448812002334210, 5809981248579074143, 17919282347891220598, 3921880343594863541, 4864618403575458388};
    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);

    // call 24
    inner_state = {1021834983209491063, 271587765569717919, 4776059245685303294, 6929972956618907976, 15632760037079799599,
                    335373011243745427, 4458191160998101431, 1054086133152375554, 2747216341432570284, 16716089959809353091,
                    18427037088977732910, 8502882582543089190, 15262916258997799331, 1649067881221390653, 16305756012321036251,
                    6396788823285448910, 16280709970257755463, 968684198036765735, 17453107891981340679, 14208300252181521039,
                    8344225276973693085, 15466940913106191879, 9691424745450112199, 11326521537916162858, 14617465633943149704};
    for (int i = 0; i < 25; ++i) {
        inner_state[i] = to_sparse<BlueprintFieldType>(inner_state[i]);
    }
    RC = to_sparse<BlueprintFieldType>(value_type(0x8000000080008008));
    expected_result = {17376452488221285863, 9571781953733019530, 15391093639620504046, 13624874521033984333, 10027350355371872343,
                        18417369716475457492, 10448040663659726788, 10113917136857017974, 12479658147685402012, 3500241080921619556,
                        16959053435453822517, 12224711289652453635, 9342009439668884831, 4879704952849025062, 140226327413610143,
                        424854978622500449, 7259519967065370866, 7004910057750291985, 13293599522548616907, 10105770293752443592,
                        10668034807192757780, 1747952066141424100, 1654286879329379778, 8500057116360352059, 16929593379567477321};

    #pragma clang diagnostic pop

    for (int i = 0; i < 25; ++i) {
        expected_result[i] = to_sparse<BlueprintFieldType>(expected_result[i]);
    }
    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, false, false>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount,
         bool xor_with_mes, bool last_round_call, std::size_t last_perm_col = 7>
void test_keccak_round_random() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::array<value_type, 25> inner_state;
    std::array<value_type, 17> padded_message_chunk;
    value_type RC;
    integral_type mask = (integral_type(1) << 64) - 1;

    for (int i = 0; i < 25; ++i) {
        auto random_value = integral_type(dis(gen)) & mask;
        inner_state[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    for (int i = 0; i < 17; ++i) {
        auto random_value = integral_type(dis(gen)) & mask;
        padded_message_chunk[i] = to_sparse<BlueprintFieldType>(value_type(random_value));
    }
    auto random_value = integral_type(dis(gen)) & mask;
    RC = to_sparse<BlueprintFieldType>(value_type(random_value));

    auto expected_result = sparse_round_function<BlueprintFieldType, xor_with_mes, last_round_call>(inner_state, padded_message_chunk, RC);

    test_keccak_round_inner<BlueprintFieldType, WitnessesAmount, xor_with_mes, last_round_call, last_perm_col>
                            (inner_state, padded_message_chunk, RC, expected_result);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    test_keccak_round_not_random<field_type, 9>();
    test_keccak_round_random<field_type, 9, false, false>();
    test_keccak_round_random<field_type, 9, true, false>();
    test_keccak_round_random<field_type, 9, true, true>();
    test_keccak_round_random<field_type, 15, false, false>();
    test_keccak_round_random<field_type, 15, true, false>();
    test_keccak_round_random<field_type, 15, true, true>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_diff_perm_cols) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    test_keccak_round_not_random<field_type, 15>();
    test_keccak_round_random<field_type, 9, false, false, 5>();
    test_keccak_round_random<field_type, 9, true, false, 6>();
    test_keccak_round_random<field_type, 9, true, true, 7>();
    test_keccak_round_random<field_type, 15, false, false, 5>();
    test_keccak_round_random<field_type, 15, true, false, 6>();
    test_keccak_round_random<field_type, 15, true, true, 9>();
    test_keccak_round_random<field_type, 15, true, true, 7>();
}

BOOST_AUTO_TEST_SUITE_END()
