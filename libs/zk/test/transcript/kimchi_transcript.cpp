//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE zk_sponge_test

#include <vector>
#include <iostream>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/vesta/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/zk/transcript/kimchi_transcript.hpp>

using namespace nil::crypto3;
using curve_type = algebra::curves::vesta;
using group_type = typename curve_type::template g1_type<algebra::curves::coordinates::affine>;
using scalar_field_type = typename curve_type::scalar_field_type;
using value_type = typename scalar_field_type::value_type;
using base_field_type = typename curve_type::base_field_type;

using fq_sponge_type = zk::transcript::DefaultFqSponge<curve_type>;
using fr_sponge_type = zk::transcript::DefaultFrSponge<curve_type>;

BOOST_AUTO_TEST_SUITE(zk_sponge_test_suite)

    BOOST_AUTO_TEST_CASE(zk_sponge_test_0) {
        fq_sponge_type spng;
        group_type::value_type g[15];

        g[0] = group_type::value_type(
                0x1CF10D1482EB88632AEFED15C16082007B38DDC528626195CF6B040E2C7D5914_cppui_modular256,
                0x15A406A92FA16DB6E24D125C8EC5365D76DD8BB188106C0063BA9EC51E0FB8E7_cppui_modular256);
        g[1] = group_type::value_type(
                0x3B38AC47170B2DB158AE7C02E939B2877139040D240171F6A6BB01183902566E_cppui_modular256,
                0x05AAC7FD92471BBFF23D5E4F9AD0B64783467A4809940FEBB7BD6C91A9E9E1C0_cppui_modular256);
        g[2] = group_type::value_type(
                0x281BD2B891CF0795B1439B3AB149ED2A535B8E08C4430112D7D4BF53F3789BEF_cppui_modular256,
                0x10B2FA452CAC5D11CC8040D5DD504222A2621FC378EFD7D08A01BAB3A3DE28DF_cppui_modular256);
        g[3] = group_type::value_type(
                0x0158FEA0E6586A75F36FB621E9C9FC7A38970812F0F1753D3BB716655E3B9D79_cppui_modular256,
                0x2A9688F370DCC43130D38AB7AD2B3FF2A925791F587B55AD138B1F067E874C59_cppui_modular256);
        g[4] = group_type::value_type(
                0x0CA7898337AB528838EAD23D7CBCD4861F1E5E2E5D3B1BD3B733A832C7931547_cppui_modular256,
                0x351C82EC1D20E977ABFC632BBA2330AF61270A00BC2D32B6F2E1DA93AA0D51F1_cppui_modular256);
        g[5] = group_type::value_type(
                0x00DCE7DC20642A850002731F9B3820327CF5856B1D8C3B0EE6BD7BC03BC85FFD_cppui_modular256,
                0x3B1BCBA06B0D33F08123EDD6DF725CC1F8CD2213EA867FF4020C2D18619BB2DB_cppui_modular256);
        g[6] = group_type::value_type(
                0x0F7C2FF92D8F0776629F87BBF25702CEAA45B1893617F7C9AC10AACB080B6E10_cppui_modular256,
                0x16E7207D6596C7FAFF46FB335E14DC57E08E150AB7F692607F3B8DCC9E6CDA93_cppui_modular256);
        g[7] = group_type::value_type(
                0x2CD748E8C8806196ABE34DF032864491CADCF205AF70CB9152507BD16B912BEC_cppui_modular256,
                0x2219EC3C1873373A6717E7BFA24827AD89BF949B0F240D7B9D8981C2006E400F_cppui_modular256);
        g[8] = group_type::value_type(
                0x027E878BD478FC5DE36CA783CB60297C5F75CB638C71615A04714C52E9B15E8E_cppui_modular256,
                0x2CCE580022C7D44E72BA8E7E608C3733A3F3EDC0304566097C07D6CCA172A1B4_cppui_modular256);
        g[9] = group_type::value_type(
                0x0DC7C8FE3A9007F09283D29C5BE99AACEB9DA6996CD691BBAC5D075BDD6DA223_cppui_modular256,
                0x1FA4B95451090B8A36D503BFDBF086D4462745626B4BA4490AF42A7A6B5FD449_cppui_modular256);
        g[10] = group_type::value_type(
                0x20254A64C61A3C1882EC3E9FCA0ABAE814B0EB0477C3396E562C1006054347F3_cppui_modular256,
                0x23CDCBDE9DCBD33AD86BF48181B1616FC76D24A18711A3953D184E772D936418_cppui_modular256);
        g[11] = group_type::value_type(
                0x00DB22BCFC9A1D1A10A53716A7E7D4022DBF101B8767B68E78837CB8263BE097_cppui_modular256,
                0x3E283D2F0D90CAC87B3FCD95E7A8933FB2B2B43EF07FA577CA566527481AB6C9_cppui_modular256);
        g[12] = group_type::value_type(
                0x0D24814B6FE1C8C42FC05834B95212E473B76C8B9588D1272BFAE8FA0E2B9384_cppui_modular256,
                0x11C75275709440AC01B74C4E64E2606F7826294F868F6B0265008E758C148369_cppui_modular256);
        g[13] = group_type::value_type(
                0x007997CB753B919B586243FCAF6E5886676F180C2220BAC055AE9739CA4A1B4B_cppui_modular256,
                0x166859AE2ECE3520D33C2D146F6DBCFC819779C288E9D81C3F7369DF5642EF31_cppui_modular256);
        g[14] = group_type::value_type(
                0x04E774B3DE1A78D6C9408D7B10D9E4614FC8AE4DFE4BFE6762278EE72BB9E25D_cppui_modular256,
                0x178AC19F836752BAF356D9E9C3C35470F27A52C16B7572EEF2C61A43B4D0499B_cppui_modular256);

        for (int i = 0; i < 15; ++i) {
            std::vector<group_type::value_type> input({g[i]});
            spng.absorb_g(input);
        }

        auto check1 = spng.challenge();
        scalar_field_type::value_type chal1 = 0x0000000000000000000000000000000006906F18EE1C02C944C3186D54A8D03E_cppui_modular256;
        BOOST_CHECK(check1 == chal1);
    }

    BOOST_AUTO_TEST_CASE(zk_sponge_test_1) {
        fq_sponge_type spng;

        group_type::value_type g[15];
        g[0] = group_type::value_type(
                0x0A0C2BD5D6D122644F29A3AD675F1EB7BA01AE9D9EBC323086E3BDED095987D4_cppui_modular256,
                0x273211F773739D39B20CCD4D5EB77479115769B4742F2FB03A4F3ED1A1EC22D4_cppui_modular256);
        g[1] = group_type::value_type(
                0x220593B5A19D0A67847BBF80DB81F49D6CF8F9591B9E8C9A2F32670DDA1D8AC6_cppui_modular256,
                0x07211D7F83661CB78042848839E2DBD04B101F157A7DA31B30A3DB8886E9B7B0_cppui_modular256);
        g[2] = group_type::value_type(
                0x02D77AF331102A224026E24CA18EE6B7B0D5D7709527D066F1FE5FABE4CE85D1_cppui_modular256,
                0x0845660D92C66C0462CF57ADA39E558E0AD9ECC2359F0332901B1D2FE98A10D6_cppui_modular256);
        g[3] = group_type::value_type(
                0x0639954FFC6E0B2CCD1929139BE3105E15252BC2FA0A36024455525E659B7D88_cppui_modular256,
                0x15A3400CC3658E630DDBAA76288D06ADFC22DA21C84575D444D633F8DA6DC932_cppui_modular256);
        g[4] = group_type::value_type(
                0x2CB8A1CA2F4340039B7912FED931EF963E442CE9920FB0A3126E25BD83E598B6_cppui_modular256,
                0x37651EF464571CEF0E7F6DC731365AFDEF8216C6D253DD2BA93A2AFB676C04E2_cppui_modular256);
        g[5] = group_type::value_type(
                0x3A427D5DBECF18AB05809180B1F80E7509BCD963FBA6217E2E9A3292513F2049_cppui_modular256,
                0x1E66FA970D768A59A53D6349E03A4C8D7A93316D08572A133CDE18C2FE64AA03_cppui_modular256);
        g[6] = group_type::value_type(
                0x31525F1FEC6FB330DAB5CEFEC348E7221108CF82F543DA0A8E512F3A390AE5E1_cppui_modular256,
                0x1CFCABDD222DBFD199A208CFCF97FA22627E03B878AE4FD1284AF1CCDFE48384_cppui_modular256);
        g[7] = group_type::value_type(
                0x20BCF66A9DBB51680B5976759A9B9BABC07153E95978C3571B85DAE260326428_cppui_modular256,
                0x0FC9D105713B9FD6CC8587E84D1521BBF3737834FE5384AD76D98051619F7813_cppui_modular256);
        g[8] = group_type::value_type(
                0x31975A5C9BD269C5B7B115205B63A9F82C9E5FAFB789FC0E3A1D9F6D1698FCFF_cppui_modular256,
                0x2B3B885F8AB568D02E0DE2BCADDBD2D9B6EDE04AA3DEC5ABB8B53913F6EE0E35_cppui_modular256);
        g[9] = group_type::value_type(
                0x380C43392B70A7370D69266BFFC5D21825D80F34EB6DD165BF300618E0871AE7_cppui_modular256,
                0x267301AFABFE44E37DD209B0C38D662582F7CF13EE036BD77576767A70D07B88_cppui_modular256);
        g[10] = group_type::value_type(
                0x1458C0D03E1240A352ACDF0B8858993ACF8F4D4EC4091E695C69A1F5CE30D939_cppui_modular256,
                0x1EDB145A8D6C3EDF28A85B0B7CCD77792C06AD3B787394BD0D98B3B453CE634A_cppui_modular256);
        g[11] = group_type::value_type(
                0x20E6522DB98F94CD90E75B74AE0F038C245BD8FACDF94652B4220B139F9A8E36_cppui_modular256,
                0x133B8A97B147D68805619B1579DD49A6B898F713DC63EBCDBD311C1B99F4CED9_cppui_modular256);
        g[12] = group_type::value_type(
                0x00203F56944A4BA0454C150B4922711F88B429B8304DE1D7AFA3AF26BBAB84A5_cppui_modular256,
                0x1371005325482F9B36105AD5C548CB5B16B94B55876F22AE1B396744C76AA548_cppui_modular256);
        g[13] = group_type::value_type(
                0x27E71C246DEB9222E939D9994A010A063231BA76DAE041FB38C0DEF3E5A8E92D_cppui_modular256,
                0x17A6FF821B3E498999B1500CE2C3CDFB1B44691B990585B0522B6548BDDAAA83_cppui_modular256);
        g[14] = group_type::value_type(
                0x0E86C27EF127EFDF0374B82A92D675AF7A0A02EC8A8D0EF2F9BA888427E6CFAB_cppui_modular256,
                0x2A14FA11389648694F68426BDA965E8380C1B155B277467B0C96C5EC73CE17EB_cppui_modular256);

        for (int i = 0; i < 15; ++i) {
            std::vector<group_type::value_type> input({g[i]});
            spng.absorb_g(input);
        }

        typename scalar_field_type::value_type chal1(
                0x000000000000000000000000000000006586A4AF99E47C9EA8C7AD23A9E42247_cppui_modular256);
        BOOST_CHECK(spng.challenge() == chal1);
    }

    BOOST_AUTO_TEST_CASE(zk_sponge_test_2) {
        fq_sponge_type spng;

        group_type::value_type g[23];
        g[0] = group_type::value_type(
                0x27CCCDE41398B04DD09FAEEFB7B78767B51BB2AFC6587838D0F5A43C43A4A218_cppui_modular256,
                0x1728B31CFD99AD2D3DA948387D407DC6F61CD630758344996E05C21B89B4FF7E_cppui_modular256);
        g[1] = group_type::value_type(
                0x2AEF45CFCF1C7A3AB0437D11B00089226C1EAD9F65D17B02EBFBEEDD6ED8FFFB_cppui_modular256,
                0x354C1269DA294634A5E6E3C6D85F5068044BE97B9A41E47CFFD096AA3991D61F_cppui_modular256);
        g[2] = group_type::value_type(
                0x01B21F2FBE8FADFD3CF5ADA9332F17B86DE9AF278982CC4E1E5CEDBC6ADFB5C5_cppui_modular256,
                0x11FFAFCFDE4766A966DCB1083C422E8A863BB1871EA5657E79149504BDF4C3F7_cppui_modular256);
        g[3] = group_type::value_type(
                0x10B268CA02F1CCC0A9179B4DC8678E0E5E63B04D8149E8A85515B81529AD04F5_cppui_modular256,
                0x1DD587777C89876DFAF9135F7F58D4A1B37DE6F6B610043C231E23BEAAA84CF6_cppui_modular256);
        g[4] = group_type::value_type(
                0x13C0DC5466D51C6852266A549093DA4F59C1B06B278ABEBB85519F07D75972ED_cppui_modular256,
                0x109EA2EA135BC41544A6892C17E0F4202C6E8EA4E75E0202436104F1D2DD0AEC_cppui_modular256);
        g[5] = group_type::value_type(
                0x30F72723AC67E979D3956C3CDFE0662D0A515C3EA6D257F24BD292DB5E0450F4_cppui_modular256,
                0x1E021A1B6BF8A365E8251A51B430C39F3F1B9E08E3A13B5DCC641094EEA10A0E_cppui_modular256);
        g[6] = group_type::value_type(
                0x04F8423216ED528B6ACB493F9E122F8E88BB173037489185ADED577FB35DD4C8_cppui_modular256,
                0x0568CBE5D3AF7A1DC593E160088A1438B8570A87E1A40AFF548F19AB88246186_cppui_modular256);
        g[7] = group_type::value_type(
                0x3C276D9F50711A0FADC6C9215B7FE55772D8854ED88055B61D624D50A46BF2D1_cppui_modular256,
                0x064EC8440A5C9EE94D2E495DD697031A0FFAB03AD8AF8653B083B024EC2E0947_cppui_modular256);
        g[8] = group_type::value_type(
                0x37F0A0BFF99A231FBEB6FA8BF1BAC5D27D681D96A3BFE439526E8E36DC3F456B_cppui_modular256,
                0x05438AD52E7ED1CADD62053822F42888E4F4027A009541D26BBB8A3277747690_cppui_modular256);
        g[9] = group_type::value_type(
                0x21EF274FA84AD809DDE6858504CB06764F23349E9AD698AB06C7C88AB9938F10_cppui_modular256,
                0x22BB862C8B9C96A349540FF9127984EDEB425FA7727A86A33F0521A36F385567_cppui_modular256);
        g[10] = group_type::value_type(
                0x339487A2AE045A6CE9B13B548CAF8C9580B1216EC279026A9EA12E5685745822_cppui_modular256,
                0x019050F98DE9302849A3C7F024544DD6D73FC5A174D0A1D3D7FED3E8612C0BDF_cppui_modular256);
        g[11] = group_type::value_type(
                0x11FD07718FACABBFA2B0FDB6D559EECE04406643C11AE03228A6A55C0199B78F_cppui_modular256,
                0x1B3F5E6BDB2CFC18947322EB26A6A89E1CE0B3BCB79EE30245FCA702CE174390_cppui_modular256);
        g[12] = group_type::value_type(
                0x3393E80C17EB7DF85CA4FAD7F6043A084773ACD3B5ED712030E4B2000FF5086F_cppui_modular256,
                0x033B8C65937B8EE3B1DC600E4BA1FD9EBD851D29590C16379BEEFB93A6F6226E_cppui_modular256);
        g[13] = group_type::value_type(
                0x15E069E1CFD96C634513360C4BED63D8D22D32947BC156649D447BFA415D9D25_cppui_modular256,
                0x3F183AD1D896978D1AB0568AF4AA91CF413A2E011352B7692E17E5C0157619EF_cppui_modular256);
        g[14] = group_type::value_type(
                0x1D42ED837696F2A777E7C1FF0436D46E96878B624ECDE039732E37AFCD409C88_cppui_modular256,
                0x1DD9078FBA2CE4F2ECE3D8374E805A0494D5F6FF85B7B1A0F255F91C79F08929_cppui_modular256);
        g[15] = group_type::value_type(
                0x0A4020BF547A53FAF4DA99584BBAC1FD5D878D264A99BDF19710748597362B9B_cppui_modular256,
                0x179AFDC1C16BD21205B6B9E487799A032BE077512F18F1DD3215250F0C67FC64_cppui_modular256);
        g[16] = group_type::value_type(
                0x363AA1A805E5BAFF2DB4BDD817E60CCC546DE456367677C5ECD48CAC2675E21F_cppui_modular256,
                0x1638CDF842DB7274F494B0DC06D9CD0B2565666F7C9E4330A21412F216227FEC_cppui_modular256);
        g[17] = group_type::value_type(
                0x39A5B4737045A5192E159C13092B428E3AED966EE0A4DDA365F54AA14D17674E_cppui_modular256,
                0x052FBAB263CAC3E2B7C701B154F8F621A9BE5390D5795A3D7622C57536A30ACB_cppui_modular256);
        g[18] = group_type::value_type(
                0x3A90A56D28DC7E01F9384207FAE64E783C7A628048F155C8D14ECB1CD53C93A8_cppui_modular256,
                0x17A22DB9090348E8C363B687BF96EC25CCA79BA366F28F176097BF5474D8C32C_cppui_modular256);
        g[19] = group_type::value_type(
                0x02790E33CB485684C1D1CB250DBA08DE299C27F4CD340AC03720983FBF9441BE_cppui_modular256,
                0x30022C5A33C30487C1B375625E5317A351C2E5498C27B39FB0DF2DE8E95036FA_cppui_modular256);
        g[20] = group_type::value_type(
                0x1E98D2E550D673BF3B2CEEC098C5319494441382C9427F71557B82187A1F6E72_cppui_modular256,
                0x0D336D94B3CE0D0C30073BDE4C3044F458A598B6B50A1FD1944D29C9F681EB60_cppui_modular256);
        g[21] = group_type::value_type(
                0x0E826DABA538B6DFDFBC0133093600E5FB812F513D0FCC04106CB4BD3F32FAD3_cppui_modular256,
                0x282038D2B42F1EEF395753E663C6C62523F3C22857CFD6BCFF83B1B0F130B320_cppui_modular256);
        g[22] = group_type::value_type(
                0x0557F05F4FE835D81BF63FFA8E35B5C014E2A4828AC3E5AEE216F11F4662D8F3_cppui_modular256,
                0x22083FE3C84501B1C06B8BF9EDC10783523E080B10B41106555D3994B42DE333_cppui_modular256);

        for (int i = 0; i < 15; ++i) {
            std::vector<group_type::value_type> input({g[i]});
            spng.absorb_g(input);
        }

        typename scalar_field_type::value_type chal1(
                0x000000000000000000000000000000005D6E02ED382BBF4A9FF5C2C13A1F0E3D_cppui_modular256);
        BOOST_CHECK(spng.challenge() == chal1);
        typename scalar_field_type::value_type chal2(
                0x0000000000000000000000000000000058C638E4FE632BB34E9D712D10953688_cppui_modular256);
        BOOST_CHECK(spng.challenge() == chal2);

        std::vector<group_type::value_type> input({g[15]});
        spng.absorb_g(input);

        typename scalar_field_type::value_type chal3(
                0x0000000000000000000000000000000072D58D72518968134276BCBD15848A54_cppui_modular256);
        BOOST_CHECK(spng.challenge() == chal3);

        for (int i = 16; i < 23; ++i) {
            std::vector<group_type::value_type> input({g[i]});
            spng.absorb_g(input);
        }
        typename scalar_field_type::value_type chal4(
                0x00000000000000000000000000000000126C2E2D31FBDDB543E4FE174987EDBC_cppui_modular256);
        BOOST_CHECK(spng.challenge() == chal4);
    }

    BOOST_AUTO_TEST_CASE(zk_sponge_test_for_absorb_fr) {
        fq_sponge_type spng;
        //     fq_sponge_type2 spng2;
        scalar_field_type::value_type g[30] = {
                0x1CF10D1482EB88632AEFED15C16082007B38DDC528626195CF6B040E2C7D5914_cppui_modular256,
                0x15A406A92FA16DB6E24D125C8EC5365D76DD8BB188106C0063BA9EC51E0FB8E7_cppui_modular256,
                0x3B38AC47170B2DB158AE7C02E939B2877139040D240171F6A6BB01183902566E_cppui_modular256,
                0x05AAC7FD92471BBFF23D5E4F9AD0B64783467A4809940FEBB7BD6C91A9E9E1C0_cppui_modular256,
                0x281BD2B891CF0795B1439B3AB149ED2A535B8E08C4430112D7D4BF53F3789BEF_cppui_modular256,
                0x10B2FA452CAC5D11CC8040D5DD504222A2621FC378EFD7D08A01BAB3A3DE28DF_cppui_modular256,
                0x0158FEA0E6586A75F36FB621E9C9FC7A38970812F0F1753D3BB716655E3B9D79_cppui_modular256,
                0x2A9688F370DCC43130D38AB7AD2B3FF2A925791F587B55AD138B1F067E874C59_cppui_modular256,
                0x0CA7898337AB528838EAD23D7CBCD4861F1E5E2E5D3B1BD3B733A832C7931547_cppui_modular256,
                0x351C82EC1D20E977ABFC632BBA2330AF61270A00BC2D32B6F2E1DA93AA0D51F1_cppui_modular256,
                0x00DCE7DC20642A850002731F9B3820327CF5856B1D8C3B0EE6BD7BC03BC85FFD_cppui_modular256,
                0x3B1BCBA06B0D33F08123EDD6DF725CC1F8CD2213EA867FF4020C2D18619BB2DB_cppui_modular256,
                0x0F7C2FF92D8F0776629F87BBF25702CEAA45B1893617F7C9AC10AACB080B6E10_cppui_modular256,
                0x16E7207D6596C7FAFF46FB335E14DC57E08E150AB7F692607F3B8DCC9E6CDA93_cppui_modular256,
                0x2CD748E8C8806196ABE34DF032864491CADCF205AF70CB9152507BD16B912BEC_cppui_modular256,
                0x2219EC3C1873373A6717E7BFA24827AD89BF949B0F240D7B9D8981C2006E400F_cppui_modular256,
                0x027E878BD478FC5DE36CA783CB60297C5F75CB638C71615A04714C52E9B15E8E_cppui_modular256,
                0x2CCE580022C7D44E72BA8E7E608C3733A3F3EDC0304566097C07D6CCA172A1B4_cppui_modular256,
                0x0DC7C8FE3A9007F09283D29C5BE99AACEB9DA6996CD691BBAC5D075BDD6DA223_cppui_modular256,
                0x1FA4B95451090B8A36D503BFDBF086D4462745626B4BA4490AF42A7A6B5FD449_cppui_modular256,
                0x20254A64C61A3C1882EC3E9FCA0ABAE814B0EB0477C3396E562C1006054347F3_cppui_modular256,
                0x23CDCBDE9DCBD33AD86BF48181B1616FC76D24A18711A3953D184E772D936418_cppui_modular256,
                0x00DB22BCFC9A1D1A10A53716A7E7D4022DBF101B8767B68E78837CB8263BE097_cppui_modular256,
                0x3E283D2F0D90CAC87B3FCD95E7A8933FB2B2B43EF07FA577CA566527481AB6C9_cppui_modular256,
                0x0D24814B6FE1C8C42FC05834B95212E473B76C8B9588D1272BFAE8FA0E2B9384_cppui_modular256,
                0x11C75275709440AC01B74C4E64E2606F7826294F868F6B0265008E758C148369_cppui_modular256,
                0x007997CB753B919B586243FCAF6E5886676F180C2220BAC055AE9739CA4A1B4B_cppui_modular256,
                0x166859AE2ECE3520D33C2D146F6DBCFC819779C288E9D81C3F7369DF5642EF31_cppui_modular256,
                0x04E774B3DE1A78D6C9408D7B10D9E4614FC8AE4DFE4BFE6762278EE72BB9E25D_cppui_modular256,
                0x178AC19F836752BAF356D9E9C3C35470F27A52C16B7572EEF2C61A43B4D0499B_cppui_modular256};

        for (int i = 0; i < 30; ++i) {
            std::vector<scalar_field_type::value_type> input({g[i]});
            spng.absorb_fr(input);
        }

        auto check1 = spng.challenge();
        scalar_field_type::value_type chal1 = 0x0000000000000000000000000000000006906F18EE1C02C944C3186D54A8D03E_cppui_modular256;
        BOOST_CHECK(check1 == chal1);
    }

    BOOST_AUTO_TEST_CASE(zk_sponge_test_for_absorb_fr_2) {
        using namespace nil::crypto3;
        using curve_type = algebra::curves::pallas;
        using group_type = typename curve_type::template g1_type<>;
        using scalar_field_type = typename curve_type::scalar_field_type;
        using base_field_type = typename curve_type::base_field_type;

        using fq_sponge_type = zk::transcript::DefaultFqSponge<curve_type>;

        std::vector<scalar_field_type::value_type> input_values = {
                0x3AA52C0B2BC507CEC6CEEDBFD2C02B9C74CFA1043847011BA789D6F871201A52_cppui_modular256};
        fq_sponge_type spng;
        spng.absorb_fr(input_values);
        base_field_type::value_type real_value = spng.challenge_fq();

        algebra::fields::detail::element_fp<algebra::fields::params<algebra::fields::pallas_base_field>> real_inputs(
                0x1D52960595E283E7636776DFE96015CE3A67D0821C23808DD3C4EB7C38900D29_cppui_modular256);
        fq_sponge_type spng_real;
        spng_real.sponge.absorb(real_inputs);
        base_field_type::value_type expected_value = spng_real.challenge_fq();

        BOOST_CHECK(real_value == expected_value);
    }

    BOOST_AUTO_TEST_CASE(zk_sponge_test_real_case) {
        fq_sponge_type spng;
        spng.absorb_fr(value_type(0x1B76B0452DBEE0301162D6D04350DDC0361222FEF7467C285DB383D51E043D83_cppui_modular256));
        BOOST_CHECK(
                spng.challenge_fq() ==
                base_field_type::value_type(
                        0x23A5199486C064AC4CB9D8BBD59B20EB2A2B1A3CA77DFA6E9DAB7C387D270E23_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x1757CFBC6F79F5DA18CAD5BFE889D8BB11A04BEFD2F5F4ECA71CDF1541FD6A10_cppui_modular256,
                0x3440D97DA37051ACEA71310B6A9519E8989E86DE57D324745616A3BA065F2272_cppui_modular256));
        spng.absorb_g(group_type::value_type(
                0x2D47BB4464D0A3788F10C5D70FC35BF750246155649C6B6690F657D372CCE6FF_cppui_modular256,
                0x1A86D626C558F0BC02FA5F89A591DD8392DA153EB457611BA1B3A40AE3E68BD8_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x000000000000000000000000000000005A694EDCBC5D63D83F6E14016563BD69_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x3FCEA348F31BE8357433DBC714AAB303EE1477D6BCFFEC816D45199D004EA0EB_cppui_modular256,
                0x37851472B67A5A35A8F54A001659CB995C7C501CEFF4BE5448D7250508A14FBC_cppui_modular256));
        spng.absorb_g(group_type::value_type(
                0x32ACB0BD9286BDE74B949BEFA7224706890479EF2B3AE5BD11B977910D1B7478_cppui_modular256,
                0x2FB122CE2BFC57B5FF1D2CDB673D3328B6770C065E8253E90980A283AF8EBB15_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x0000000000000000000000000000000063597BF8593B53D1BEA983CAE5AA0140_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x1012AEEE4AB904D4A3B47AACDD04BD8D119B3A8015F76DF7F24AD13B7C06BB90_cppui_modular256,
                0x03428FD045BAA622B9F7EEB54E8321D96EE1CC04CEFB26F1AEB3D6D40A4DED20_cppui_modular256));
        spng.absorb_g(group_type::value_type(
                0x184F8EA7DFF1970F52E5A75BC74D8F0FAF76BEB2C56A42D44CB96CCCA895870A_cppui_modular256,
                0x110904EE3F6325E6D3D591FC6D1EAE61D43ACDB54357A7F76AD4FD6DFA59FCB8_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x0000000000000000000000000000000027ABB6B27E12348F52A181F17FE29F41_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x22F5F9CD40DE3BA2268208BAC69D839A0EFF28C445FFC36C21EA64FCC62A7FC5_cppui_modular256,
                0x35FF2C0CAB2901382134A1862322C212A143237419EE758AE4CB6B02FF1BA141_cppui_modular256));
        spng.absorb_g(group_type::value_type(
                0x1E0518490D0DD242420C8786B744E444FF09E2ECB44217B3FC2323BF739BE8A0_cppui_modular256,
                0x00A9F106114217ECA4313604AA123351DEC9EE0B6C42624270CA9390D34DD0F1_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x000000000000000000000000000000000B79378485D93E3A44F4E3EAEF25D3DA_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x14309CF280C4C82C856B17A808A2E5A583DA7EEB1C385F3B4EB12039EA76AE83_cppui_modular256,
                0x241285C939BD25A6CA34D6F347596BD110FE55AF173A0EBBFB659630A4C96B99_cppui_modular256));
        spng.absorb_g(group_type::value_type(
                0x09DA297567A8850406E640FF07BC76CCB9A4FA5C11F328EF03708414CBC1F4B9_cppui_modular256,
                0x3BE674505BBBD0F9ED806218258E029084BAECD51ABE6F9264E80C1899307ED6_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x000000000000000000000000000000003CBCF6C44411CE451A33BAB179026502_cppui_modular256));

        spng.absorb_g(group_type::value_type(
                0x1DA94235A1E998434A93578409C4EB18BD82A01EC5A25E5D7C7C7C5E001F18FB_cppui_modular256,
                0x04A566923D712C1CEBF2DBE553DD185F8FDACF604E50948925264D3A49C037EA_cppui_modular256));
        BOOST_CHECK(spng.challenge() ==
                    value_type(0x0000000000000000000000000000000072FF5A26FAF972660330A5D0CC5C4700_cppui_modular256));
    }

    BOOST_AUTO_TEST_CASE(zk_fr_sponge_test_real_case) {
        // using value_type = base_field_type::value_type;
        fr_sponge_type spng;
        spng.absorb(value_type(0x0ACB65E0765F80498D643313EAAEBFBC7899766A4A337EAF61261344E8C2C551_cppui_modular256));

        spng.absorb(value_type(0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui_modular256));
        spng.absorb(value_type(0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui_modular256));
        spng.absorb(value_type(0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui_modular256));
        spng.absorb(value_type(0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui_modular256));
        spng.absorb(value_type(0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui_modular256));
        spng.absorb(value_type(0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui_modular256));
        spng.absorb(value_type(0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui_modular256));
        spng.absorb(value_type(0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui_modular256));
        spng.absorb(value_type(0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui_modular256));
        spng.absorb(value_type(0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui_modular256));
        spng.absorb(value_type(0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui_modular256));
        spng.absorb(value_type(0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui_modular256));
        spng.absorb(value_type(0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui_modular256));
        spng.absorb(value_type(0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui_modular256));
        spng.absorb(value_type(0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui_modular256));
        spng.absorb(value_type(0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui_modular256));
        spng.absorb(value_type(0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui_modular256));
        spng.absorb(value_type(0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui_modular256));
        spng.absorb(value_type(0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui_modular256));
        spng.absorb(value_type(0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui_modular256));
        spng.absorb(value_type(0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui_modular256));
        spng.absorb(value_type(0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui_modular256));

        // BOOST_CHECK(spng.challenge().value() ==
        // value_type(0x0000000000000000000000000000000000F9B1BCD2BB1DE25807BE9313410D43_cppui_modular256));

        spng.absorb(value_type(0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui_modular256));
        spng.absorb(value_type(0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui_modular256));
        spng.absorb(value_type(0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui_modular256));
        spng.absorb(value_type(0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui_modular256));
        spng.absorb(value_type(0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui_modular256));
        spng.absorb(value_type(0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui_modular256));
        spng.absorb(value_type(0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui_modular256));
        spng.absorb(value_type(0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui_modular256));
        spng.absorb(value_type(0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui_modular256));
        spng.absorb(value_type(0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui_modular256));
        spng.absorb(value_type(0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui_modular256));
        spng.absorb(value_type(0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui_modular256));
        spng.absorb(value_type(0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui_modular256));
        spng.absorb(value_type(0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui_modular256));
        spng.absorb(value_type(0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui_modular256));
        spng.absorb(value_type(0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui_modular256));
        spng.absorb(value_type(0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui_modular256));
        spng.absorb(value_type(0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui_modular256));
        spng.absorb(value_type(0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui_modular256));
        spng.absorb(value_type(0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui_modular256));
        spng.absorb(value_type(0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui_modular256));
        spng.absorb(value_type(0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui_modular256));

        // BOOST_CHECK(spng.challenge().value() ==
        // value_type(0x00000000000000000000000000000000578543A9BA83C66925F5301C187FBF94_cppui_modular256));

        spng.absorb(value_type(0x16FE1AE7F56997161DB512632BE7BFA337F47F422E0D01AF06DE298DD8C429D5_cppui_modular256));

        auto squeezed_val1 = spng.challenge().value();
        // std::cout << std::hex << squeezed_val1.data << '\n';
        BOOST_CHECK(squeezed_val1 ==
                    value_type(0x0000000000000000000000000000000070BB1327D20E6ADBCA0F584AEC2D4D0C_cppui_modular256));

        squeezed_val1 = spng.challenge().value();
        // std::cout << std::hex << squeezed_val1.data << '\n';
        BOOST_CHECK(squeezed_val1 ==
                    value_type(0x0000000000000000000000000000000062BE7EB9CB6245B29DF02D68B4B51EC5_cppui_modular256));
    }

BOOST_AUTO_TEST_SUITE_END()
