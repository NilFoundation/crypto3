//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BRAINPOOL_R1_HPP
#define ALGEBRA_CURVES_BRAINPOOL_R1_HPP

#include <nil/crypto3/pubkey/ec_group/curve_weierstrass.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(160)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(320)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521)

            template<std::size_t PBits>
            struct brainpool_r1 : public curve_weierstrass<PBits> {};

            template<>
            struct brainpool_r1<160> : public curve_weierstrass<160> {
                typedef typename curve_weierstrass<160>::number_type number_type;

                constexpr static const number_type p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F_cppui160;
                constexpr static const number_type a = 0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300_cppui160;
                constexpr static const number_type b = 0x1E589A8595423412134FAA2DBDEC95C8D8675E58_cppui160;
                constexpr static const number_type x = 0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3_cppui160;
                constexpr static const number_type y = 0x1667CB477A1A8EC338F94741669C976316DA6321_cppui160;
                constexpr static const number_type order = 0xE95E4A5F737059DC60DF5991D45029409E60FC09_cppui160;

            };

            typedef brainpool_r1<160> brainpool160r1;

            template<>
            struct brainpool_r1<192> : public curve_weierstrass<192> {
                typedef typename curve_weierstrass<192>::number_type number_type;

                constexpr static const number_type p = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297_cppui192;
                constexpr static const number_type a = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF_cppui192;
                constexpr static const number_type b = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9_cppui192;
                constexpr static const number_type x = 0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6_cppui192;
                constexpr static const number_type y = 0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F_cppui192;
                constexpr static const number_type order = 0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1_cppui192;

            };

            typedef brainpool_r1<192> brainpool192r1;

            template<>
            struct brainpool_r1<224> : public curve_weierstrass<224> {
                typedef typename ec_group_info<224>::number_type number_type;

                constexpr static const number_type p =
                    0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF_cppui224;
                constexpr static const number_type a =
                    0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43_cppui224;
                constexpr static const number_type b =
                    0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B_cppui224;
                constexpr static const number_type x =
                    0xD9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D_cppui224;
                constexpr static const number_type y =
                    0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD_cppui224;
                constexpr static const number_type order =
                    0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F_cppui224;

            };

            typedef brainpool_r1<224> brainpool224r1;

            template<>
            struct brainpool_r1<256> : public curve_weierstrass<256> {
                typedef typename ec_group_info<256>::number_type number_type;

                constexpr static const number_type p =
                    0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377_cppui256;
                constexpr static const number_type a =
                    0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9_cppui256;
                constexpr static const number_type b =
                    0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6_cppui256;
                constexpr static const number_type x =
                    0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262_cppui256;
                constexpr static const number_type y =
                    0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997_cppui256;
                constexpr static const number_type order =
                    0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7_cppui256;

            };

            typedef brainpool_r1<256> brainpool256r1;

            template<>
            struct brainpool_r1<320> : public curve_weierstrass<320> {
                typedef typename ec_group_info<320>::number_type number_type;

                constexpr static const number_type p =
                    0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27_cppui320;
                constexpr static const number_type a =
                    0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4_cppui320;
                constexpr static const number_type b =
                    0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6_cppui320;
                constexpr static const number_type x =
                    0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611_cppui320;
                constexpr static const number_type y =
                    0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1_cppui320;
                constexpr static const number_type order =
                    0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311_cppui320;

            };

            typedef brainpool_r1<320> brainpool320r1;

            template<>
            struct brainpool_r1<384> : public curve_weierstrass<384> {
                typedef typename ec_group_info<384>::number_type number_type;

                constexpr static const number_type p =
                    0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53_cppui384;
                constexpr static const number_type a =
                    0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826_cppui384;
                constexpr static const number_type b =
                    0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11_cppui384;
                constexpr static const number_type x =
                    0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E_cppui384;
                constexpr static const number_type y =
                    0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315_cppui384;
                constexpr static const number_type order =
                    0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565_cppui384;

            };

            typedef brainpool_r1<384> brainpool384r1;

            template<>
            struct brainpool_r1<512> : public curve_weierstrass<512> {
                typedef typename ec_group_info<512>::number_type number_type;

                constexpr static const number_type p =
                    0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3_cppui512;
                constexpr static const number_type a =
                    0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA_cppui512;
                constexpr static const number_type b =
                    0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723_cppui512;
                constexpr static const number_type x =
                    0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822_cppui512;
                constexpr static const number_type y =
                    0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892_cppui512;
                constexpr static const number_type order =
                    0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069_cppui512;
            };

            typedef brainpool_r1<512> brainpool512r1;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_BRAINPOOL_R1_HPP
