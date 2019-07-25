#ifndef CRYPTO3_PUBKEY_EC_GROUP_INFO_HPP
#define CRYPTO3_PUBKEY_EC_GROUP_INFO_HPP

#include <nil/crypto3/asn1/asn1_oid.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int/cpp_int_config.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            using namespace boost::multiprecision;

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(160)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(239)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(320)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)
            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521)

            template<std::size_t PBits>
            struct ec_group_info {
                constexpr static const std::size_t p_bits = PBits;

                typedef number<backends::cpp_int_backend<p_bits, p_bits, unsigned_magnitude, unchecked, void>>
                    number_type;
            };

            template<std::size_t PBits>
            struct nist : public ec_group_info<PBits> {};

            template<>
            struct nist<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF_cppui256;
                constexpr static const number_type a
                    = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC_cppui256;
                constexpr static const number_type b
                    = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B_cppui256;
                constexpr static const number_type x
                    = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296_cppui256;
                constexpr static const number_type y
                    = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5_cppui256;
                constexpr static const number_type order
                    = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551_cppui256;

                static const oid_t oid;
            };

            const oid_t nist<256>::oid = oid_t {1, 2, 840, 10045, 3, 1, 7};

            template<>
            struct nist<384> : public ec_group_info<384> {
                typedef ec_group_info<384>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF_cppui384;
                constexpr static const number_type a
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC_cppui384;
                constexpr static const number_type b
                    = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF_cppui384;
                constexpr static const number_type x
                    = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7_cppui384;
                constexpr static const number_type y
                    = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F_cppui384;
                constexpr static const number_type order
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973_cppui384;

                static const oid_t oid;
            };

            const oid_t nist<384>::oid = oid_t {1, 3, 132, 0, 34};

            template<>
            struct nist<521> : public ec_group_info<521> {
                typedef ec_group_info<521>::number_type number_type;

                constexpr static const number_type p
                    = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_cppui521;
                constexpr static const number_type a
                    = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC_cppui521;
                constexpr static const number_type b
                    = 0x51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00_cppui521;
                constexpr static const number_type x
                    = 0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66_cppui521;
                constexpr static const number_type y
                    = 0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650_cppui521;
                constexpr static const number_type order
                    = 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409_cppui521;

                static const oid_t oid;
            };

            const oid_t nist<521>::oid = oid_t {1, 3, 132, 0, 35};

            template<std::size_t PBits>
            struct brainpool_r1 : public ec_group_info<PBits> {};

            template<>
            struct brainpool_r1<160> : public ec_group_info<160> {
                typedef ec_group_info<160>::number_type number_type;

                constexpr static const number_type p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F_cppui160;
                constexpr static const number_type a = 0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300_cppui160;
                constexpr static const number_type b = 0x1E589A8595423412134FAA2DBDEC95C8D8675E58_cppui160;
                constexpr static const number_type x = 0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3_cppui160;
                constexpr static const number_type y = 0x1667CB477A1A8EC338F94741669C976316DA6321_cppui160;
                constexpr static const number_type order = 0xE95E4A5F737059DC60DF5991D45029409E60FC09_cppui160;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<160>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 1};

            typedef brainpool_r1<160> brainpool160r1;

            template<>
            struct brainpool_r1<192> : public ec_group_info<192> {
                typedef ec_group_info<192>::number_type number_type;

                constexpr static const number_type p = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297_cppui192;
                constexpr static const number_type a = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF_cppui192;
                constexpr static const number_type b = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9_cppui192;
                constexpr static const number_type x = 0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6_cppui192;
                constexpr static const number_type y = 0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F_cppui192;
                constexpr static const number_type order = 0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1_cppui192;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<192>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 3};

            typedef brainpool_r1<192> brainpool192r1;

            template<>
            struct brainpool_r1<224> : public ec_group_info<224> {
                typedef ec_group_info<224>::number_type number_type;

                constexpr static const number_type p
                    = 0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF_cppui224;
                constexpr static const number_type a
                    = 0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43_cppui224;
                constexpr static const number_type b
                    = 0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B_cppui224;
                constexpr static const number_type x
                    = 0xD9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D_cppui224;
                constexpr static const number_type y
                    = 0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD_cppui224;
                constexpr static const number_type order
                    = 0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F_cppui224;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<224>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 5};

            typedef brainpool_r1<224> brainpool224r1;

            template<>
            struct brainpool_r1<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377_cppui256;
                constexpr static const number_type a
                    = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9_cppui256;
                constexpr static const number_type b
                    = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6_cppui256;
                constexpr static const number_type x
                    = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262_cppui256;
                constexpr static const number_type y
                    = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997_cppui256;
                constexpr static const number_type order
                    = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7_cppui256;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<256>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 7};

            typedef brainpool_r1<256> brainpool256r1;

            template<>
            struct brainpool_r1<320> : public ec_group_info<320> {
                typedef ec_group_info<320>::number_type number_type;

                constexpr static const number_type p
                    = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27_cppui320;
                constexpr static const number_type a
                    = 0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4_cppui320;
                constexpr static const number_type b
                    = 0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6_cppui320;
                constexpr static const number_type x
                    = 0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611_cppui320;
                constexpr static const number_type y
                    = 0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1_cppui320;
                constexpr static const number_type order
                    = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311_cppui320;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<320>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 9};

            typedef brainpool_r1<320> brainpool320r1;

            template<>
            struct brainpool_r1<384> : public ec_group_info<384> {
                typedef ec_group_info<384>::number_type number_type;

                constexpr static const number_type p
                    = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53_cppui384;
                constexpr static const number_type a
                    = 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826_cppui384;
                constexpr static const number_type b
                    = 0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11_cppui384;
                constexpr static const number_type x
                    = 0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E_cppui384;
                constexpr static const number_type y
                    = 0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315_cppui384;
                constexpr static const number_type order
                    = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565_cppui384;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<384>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 11};

            typedef brainpool_r1<384> brainpool384r1;

            template<>
            struct brainpool_r1<512> : public ec_group_info<512> {
                typedef ec_group_info<512>::number_type number_type;

                constexpr static const number_type p
                    = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3_cppui512;
                constexpr static const number_type a
                    = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA_cppui512;
                constexpr static const number_type b
                    = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723_cppui512;
                constexpr static const number_type x
                    = 0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822_cppui512;
                constexpr static const number_type y
                    = 0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892_cppui512;
                constexpr static const number_type order
                    = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069_cppui512;

                static const oid_t oid;
            };

            const oid_t brainpool_r1<512>::oid = oid_t {1, 3, 36, 3, 3, 2, 8, 1, 1, 13};

            typedef brainpool_r1<512> brainpool512r1;

            template<std::size_t PBits>
            struct frp_v1 : public ec_group_info<PBits> {};

            template<>
            struct frp_v1<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03_cppui256;
                constexpr static const number_type a
                    = 0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00_cppui256;
                constexpr static const number_type b
                    = 0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F_cppui256;
                constexpr static const number_type x
                    = 0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF_cppui256;
                constexpr static const number_type y
                    = 0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB_cppui256;
                constexpr static const number_type order
                    = 0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1_cppui256;

                static const oid_t oid;
            };

            const oid_t frp_v1<256>::oid = oid_t {1, 2, 250, 1, 223, 101, 256, 1};

            template<std::size_t PBits>
            struct gost_A : public ec_group_info<PBits> {};

            template<>
            struct gost_A<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97_cppui256;
                constexpr static const number_type a
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94_cppui256;
                constexpr static const number_type b = 0xA6_cppui256;
                constexpr static const number_type x = 0x1_cppui256;
                constexpr static const number_type y
                    = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14_cppui256;
                constexpr static const number_type order
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893_cppui256;

                static const oid_t oid;
            };

            const oid_t gost_A<256>::oid = oid_t {1, 2, 643, 2, 2, 35, 1};

            template<std::size_t PBits>
            struct secp_k1 : public ec_group_info<PBits> {};

            template<std::size_t PBits>
            struct secp_r1 : public ec_group_info<PBits> {};

            template<std::size_t PBits>
            struct secp_r2 : public ec_group_info<PBits> {};

            template<>
            struct secp_k1<160> : public ec_group_info<160> {
                typedef ec_group_info<160>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;
                constexpr static const number_type a = 0x0_cppui160;
                constexpr static const number_type b = 0x7_cppui160;
                constexpr static const number_type x = 0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB_cppui160;
                constexpr static const number_type y = 0x938CF935318FDCED6BC28286531733C3F03C4FEE_cppui160;
                constexpr static const number_type order = 0x100000000000000000001B8FA16DFAB9ACA16B6B3_cppui160;

                static const oid_t oid;
            };

            const oid_t secp_k1<160>::oid = oid_t {1, 3, 132, 0, 9};

            typedef secp_k1<160> secp160k1;

            template<>
            struct secp_r1<160> : public ec_group_info<160> {
                typedef ec_group_info<160>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF_cppui160;
                constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC_cppui160;
                constexpr static const number_type b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45_cppui160;
                constexpr static const number_type x = 0x4A96B5688EF573284664698968C38BB913CBFC82_cppui160;
                constexpr static const number_type y = 0x23A628553168947D59DCC912042351377AC5FB32_cppui160;
                constexpr static const number_type order = 0x100000000000000000001F4C8F927AED3CA752257_cppui160;

                static const oid_t oid;
            };

            const oid_t secp_r1<160>::oid = oid_t {1, 3, 132, 0, 8};

            typedef secp_r1<160> secp160r1;

            template<>
            struct secp_r2<160> : public ec_group_info<160> {
                typedef ec_group_info<160>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;
                constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70_cppui160;
                constexpr static const number_type b = 0xB4E134D3FB59EB8BAB57274904664D5AF50388BA_cppui160;
                constexpr static const number_type x = 0x52DCB034293A117E1F4FF11B30F7199D3144CE6D_cppui160;
                constexpr static const number_type y = 0xFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E_cppui160;
                constexpr static const number_type order = 0x100000000000000000000351EE786A818F3A1A16B_cppui160;

                static const oid_t oid;
            };

            const oid_t secp_r2<160>::oid = oid_t {1, 3, 132, 0, 30};

            typedef secp_r2<160> secp160r2;

            template<>
            struct secp_k1<192> : public ec_group_info<192> {
                typedef ec_group_info<192>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;
                constexpr static const number_type a = 0x0_cppui192;
                constexpr static const number_type b = 0x3_cppui192;
                constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
                constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
                constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                static const oid_t oid;
            };

            const oid_t secp_k1<192>::oid = oid_t {1, 3, 132, 0, 31};

            typedef secp_k1<192> secp192k1;

            template<>
            struct secp_r1<192> : public ec_group_info<192> {
                typedef ec_group_info<192>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;
                constexpr static const number_type a = 0x0_cppui192;
                constexpr static const number_type b = 0x3_cppui192;
                constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
                constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
                constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                static const oid_t oid;
            };

            const oid_t secp_r1<192>::oid = oid_t {1, 2, 840, 10045, 3, 1, 1};

            typedef secp_r1<192> secp192r1;

            template<>
            struct secp_k1<224> : public ec_group_info<224> {
                typedef ec_group_info<224>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D_cppui224;
                constexpr static const number_type a = 0x0_cppui224;
                constexpr static const number_type b = 0x5_cppui224;
                constexpr static const number_type x
                    = 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C_cppui224;
                constexpr static const number_type y
                    = 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5_cppui224;
                constexpr static const number_type order
                    = 0x10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7_cppui224;

                static const oid_t oid;
            };

            const oid_t secp_k1<224>::oid = oid_t {1, 3, 132, 0, 32};

            typedef secp_k1<224> secp224k1;

            template<>
            struct secp_r1<224> : public ec_group_info<224> {
                typedef ec_group_info<224>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;
                constexpr static const number_type a
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE_cppui224;
                constexpr static const number_type b
                    = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4_cppui224;
                constexpr static const number_type x
                    = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21_cppui224;
                constexpr static const number_type y
                    = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34_cppui224;
                constexpr static const number_type order
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D_cppui224;

                static const oid_t oid;
            };

            const oid_t secp_r1<224>::oid = oid_t {1, 3, 132, 0, 33};

            typedef secp_r1<256> secp256r1;

            template<>
            struct secp_k1<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_cppui256;
                constexpr static const number_type a = 0x0_cppui256;
                constexpr static const number_type b = 0x7_cppui256;
                constexpr static const number_type x
                    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_cppui256;
                constexpr static const number_type y
                    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_cppui256;
                constexpr static const number_type order
                    = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_cppui256;

                static const oid_t oid;
            };

            const oid_t secp_k1<256>::oid = oid_t {1, 3, 132, 0, 10};

            typedef secp_k1<256> secp256k1;

            template<std::size_t PBits>
            struct sm2p_v1 : public ec_group_info<PBits> {};

            template<>
            struct sm2p_v1<256> : public ec_group_info<256> {
                typedef ec_group_info<256>::number_type number_type;

                constexpr static const number_type p
                    = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF_cppui256;
                constexpr static const number_type a
                    = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC_cppui256;
                constexpr static const number_type b
                    = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93_cppui256;
                constexpr static const number_type x
                    = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7_cppui256;
                constexpr static const number_type y
                    = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0_cppui256;
                constexpr static const number_type order
                    = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123_cppui256;

                static const oid_t oid;
            };

            const oid_t sm2p_v1<256>::oid = oid_t {1, 2, 156, 10197, 1, 301};

            typedef sm2p_v1<256> sm2p256v1;

            template<std::size_t PBits>
            struct x962_p_v1 : public ec_group_info<PBits> {};

            template<std::size_t PBits>
            struct x962_p_v2 : public ec_group_info<PBits> {};

            template<std::size_t PBits>
            struct x962_p_v3 : public ec_group_info<PBits> {};

            template<>
            struct x962_p_v2<192> : public ec_group_info<192> {
                typedef ec_group_info<192>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
                constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
                constexpr static const number_type b = 0xCC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953_cppui192;
                constexpr static const number_type x = 0xEEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A_cppui192;
                constexpr static const number_type y = 0x6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15_cppui192;
                constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31_cppui192;

                static const oid_t oid;
            };

            const oid_t x962_p_v2<192>::oid = oid_t {1, 2, 840, 10045, 3, 1, 2};

            typedef x962_p_v3<192> x962_p192v2;

            template<>
            struct x962_p_v3<192> : public ec_group_info<192> {
                typedef ec_group_info<192>::number_type number_type;

                constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
                constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
                constexpr static const number_type b = 0x22123DC2395A05CAA7423DAECCC94760A7D462256BD56916_cppui192;
                constexpr static const number_type x = 0x7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896_cppui192;
                constexpr static const number_type y = 0x38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0_cppui192;
                constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13_cppui192;

                static const oid_t oid;
            };

            const oid_t x962_p_v3<192>::oid = oid_t {1, 2, 840, 10045, 3, 1, 3};

            typedef x962_p_v3<192> x962_p192v3;

            template<>
            struct x962_p_v1<239> : public ec_group_info<239> {
                typedef ec_group_info<239>::number_type number_type;

                constexpr static const number_type p
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
                constexpr static const number_type a
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                constexpr static const number_type b
                    = 0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A_cppui239;
                constexpr static const number_type x
                    = 0xFFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF_cppui239;
                constexpr static const number_type y
                    = 0x7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE_cppui239;
                constexpr static const number_type order
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B_cppui239;

                static const oid_t oid;
            };

            const oid_t x962_p_v1<239>::oid = oid_t {1, 2, 840, 10045, 3, 1, 4};

            typedef x962_p_v3<239> x962_p239v1;

            template<>
            struct x962_p_v2<239> : public ec_group_info<239> {
                typedef ec_group_info<239>::number_type number_type;

                constexpr static const number_type p
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
                constexpr static const number_type a
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                constexpr static const number_type b
                    = 0x617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C_cppui239;
                constexpr static const number_type x
                    = 0x38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7_cppui239;
                constexpr static const number_type y
                    = 0x5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA_cppui239;
                constexpr static const number_type order
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063_cppui239;

                static const oid_t oid;
            };

            const oid_t x962_p_v2<239>::oid = oid_t {1, 2, 840, 10045, 3, 1, 5};

            typedef x962_p_v3<239> x962_p239v2;

            template<>
            struct x962_p_v3<239> : public ec_group_info<239> {
                typedef ec_group_info<239>::number_type number_type;

                constexpr static const number_type p
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
                constexpr static const number_type a
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
                constexpr static const number_type b
                    = 0x255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E_cppui239;
                constexpr static const number_type x
                    = 0x6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A_cppui239;
                constexpr static const number_type y
                    = 0x1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3_cppui239;
                constexpr static const number_type order
                    = 0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551_cppui239;

                static const oid_t oid;
            };

            const oid_t x962_p_v3<239>::oid = oid_t {1, 2, 840, 10045, 3, 1, 6};

            typedef x962_p_v3<239> x962_p239v3;
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_EC_GROUP_INFO_HPP
