//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP

#include <boost/algorithm/string.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#define MAX_STRING_LITERAL_LENGTH 249
#define STRING_LITERAL(str) string_literal<char_pack<STRING_LITERAL_249(str)>>::s
#define STRING_LITERAL_250(str) STRING_LITERAL_249(str), ((TERMINATED_249(str)) ? (str[249]) : ('\0'))
#define STRING_LITERAL_249(str) STRING_LITERAL_248(str), ((TERMINATED_248(str)) ? (str[248]) : ('\0'))
#define STRING_LITERAL_248(str) STRING_LITERAL_247(str), ((TERMINATED_247(str)) ? (str[247]) : ('\0'))
#define STRING_LITERAL_247(str) STRING_LITERAL_246(str), ((TERMINATED_246(str)) ? (str[246]) : ('\0'))
#define STRING_LITERAL_246(str) STRING_LITERAL_245(str), ((TERMINATED_245(str)) ? (str[245]) : ('\0'))
#define STRING_LITERAL_245(str) STRING_LITERAL_244(str), ((TERMINATED_244(str)) ? (str[244]) : ('\0'))
#define STRING_LITERAL_244(str) STRING_LITERAL_243(str), ((TERMINATED_243(str)) ? (str[243]) : ('\0'))
#define STRING_LITERAL_243(str) STRING_LITERAL_242(str), ((TERMINATED_242(str)) ? (str[242]) : ('\0'))
#define STRING_LITERAL_242(str) STRING_LITERAL_241(str), ((TERMINATED_241(str)) ? (str[241]) : ('\0'))
#define STRING_LITERAL_241(str) STRING_LITERAL_240(str), ((TERMINATED_240(str)) ? (str[240]) : ('\0'))
#define STRING_LITERAL_240(str) STRING_LITERAL_239(str), ((TERMINATED_239(str)) ? (str[239]) : ('\0'))
#define STRING_LITERAL_239(str) STRING_LITERAL_238(str), ((TERMINATED_238(str)) ? (str[238]) : ('\0'))
#define STRING_LITERAL_238(str) STRING_LITERAL_237(str), ((TERMINATED_237(str)) ? (str[237]) : ('\0'))
#define STRING_LITERAL_237(str) STRING_LITERAL_236(str), ((TERMINATED_236(str)) ? (str[236]) : ('\0'))
#define STRING_LITERAL_236(str) STRING_LITERAL_235(str), ((TERMINATED_235(str)) ? (str[235]) : ('\0'))
#define STRING_LITERAL_235(str) STRING_LITERAL_234(str), ((TERMINATED_234(str)) ? (str[234]) : ('\0'))
#define STRING_LITERAL_234(str) STRING_LITERAL_233(str), ((TERMINATED_233(str)) ? (str[233]) : ('\0'))
#define STRING_LITERAL_233(str) STRING_LITERAL_232(str), ((TERMINATED_232(str)) ? (str[232]) : ('\0'))
#define STRING_LITERAL_232(str) STRING_LITERAL_231(str), ((TERMINATED_231(str)) ? (str[231]) : ('\0'))
#define STRING_LITERAL_231(str) STRING_LITERAL_230(str), ((TERMINATED_230(str)) ? (str[230]) : ('\0'))
#define STRING_LITERAL_230(str) STRING_LITERAL_229(str), ((TERMINATED_229(str)) ? (str[229]) : ('\0'))
#define STRING_LITERAL_229(str) STRING_LITERAL_228(str), ((TERMINATED_228(str)) ? (str[228]) : ('\0'))
#define STRING_LITERAL_228(str) STRING_LITERAL_227(str), ((TERMINATED_227(str)) ? (str[227]) : ('\0'))
#define STRING_LITERAL_227(str) STRING_LITERAL_226(str), ((TERMINATED_226(str)) ? (str[226]) : ('\0'))
#define STRING_LITERAL_226(str) STRING_LITERAL_225(str), ((TERMINATED_225(str)) ? (str[225]) : ('\0'))
#define STRING_LITERAL_225(str) STRING_LITERAL_224(str), ((TERMINATED_224(str)) ? (str[224]) : ('\0'))
#define STRING_LITERAL_224(str) STRING_LITERAL_223(str), ((TERMINATED_223(str)) ? (str[223]) : ('\0'))
#define STRING_LITERAL_223(str) STRING_LITERAL_222(str), ((TERMINATED_222(str)) ? (str[222]) : ('\0'))
#define STRING_LITERAL_222(str) STRING_LITERAL_221(str), ((TERMINATED_221(str)) ? (str[221]) : ('\0'))
#define STRING_LITERAL_221(str) STRING_LITERAL_220(str), ((TERMINATED_220(str)) ? (str[220]) : ('\0'))
#define STRING_LITERAL_220(str) STRING_LITERAL_219(str), ((TERMINATED_219(str)) ? (str[219]) : ('\0'))
#define STRING_LITERAL_219(str) STRING_LITERAL_218(str), ((TERMINATED_218(str)) ? (str[218]) : ('\0'))
#define STRING_LITERAL_218(str) STRING_LITERAL_217(str), ((TERMINATED_217(str)) ? (str[217]) : ('\0'))
#define STRING_LITERAL_217(str) STRING_LITERAL_216(str), ((TERMINATED_216(str)) ? (str[216]) : ('\0'))
#define STRING_LITERAL_216(str) STRING_LITERAL_215(str), ((TERMINATED_215(str)) ? (str[215]) : ('\0'))
#define STRING_LITERAL_215(str) STRING_LITERAL_214(str), ((TERMINATED_214(str)) ? (str[214]) : ('\0'))
#define STRING_LITERAL_214(str) STRING_LITERAL_213(str), ((TERMINATED_213(str)) ? (str[213]) : ('\0'))
#define STRING_LITERAL_213(str) STRING_LITERAL_212(str), ((TERMINATED_212(str)) ? (str[212]) : ('\0'))
#define STRING_LITERAL_212(str) STRING_LITERAL_211(str), ((TERMINATED_211(str)) ? (str[211]) : ('\0'))
#define STRING_LITERAL_211(str) STRING_LITERAL_210(str), ((TERMINATED_210(str)) ? (str[210]) : ('\0'))
#define STRING_LITERAL_210(str) STRING_LITERAL_209(str), ((TERMINATED_209(str)) ? (str[209]) : ('\0'))
#define STRING_LITERAL_209(str) STRING_LITERAL_208(str), ((TERMINATED_208(str)) ? (str[208]) : ('\0'))
#define STRING_LITERAL_208(str) STRING_LITERAL_207(str), ((TERMINATED_207(str)) ? (str[207]) : ('\0'))
#define STRING_LITERAL_207(str) STRING_LITERAL_206(str), ((TERMINATED_206(str)) ? (str[206]) : ('\0'))
#define STRING_LITERAL_206(str) STRING_LITERAL_205(str), ((TERMINATED_205(str)) ? (str[205]) : ('\0'))
#define STRING_LITERAL_205(str) STRING_LITERAL_204(str), ((TERMINATED_204(str)) ? (str[204]) : ('\0'))
#define STRING_LITERAL_204(str) STRING_LITERAL_203(str), ((TERMINATED_203(str)) ? (str[203]) : ('\0'))
#define STRING_LITERAL_203(str) STRING_LITERAL_202(str), ((TERMINATED_202(str)) ? (str[202]) : ('\0'))
#define STRING_LITERAL_202(str) STRING_LITERAL_201(str), ((TERMINATED_201(str)) ? (str[201]) : ('\0'))
#define STRING_LITERAL_201(str) STRING_LITERAL_200(str), ((TERMINATED_200(str)) ? (str[200]) : ('\0'))
#define STRING_LITERAL_200(str) STRING_LITERAL_199(str), ((TERMINATED_199(str)) ? (str[199]) : ('\0'))
#define STRING_LITERAL_199(str) STRING_LITERAL_198(str), ((TERMINATED_198(str)) ? (str[198]) : ('\0'))
#define STRING_LITERAL_198(str) STRING_LITERAL_197(str), ((TERMINATED_197(str)) ? (str[197]) : ('\0'))
#define STRING_LITERAL_197(str) STRING_LITERAL_196(str), ((TERMINATED_196(str)) ? (str[196]) : ('\0'))
#define STRING_LITERAL_196(str) STRING_LITERAL_195(str), ((TERMINATED_195(str)) ? (str[195]) : ('\0'))
#define STRING_LITERAL_195(str) STRING_LITERAL_194(str), ((TERMINATED_194(str)) ? (str[194]) : ('\0'))
#define STRING_LITERAL_194(str) STRING_LITERAL_193(str), ((TERMINATED_193(str)) ? (str[193]) : ('\0'))
#define STRING_LITERAL_193(str) STRING_LITERAL_192(str), ((TERMINATED_192(str)) ? (str[192]) : ('\0'))
#define STRING_LITERAL_192(str) STRING_LITERAL_191(str), ((TERMINATED_191(str)) ? (str[191]) : ('\0'))
#define STRING_LITERAL_191(str) STRING_LITERAL_190(str), ((TERMINATED_190(str)) ? (str[190]) : ('\0'))
#define STRING_LITERAL_190(str) STRING_LITERAL_189(str), ((TERMINATED_189(str)) ? (str[189]) : ('\0'))
#define STRING_LITERAL_189(str) STRING_LITERAL_188(str), ((TERMINATED_188(str)) ? (str[188]) : ('\0'))
#define STRING_LITERAL_188(str) STRING_LITERAL_187(str), ((TERMINATED_187(str)) ? (str[187]) : ('\0'))
#define STRING_LITERAL_187(str) STRING_LITERAL_186(str), ((TERMINATED_186(str)) ? (str[186]) : ('\0'))
#define STRING_LITERAL_186(str) STRING_LITERAL_185(str), ((TERMINATED_185(str)) ? (str[185]) : ('\0'))
#define STRING_LITERAL_185(str) STRING_LITERAL_184(str), ((TERMINATED_184(str)) ? (str[184]) : ('\0'))
#define STRING_LITERAL_184(str) STRING_LITERAL_183(str), ((TERMINATED_183(str)) ? (str[183]) : ('\0'))
#define STRING_LITERAL_183(str) STRING_LITERAL_182(str), ((TERMINATED_182(str)) ? (str[182]) : ('\0'))
#define STRING_LITERAL_182(str) STRING_LITERAL_181(str), ((TERMINATED_181(str)) ? (str[181]) : ('\0'))
#define STRING_LITERAL_181(str) STRING_LITERAL_180(str), ((TERMINATED_180(str)) ? (str[180]) : ('\0'))
#define STRING_LITERAL_180(str) STRING_LITERAL_179(str), ((TERMINATED_179(str)) ? (str[179]) : ('\0'))
#define STRING_LITERAL_179(str) STRING_LITERAL_178(str), ((TERMINATED_178(str)) ? (str[178]) : ('\0'))
#define STRING_LITERAL_178(str) STRING_LITERAL_177(str), ((TERMINATED_177(str)) ? (str[177]) : ('\0'))
#define STRING_LITERAL_177(str) STRING_LITERAL_176(str), ((TERMINATED_176(str)) ? (str[176]) : ('\0'))
#define STRING_LITERAL_176(str) STRING_LITERAL_175(str), ((TERMINATED_175(str)) ? (str[175]) : ('\0'))
#define STRING_LITERAL_175(str) STRING_LITERAL_174(str), ((TERMINATED_174(str)) ? (str[174]) : ('\0'))
#define STRING_LITERAL_174(str) STRING_LITERAL_173(str), ((TERMINATED_173(str)) ? (str[173]) : ('\0'))
#define STRING_LITERAL_173(str) STRING_LITERAL_172(str), ((TERMINATED_172(str)) ? (str[172]) : ('\0'))
#define STRING_LITERAL_172(str) STRING_LITERAL_171(str), ((TERMINATED_171(str)) ? (str[171]) : ('\0'))
#define STRING_LITERAL_171(str) STRING_LITERAL_170(str), ((TERMINATED_170(str)) ? (str[170]) : ('\0'))
#define STRING_LITERAL_170(str) STRING_LITERAL_169(str), ((TERMINATED_169(str)) ? (str[169]) : ('\0'))
#define STRING_LITERAL_169(str) STRING_LITERAL_168(str), ((TERMINATED_168(str)) ? (str[168]) : ('\0'))
#define STRING_LITERAL_168(str) STRING_LITERAL_167(str), ((TERMINATED_167(str)) ? (str[167]) : ('\0'))
#define STRING_LITERAL_167(str) STRING_LITERAL_166(str), ((TERMINATED_166(str)) ? (str[166]) : ('\0'))
#define STRING_LITERAL_166(str) STRING_LITERAL_165(str), ((TERMINATED_165(str)) ? (str[165]) : ('\0'))
#define STRING_LITERAL_165(str) STRING_LITERAL_164(str), ((TERMINATED_164(str)) ? (str[164]) : ('\0'))
#define STRING_LITERAL_164(str) STRING_LITERAL_163(str), ((TERMINATED_163(str)) ? (str[163]) : ('\0'))
#define STRING_LITERAL_163(str) STRING_LITERAL_162(str), ((TERMINATED_162(str)) ? (str[162]) : ('\0'))
#define STRING_LITERAL_162(str) STRING_LITERAL_161(str), ((TERMINATED_161(str)) ? (str[161]) : ('\0'))
#define STRING_LITERAL_161(str) STRING_LITERAL_160(str), ((TERMINATED_160(str)) ? (str[160]) : ('\0'))
#define STRING_LITERAL_160(str) STRING_LITERAL_159(str), ((TERMINATED_159(str)) ? (str[159]) : ('\0'))
#define STRING_LITERAL_159(str) STRING_LITERAL_158(str), ((TERMINATED_158(str)) ? (str[158]) : ('\0'))
#define STRING_LITERAL_158(str) STRING_LITERAL_157(str), ((TERMINATED_157(str)) ? (str[157]) : ('\0'))
#define STRING_LITERAL_157(str) STRING_LITERAL_156(str), ((TERMINATED_156(str)) ? (str[156]) : ('\0'))
#define STRING_LITERAL_156(str) STRING_LITERAL_155(str), ((TERMINATED_155(str)) ? (str[155]) : ('\0'))
#define STRING_LITERAL_155(str) STRING_LITERAL_154(str), ((TERMINATED_154(str)) ? (str[154]) : ('\0'))
#define STRING_LITERAL_154(str) STRING_LITERAL_153(str), ((TERMINATED_153(str)) ? (str[153]) : ('\0'))
#define STRING_LITERAL_153(str) STRING_LITERAL_152(str), ((TERMINATED_152(str)) ? (str[152]) : ('\0'))
#define STRING_LITERAL_152(str) STRING_LITERAL_151(str), ((TERMINATED_151(str)) ? (str[151]) : ('\0'))
#define STRING_LITERAL_151(str) STRING_LITERAL_150(str), ((TERMINATED_150(str)) ? (str[150]) : ('\0'))
#define STRING_LITERAL_150(str) STRING_LITERAL_149(str), ((TERMINATED_149(str)) ? (str[149]) : ('\0'))
#define STRING_LITERAL_149(str) STRING_LITERAL_148(str), ((TERMINATED_148(str)) ? (str[148]) : ('\0'))
#define STRING_LITERAL_148(str) STRING_LITERAL_147(str), ((TERMINATED_147(str)) ? (str[147]) : ('\0'))
#define STRING_LITERAL_147(str) STRING_LITERAL_146(str), ((TERMINATED_146(str)) ? (str[146]) : ('\0'))
#define STRING_LITERAL_146(str) STRING_LITERAL_145(str), ((TERMINATED_145(str)) ? (str[145]) : ('\0'))
#define STRING_LITERAL_145(str) STRING_LITERAL_144(str), ((TERMINATED_144(str)) ? (str[144]) : ('\0'))
#define STRING_LITERAL_144(str) STRING_LITERAL_143(str), ((TERMINATED_143(str)) ? (str[143]) : ('\0'))
#define STRING_LITERAL_143(str) STRING_LITERAL_142(str), ((TERMINATED_142(str)) ? (str[142]) : ('\0'))
#define STRING_LITERAL_142(str) STRING_LITERAL_141(str), ((TERMINATED_141(str)) ? (str[141]) : ('\0'))
#define STRING_LITERAL_141(str) STRING_LITERAL_140(str), ((TERMINATED_140(str)) ? (str[140]) : ('\0'))
#define STRING_LITERAL_140(str) STRING_LITERAL_139(str), ((TERMINATED_139(str)) ? (str[139]) : ('\0'))
#define STRING_LITERAL_139(str) STRING_LITERAL_138(str), ((TERMINATED_138(str)) ? (str[138]) : ('\0'))
#define STRING_LITERAL_138(str) STRING_LITERAL_137(str), ((TERMINATED_137(str)) ? (str[137]) : ('\0'))

#define STRING_LITERAL_137(str) STRING_LITERAL_136(str), ((TERMINATED_136(str)) ? (str[136]) : ('\0'))
#define STRING_LITERAL_136(str) STRING_LITERAL_135(str), ((TERMINATED_135(str)) ? (str[135]) : ('\0'))
#define STRING_LITERAL_135(str) STRING_LITERAL_134(str), ((TERMINATED_134(str)) ? (str[134]) : ('\0'))
#define STRING_LITERAL_134(str) STRING_LITERAL_133(str), ((TERMINATED_133(str)) ? (str[133]) : ('\0'))
#define STRING_LITERAL_133(str) STRING_LITERAL_132(str), ((TERMINATED_132(str)) ? (str[132]) : ('\0'))
#define STRING_LITERAL_132(str) STRING_LITERAL_131(str), ((TERMINATED_131(str)) ? (str[131]) : ('\0'))
#define STRING_LITERAL_131(str) STRING_LITERAL_130(str), ((TERMINATED_130(str)) ? (str[130]) : ('\0'))
#define STRING_LITERAL_130(str) STRING_LITERAL_129(str), ((TERMINATED_129(str)) ? (str[129]) : ('\0'))
#define STRING_LITERAL_129(str) STRING_LITERAL_128(str), ((TERMINATED_128(str)) ? (str[128]) : ('\0'))
#define STRING_LITERAL_128(str) STRING_LITERAL_127(str), ((TERMINATED_127(str)) ? (str[127]) : ('\0'))
#define STRING_LITERAL_127(str) STRING_LITERAL_126(str), ((TERMINATED_126(str)) ? (str[126]) : ('\0'))
#define STRING_LITERAL_126(str) STRING_LITERAL_125(str), ((TERMINATED_125(str)) ? (str[125]) : ('\0'))
#define STRING_LITERAL_125(str) STRING_LITERAL_124(str), ((TERMINATED_124(str)) ? (str[124]) : ('\0'))
#define STRING_LITERAL_124(str) STRING_LITERAL_123(str), ((TERMINATED_123(str)) ? (str[123]) : ('\0'))
#define STRING_LITERAL_123(str) STRING_LITERAL_122(str), ((TERMINATED_122(str)) ? (str[122]) : ('\0'))
#define STRING_LITERAL_122(str) STRING_LITERAL_121(str), ((TERMINATED_121(str)) ? (str[121]) : ('\0'))
#define STRING_LITERAL_121(str) STRING_LITERAL_120(str), ((TERMINATED_120(str)) ? (str[120]) : ('\0'))
#define STRING_LITERAL_120(str) STRING_LITERAL_119(str), ((TERMINATED_119(str)) ? (str[119]) : ('\0'))
#define STRING_LITERAL_119(str) STRING_LITERAL_118(str), ((TERMINATED_118(str)) ? (str[118]) : ('\0'))
#define STRING_LITERAL_118(str) STRING_LITERAL_117(str), ((TERMINATED_117(str)) ? (str[117]) : ('\0'))
#define STRING_LITERAL_117(str) STRING_LITERAL_116(str), ((TERMINATED_116(str)) ? (str[116]) : ('\0'))
#define STRING_LITERAL_116(str) STRING_LITERAL_115(str), ((TERMINATED_115(str)) ? (str[115]) : ('\0'))
#define STRING_LITERAL_115(str) STRING_LITERAL_114(str), ((TERMINATED_114(str)) ? (str[114]) : ('\0'))
#define STRING_LITERAL_114(str) STRING_LITERAL_113(str), ((TERMINATED_113(str)) ? (str[113]) : ('\0'))
#define STRING_LITERAL_113(str) STRING_LITERAL_112(str), ((TERMINATED_112(str)) ? (str[112]) : ('\0'))
#define STRING_LITERAL_112(str) STRING_LITERAL_111(str), ((TERMINATED_111(str)) ? (str[111]) : ('\0'))
#define STRING_LITERAL_111(str) STRING_LITERAL_110(str), ((TERMINATED_110(str)) ? (str[110]) : ('\0'))
#define STRING_LITERAL_110(str) STRING_LITERAL_109(str), ((TERMINATED_109(str)) ? (str[109]) : ('\0'))
#define STRING_LITERAL_109(str) STRING_LITERAL_108(str), ((TERMINATED_108(str)) ? (str[108]) : ('\0'))
#define STRING_LITERAL_108(str) STRING_LITERAL_107(str), ((TERMINATED_107(str)) ? (str[107]) : ('\0'))
#define STRING_LITERAL_107(str) STRING_LITERAL_106(str), ((TERMINATED_106(str)) ? (str[106]) : ('\0'))
#define STRING_LITERAL_106(str) STRING_LITERAL_105(str), ((TERMINATED_105(str)) ? (str[105]) : ('\0'))
#define STRING_LITERAL_105(str) STRING_LITERAL_104(str), ((TERMINATED_104(str)) ? (str[104]) : ('\0'))
#define STRING_LITERAL_104(str) STRING_LITERAL_103(str), ((TERMINATED_103(str)) ? (str[103]) : ('\0'))
#define STRING_LITERAL_103(str) STRING_LITERAL_102(str), ((TERMINATED_102(str)) ? (str[102]) : ('\0'))
#define STRING_LITERAL_102(str) STRING_LITERAL_101(str), ((TERMINATED_101(str)) ? (str[101]) : ('\0'))
#define STRING_LITERAL_101(str) STRING_LITERAL_100(str), ((TERMINATED_100(str)) ? (str[100]) : ('\0'))
#define STRING_LITERAL_100(str) STRING_LITERAL_99(str), ((TERMINATED_99(str)) ? (str[99]) : ('\0'))
#define STRING_LITERAL_99(str) STRING_LITERAL_98(str), ((TERMINATED_98(str)) ? (str[98]) : ('\0'))
#define STRING_LITERAL_98(str) STRING_LITERAL_97(str), ((TERMINATED_97(str)) ? (str[97]) : ('\0'))
#define STRING_LITERAL_97(str) STRING_LITERAL_96(str), ((TERMINATED_96(str)) ? (str[96]) : ('\0'))
#define STRING_LITERAL_96(str) STRING_LITERAL_95(str), ((TERMINATED_95(str)) ? (str[95]) : ('\0'))
#define STRING_LITERAL_95(str) STRING_LITERAL_94(str), ((TERMINATED_94(str)) ? (str[94]) : ('\0'))
#define STRING_LITERAL_94(str) STRING_LITERAL_93(str), ((TERMINATED_93(str)) ? (str[93]) : ('\0'))
#define STRING_LITERAL_93(str) STRING_LITERAL_92(str), ((TERMINATED_92(str)) ? (str[92]) : ('\0'))
#define STRING_LITERAL_92(str) STRING_LITERAL_91(str), ((TERMINATED_91(str)) ? (str[91]) : ('\0'))
#define STRING_LITERAL_91(str) STRING_LITERAL_90(str), ((TERMINATED_90(str)) ? (str[90]) : ('\0'))
#define STRING_LITERAL_90(str) STRING_LITERAL_89(str), ((TERMINATED_89(str)) ? (str[89]) : ('\0'))
#define STRING_LITERAL_89(str) STRING_LITERAL_88(str), ((TERMINATED_88(str)) ? (str[88]) : ('\0'))
#define STRING_LITERAL_88(str) STRING_LITERAL_87(str), ((TERMINATED_87(str)) ? (str[87]) : ('\0'))
#define STRING_LITERAL_87(str) STRING_LITERAL_86(str), ((TERMINATED_86(str)) ? (str[86]) : ('\0'))
#define STRING_LITERAL_86(str) STRING_LITERAL_85(str), ((TERMINATED_85(str)) ? (str[85]) : ('\0'))
#define STRING_LITERAL_85(str) STRING_LITERAL_84(str), ((TERMINATED_84(str)) ? (str[84]) : ('\0'))
#define STRING_LITERAL_84(str) STRING_LITERAL_83(str), ((TERMINATED_83(str)) ? (str[83]) : ('\0'))
#define STRING_LITERAL_83(str) STRING_LITERAL_82(str), ((TERMINATED_82(str)) ? (str[82]) : ('\0'))
#define STRING_LITERAL_82(str) STRING_LITERAL_81(str), ((TERMINATED_81(str)) ? (str[81]) : ('\0'))
#define STRING_LITERAL_81(str) STRING_LITERAL_80(str), ((TERMINATED_80(str)) ? (str[80]) : ('\0'))
#define STRING_LITERAL_80(str) STRING_LITERAL_79(str), ((TERMINATED_79(str)) ? (str[79]) : ('\0'))
#define STRING_LITERAL_79(str) STRING_LITERAL_78(str), ((TERMINATED_78(str)) ? (str[78]) : ('\0'))
#define STRING_LITERAL_78(str) STRING_LITERAL_77(str), ((TERMINATED_77(str)) ? (str[77]) : ('\0'))
#define STRING_LITERAL_77(str) STRING_LITERAL_76(str), ((TERMINATED_76(str)) ? (str[76]) : ('\0'))
#define STRING_LITERAL_76(str) STRING_LITERAL_75(str), ((TERMINATED_75(str)) ? (str[75]) : ('\0'))
#define STRING_LITERAL_75(str) STRING_LITERAL_74(str), ((TERMINATED_74(str)) ? (str[74]) : ('\0'))
#define STRING_LITERAL_74(str) STRING_LITERAL_73(str), ((TERMINATED_73(str)) ? (str[73]) : ('\0'))
#define STRING_LITERAL_73(str) STRING_LITERAL_72(str), ((TERMINATED_72(str)) ? (str[72]) : ('\0'))
#define STRING_LITERAL_72(str) STRING_LITERAL_71(str), ((TERMINATED_71(str)) ? (str[71]) : ('\0'))
#define STRING_LITERAL_71(str) STRING_LITERAL_70(str), ((TERMINATED_70(str)) ? (str[70]) : ('\0'))

#define STRING_LITERAL_70(str) STRING_LITERAL_69(str), ((TERMINATED_69(str)) ? (str[69]) : ('\0'))
#define STRING_LITERAL_69(str) STRING_LITERAL_68(str), ((TERMINATED_68(str)) ? (str[68]) : ('\0'))
#define STRING_LITERAL_68(str) STRING_LITERAL_67(str), ((TERMINATED_67(str)) ? (str[67]) : ('\0'))
#define STRING_LITERAL_67(str) STRING_LITERAL_66(str), ((TERMINATED_66(str)) ? (str[66]) : ('\0'))
#define STRING_LITERAL_66(str) STRING_LITERAL_65(str), ((TERMINATED_65(str)) ? (str[65]) : ('\0'))
#define STRING_LITERAL_65(str) STRING_LITERAL_64(str), ((TERMINATED_64(str)) ? (str[64]) : ('\0'))
#define STRING_LITERAL_64(str) STRING_LITERAL_63(str), ((TERMINATED_63(str)) ? (str[63]) : ('\0'))
#define STRING_LITERAL_63(str) STRING_LITERAL_62(str), ((TERMINATED_62(str)) ? (str[62]) : ('\0'))
#define STRING_LITERAL_62(str) STRING_LITERAL_61(str), ((TERMINATED_61(str)) ? (str[61]) : ('\0'))
#define STRING_LITERAL_61(str) STRING_LITERAL_60(str), ((TERMINATED_60(str)) ? (str[60]) : ('\0'))
#define STRING_LITERAL_60(str) STRING_LITERAL_59(str), ((TERMINATED_59(str)) ? (str[59]) : ('\0'))
#define STRING_LITERAL_59(str) STRING_LITERAL_58(str), ((TERMINATED_58(str)) ? (str[58]) : ('\0'))
#define STRING_LITERAL_58(str) STRING_LITERAL_57(str), ((TERMINATED_57(str)) ? (str[57]) : ('\0'))
#define STRING_LITERAL_57(str) STRING_LITERAL_56(str), ((TERMINATED_56(str)) ? (str[56]) : ('\0'))
#define STRING_LITERAL_56(str) STRING_LITERAL_55(str), ((TERMINATED_55(str)) ? (str[55]) : ('\0'))
#define STRING_LITERAL_55(str) STRING_LITERAL_54(str), ((TERMINATED_54(str)) ? (str[54]) : ('\0'))
#define STRING_LITERAL_54(str) STRING_LITERAL_53(str), ((TERMINATED_53(str)) ? (str[53]) : ('\0'))
#define STRING_LITERAL_53(str) STRING_LITERAL_52(str), ((TERMINATED_52(str)) ? (str[52]) : ('\0'))
#define STRING_LITERAL_52(str) STRING_LITERAL_51(str), ((TERMINATED_51(str)) ? (str[51]) : ('\0'))
#define STRING_LITERAL_51(str) STRING_LITERAL_50(str), ((TERMINATED_50(str)) ? (str[50]) : ('\0'))
#define STRING_LITERAL_50(str) STRING_LITERAL_49(str), ((TERMINATED_49(str)) ? (str[49]) : ('\0'))
#define STRING_LITERAL_49(str) STRING_LITERAL_48(str), ((TERMINATED_48(str)) ? (str[48]) : ('\0'))
#define STRING_LITERAL_48(str) STRING_LITERAL_47(str), ((TERMINATED_47(str)) ? (str[47]) : ('\0'))
#define STRING_LITERAL_47(str) STRING_LITERAL_46(str), ((TERMINATED_46(str)) ? (str[46]) : ('\0'))
#define STRING_LITERAL_46(str) STRING_LITERAL_45(str), ((TERMINATED_45(str)) ? (str[45]) : ('\0'))
#define STRING_LITERAL_45(str) STRING_LITERAL_44(str), ((TERMINATED_44(str)) ? (str[44]) : ('\0'))
#define STRING_LITERAL_44(str) STRING_LITERAL_43(str), ((TERMINATED_43(str)) ? (str[43]) : ('\0'))
#define STRING_LITERAL_43(str) STRING_LITERAL_42(str), ((TERMINATED_42(str)) ? (str[42]) : ('\0'))
#define STRING_LITERAL_42(str) STRING_LITERAL_41(str), ((TERMINATED_41(str)) ? (str[41]) : ('\0'))
#define STRING_LITERAL_41(str) STRING_LITERAL_40(str), ((TERMINATED_40(str)) ? (str[40]) : ('\0'))
#define STRING_LITERAL_40(str) STRING_LITERAL_39(str), ((TERMINATED_39(str)) ? (str[39]) : ('\0'))
#define STRING_LITERAL_39(str) STRING_LITERAL_38(str), ((TERMINATED_38(str)) ? (str[38]) : ('\0'))
#define STRING_LITERAL_38(str) STRING_LITERAL_37(str), ((TERMINATED_37(str)) ? (str[37]) : ('\0'))
#define STRING_LITERAL_37(str) STRING_LITERAL_36(str), ((TERMINATED_36(str)) ? (str[36]) : ('\0'))
#define STRING_LITERAL_36(str) STRING_LITERAL_35(str), ((TERMINATED_35(str)) ? (str[35]) : ('\0'))
#define STRING_LITERAL_35(str) STRING_LITERAL_34(str), ((TERMINATED_34(str)) ? (str[34]) : ('\0'))
#define STRING_LITERAL_34(str) STRING_LITERAL_33(str), ((TERMINATED_33(str)) ? (str[33]) : ('\0'))
#define STRING_LITERAL_33(str) STRING_LITERAL_32(str), ((TERMINATED_32(str)) ? (str[32]) : ('\0'))
#define STRING_LITERAL_32(str) STRING_LITERAL_31(str), ((TERMINATED_31(str)) ? (str[31]) : ('\0'))
#define STRING_LITERAL_31(str) STRING_LITERAL_30(str), ((TERMINATED_30(str)) ? (str[30]) : ('\0'))
#define STRING_LITERAL_30(str) STRING_LITERAL_29(str), ((TERMINATED_29(str)) ? (str[29]) : ('\0'))
#define STRING_LITERAL_29(str) STRING_LITERAL_28(str), ((TERMINATED_28(str)) ? (str[28]) : ('\0'))
#define STRING_LITERAL_28(str) STRING_LITERAL_27(str), ((TERMINATED_27(str)) ? (str[27]) : ('\0'))
#define STRING_LITERAL_27(str) STRING_LITERAL_26(str), ((TERMINATED_26(str)) ? (str[26]) : ('\0'))
#define STRING_LITERAL_26(str) STRING_LITERAL_25(str), ((TERMINATED_25(str)) ? (str[25]) : ('\0'))
#define STRING_LITERAL_25(str) STRING_LITERAL_24(str), ((TERMINATED_24(str)) ? (str[24]) : ('\0'))
#define STRING_LITERAL_24(str) STRING_LITERAL_23(str), ((TERMINATED_23(str)) ? (str[23]) : ('\0'))
#define STRING_LITERAL_23(str) STRING_LITERAL_22(str), ((TERMINATED_22(str)) ? (str[22]) : ('\0'))
#define STRING_LITERAL_22(str) STRING_LITERAL_21(str), ((TERMINATED_21(str)) ? (str[21]) : ('\0'))
#define STRING_LITERAL_21(str) STRING_LITERAL_20(str), ((TERMINATED_20(str)) ? (str[20]) : ('\0'))
#define STRING_LITERAL_20(str) STRING_LITERAL_19(str), ((TERMINATED_19(str)) ? (str[19]) : ('\0'))
#define STRING_LITERAL_19(str) STRING_LITERAL_18(str), ((TERMINATED_18(str)) ? (str[18]) : ('\0'))
#define STRING_LITERAL_18(str) STRING_LITERAL_17(str), ((TERMINATED_17(str)) ? (str[17]) : ('\0'))
#define STRING_LITERAL_17(str) STRING_LITERAL_16(str), ((TERMINATED_16(str)) ? (str[16]) : ('\0'))
#define STRING_LITERAL_16(str) STRING_LITERAL_15(str), ((TERMINATED_15(str)) ? (str[15]) : ('\0'))
#define STRING_LITERAL_15(str) STRING_LITERAL_14(str), ((TERMINATED_14(str)) ? (str[14]) : ('\0'))
#define STRING_LITERAL_14(str) STRING_LITERAL_13(str), ((TERMINATED_13(str)) ? (str[13]) : ('\0'))
#define STRING_LITERAL_13(str) STRING_LITERAL_12(str), ((TERMINATED_12(str)) ? (str[12]) : ('\0'))
#define STRING_LITERAL_12(str) STRING_LITERAL_11(str), ((TERMINATED_11(str)) ? (str[11]) : ('\0'))
#define STRING_LITERAL_11(str) STRING_LITERAL_10(str), ((TERMINATED_10(str)) ? (str[10]) : ('\0'))
#define STRING_LITERAL_10(str) STRING_LITERAL_9(str), ((TERMINATED_9(str)) ? (str[9]) : ('\0'))
#define STRING_LITERAL_9(str) STRING_LITERAL_8(str), ((TERMINATED_8(str)) ? (str[8]) : ('\0'))
#define STRING_LITERAL_8(str) STRING_LITERAL_7(str), ((TERMINATED_7(str)) ? (str[7]) : ('\0'))
#define STRING_LITERAL_7(str) STRING_LITERAL_6(str), ((TERMINATED_6(str)) ? (str[6]) : ('\0'))
#define STRING_LITERAL_6(str) STRING_LITERAL_5(str), ((TERMINATED_5(str)) ? (str[5]) : ('\0'))
#define STRING_LITERAL_5(str) STRING_LITERAL_4(str), ((TERMINATED_4(str)) ? (str[4]) : ('\0'))
#define STRING_LITERAL_4(str) STRING_LITERAL_3(str), ((TERMINATED_3(str)) ? (str[3]) : ('\0'))
#define STRING_LITERAL_3(str) STRING_LITERAL_2(str), ((TERMINATED_2(str)) ? (str[2]) : ('\0'))
#define STRING_LITERAL_2(str) STRING_LITERAL_1(str), ((TERMINATED_1(str)) ? (str[1]) : ('\0'))
#define STRING_LITERAL_1(str) str[0]

#define TERMINATED_250(str) TERMINATED_249(str) && str[249]
#define TERMINATED_249(str) TERMINATED_248(str) && str[248]
#define TERMINATED_248(str) TERMINATED_247(str) && str[247]
#define TERMINATED_247(str) TERMINATED_246(str) && str[246]
#define TERMINATED_246(str) TERMINATED_245(str) && str[245]
#define TERMINATED_245(str) TERMINATED_244(str) && str[244]
#define TERMINATED_244(str) TERMINATED_243(str) && str[243]
#define TERMINATED_243(str) TERMINATED_242(str) && str[242]
#define TERMINATED_242(str) TERMINATED_241(str) && str[241]
#define TERMINATED_241(str) TERMINATED_240(str) && str[240]
#define TERMINATED_240(str) TERMINATED_239(str) && str[239]
#define TERMINATED_239(str) TERMINATED_238(str) && str[238]
#define TERMINATED_238(str) TERMINATED_237(str) && str[237]
#define TERMINATED_237(str) TERMINATED_236(str) && str[236]
#define TERMINATED_236(str) TERMINATED_235(str) && str[235]
#define TERMINATED_235(str) TERMINATED_234(str) && str[234]
#define TERMINATED_234(str) TERMINATED_233(str) && str[233]
#define TERMINATED_233(str) TERMINATED_232(str) && str[232]
#define TERMINATED_232(str) TERMINATED_231(str) && str[231]
#define TERMINATED_231(str) TERMINATED_230(str) && str[230]
#define TERMINATED_230(str) TERMINATED_229(str) && str[229]
#define TERMINATED_229(str) TERMINATED_228(str) && str[228]
#define TERMINATED_228(str) TERMINATED_227(str) && str[227]
#define TERMINATED_227(str) TERMINATED_226(str) && str[226]
#define TERMINATED_226(str) TERMINATED_225(str) && str[225]
#define TERMINATED_225(str) TERMINATED_224(str) && str[224]
#define TERMINATED_224(str) TERMINATED_223(str) && str[223]
#define TERMINATED_223(str) TERMINATED_222(str) && str[222]
#define TERMINATED_222(str) TERMINATED_221(str) && str[221]
#define TERMINATED_221(str) TERMINATED_220(str) && str[220]
#define TERMINATED_220(str) TERMINATED_219(str) && str[219]
#define TERMINATED_219(str) TERMINATED_218(str) && str[218]
#define TERMINATED_218(str) TERMINATED_217(str) && str[217]
#define TERMINATED_217(str) TERMINATED_216(str) && str[216]
#define TERMINATED_216(str) TERMINATED_215(str) && str[215]
#define TERMINATED_215(str) TERMINATED_214(str) && str[214]
#define TERMINATED_214(str) TERMINATED_213(str) && str[213]
#define TERMINATED_213(str) TERMINATED_212(str) && str[212]
#define TERMINATED_212(str) TERMINATED_211(str) && str[211]
#define TERMINATED_211(str) TERMINATED_210(str) && str[210]
#define TERMINATED_210(str) TERMINATED_209(str) && str[209]
#define TERMINATED_209(str) TERMINATED_208(str) && str[208]
#define TERMINATED_208(str) TERMINATED_207(str) && str[207]
#define TERMINATED_207(str) TERMINATED_206(str) && str[206]
#define TERMINATED_206(str) TERMINATED_205(str) && str[205]
#define TERMINATED_205(str) TERMINATED_204(str) && str[204]
#define TERMINATED_204(str) TERMINATED_203(str) && str[203]
#define TERMINATED_203(str) TERMINATED_202(str) && str[202]
#define TERMINATED_202(str) TERMINATED_201(str) && str[201]
#define TERMINATED_201(str) TERMINATED_200(str) && str[200]
#define TERMINATED_200(str) TERMINATED_199(str) && str[199]
#define TERMINATED_199(str) TERMINATED_198(str) && str[198]
#define TERMINATED_198(str) TERMINATED_197(str) && str[197]
#define TERMINATED_197(str) TERMINATED_196(str) && str[196]
#define TERMINATED_196(str) TERMINATED_195(str) && str[195]
#define TERMINATED_195(str) TERMINATED_194(str) && str[194]
#define TERMINATED_194(str) TERMINATED_193(str) && str[193]
#define TERMINATED_193(str) TERMINATED_192(str) && str[192]
#define TERMINATED_192(str) TERMINATED_191(str) && str[191]
#define TERMINATED_191(str) TERMINATED_190(str) && str[190]
#define TERMINATED_190(str) TERMINATED_189(str) && str[189]
#define TERMINATED_189(str) TERMINATED_188(str) && str[188]
#define TERMINATED_188(str) TERMINATED_187(str) && str[187]
#define TERMINATED_187(str) TERMINATED_186(str) && str[186]
#define TERMINATED_186(str) TERMINATED_185(str) && str[185]
#define TERMINATED_185(str) TERMINATED_184(str) && str[184]
#define TERMINATED_184(str) TERMINATED_183(str) && str[183]
#define TERMINATED_183(str) TERMINATED_182(str) && str[182]
#define TERMINATED_182(str) TERMINATED_181(str) && str[181]
#define TERMINATED_181(str) TERMINATED_180(str) && str[180]
#define TERMINATED_180(str) TERMINATED_179(str) && str[179]
#define TERMINATED_179(str) TERMINATED_178(str) && str[178]
#define TERMINATED_178(str) TERMINATED_177(str) && str[177]
#define TERMINATED_177(str) TERMINATED_176(str) && str[176]
#define TERMINATED_176(str) TERMINATED_175(str) && str[175]
#define TERMINATED_175(str) TERMINATED_174(str) && str[174]
#define TERMINATED_174(str) TERMINATED_173(str) && str[173]
#define TERMINATED_173(str) TERMINATED_172(str) && str[172]
#define TERMINATED_172(str) TERMINATED_171(str) && str[171]
#define TERMINATED_171(str) TERMINATED_170(str) && str[170]
#define TERMINATED_170(str) TERMINATED_169(str) && str[169]
#define TERMINATED_169(str) TERMINATED_168(str) && str[168]
#define TERMINATED_168(str) TERMINATED_167(str) && str[167]
#define TERMINATED_167(str) TERMINATED_166(str) && str[166]
#define TERMINATED_166(str) TERMINATED_165(str) && str[165]
#define TERMINATED_165(str) TERMINATED_164(str) && str[164]
#define TERMINATED_164(str) TERMINATED_163(str) && str[163]
#define TERMINATED_163(str) TERMINATED_162(str) && str[162]
#define TERMINATED_162(str) TERMINATED_161(str) && str[161]
#define TERMINATED_161(str) TERMINATED_160(str) && str[160]
#define TERMINATED_160(str) TERMINATED_159(str) && str[159]
#define TERMINATED_159(str) TERMINATED_158(str) && str[158]
#define TERMINATED_158(str) TERMINATED_157(str) && str[157]
#define TERMINATED_157(str) TERMINATED_156(str) && str[156]
#define TERMINATED_156(str) TERMINATED_155(str) && str[155]
#define TERMINATED_155(str) TERMINATED_154(str) && str[154]
#define TERMINATED_154(str) TERMINATED_153(str) && str[153]
#define TERMINATED_153(str) TERMINATED_152(str) && str[152]
#define TERMINATED_152(str) TERMINATED_151(str) && str[151]
#define TERMINATED_151(str) TERMINATED_150(str) && str[150]

#define TERMINATED_150(str) TERMINATED_149(str) && str[149]
#define TERMINATED_149(str) TERMINATED_148(str) && str[148]
#define TERMINATED_148(str) TERMINATED_147(str) && str[147]
#define TERMINATED_147(str) TERMINATED_146(str) && str[146]
#define TERMINATED_146(str) TERMINATED_145(str) && str[145]
#define TERMINATED_145(str) TERMINATED_144(str) && str[144]
#define TERMINATED_144(str) TERMINATED_143(str) && str[143]
#define TERMINATED_143(str) TERMINATED_142(str) && str[142]
#define TERMINATED_142(str) TERMINATED_141(str) && str[141]
#define TERMINATED_141(str) TERMINATED_140(str) && str[140]
#define TERMINATED_140(str) TERMINATED_139(str) && str[139]
#define TERMINATED_139(str) TERMINATED_138(str) && str[138]
#define TERMINATED_138(str) TERMINATED_137(str) && str[137]

#define TERMINATED_137(str) TERMINATED_136(str) && str[136]
#define TERMINATED_136(str) TERMINATED_135(str) && str[135]
#define TERMINATED_135(str) TERMINATED_134(str) && str[134]
#define TERMINATED_134(str) TERMINATED_133(str) && str[133]
#define TERMINATED_133(str) TERMINATED_132(str) && str[132]
#define TERMINATED_132(str) TERMINATED_131(str) && str[131]
#define TERMINATED_131(str) TERMINATED_130(str) && str[130]
#define TERMINATED_130(str) TERMINATED_129(str) && str[129]
#define TERMINATED_129(str) TERMINATED_128(str) && str[128]
#define TERMINATED_128(str) TERMINATED_127(str) && str[127]
#define TERMINATED_127(str) TERMINATED_126(str) && str[126]
#define TERMINATED_126(str) TERMINATED_125(str) && str[125]
#define TERMINATED_125(str) TERMINATED_124(str) && str[124]
#define TERMINATED_124(str) TERMINATED_123(str) && str[123]
#define TERMINATED_123(str) TERMINATED_122(str) && str[122]
#define TERMINATED_122(str) TERMINATED_121(str) && str[121]
#define TERMINATED_121(str) TERMINATED_120(str) && str[120]
#define TERMINATED_120(str) TERMINATED_119(str) && str[119]
#define TERMINATED_119(str) TERMINATED_118(str) && str[118]
#define TERMINATED_118(str) TERMINATED_117(str) && str[117]
#define TERMINATED_117(str) TERMINATED_116(str) && str[116]
#define TERMINATED_116(str) TERMINATED_115(str) && str[115]
#define TERMINATED_115(str) TERMINATED_114(str) && str[114]
#define TERMINATED_114(str) TERMINATED_113(str) && str[113]
#define TERMINATED_113(str) TERMINATED_112(str) && str[112]
#define TERMINATED_112(str) TERMINATED_111(str) && str[111]
#define TERMINATED_111(str) TERMINATED_110(str) && str[110]
#define TERMINATED_110(str) TERMINATED_109(str) && str[109]
#define TERMINATED_109(str) TERMINATED_108(str) && str[108]
#define TERMINATED_108(str) TERMINATED_107(str) && str[107]
#define TERMINATED_107(str) TERMINATED_106(str) && str[106]
#define TERMINATED_106(str) TERMINATED_105(str) && str[105]
#define TERMINATED_105(str) TERMINATED_104(str) && str[104]
#define TERMINATED_104(str) TERMINATED_103(str) && str[103]
#define TERMINATED_103(str) TERMINATED_102(str) && str[102]
#define TERMINATED_102(str) TERMINATED_101(str) && str[101]
#define TERMINATED_101(str) TERMINATED_100(str) && str[100]
#define TERMINATED_100(str) TERMINATED_99(str) && str[99]
#define TERMINATED_99(str) TERMINATED_98(str) && str[98]
#define TERMINATED_98(str) TERMINATED_97(str) && str[97]
#define TERMINATED_97(str) TERMINATED_96(str) && str[96]
#define TERMINATED_96(str) TERMINATED_95(str) && str[95]
#define TERMINATED_95(str) TERMINATED_94(str) && str[94]
#define TERMINATED_94(str) TERMINATED_93(str) && str[93]
#define TERMINATED_93(str) TERMINATED_92(str) && str[92]
#define TERMINATED_92(str) TERMINATED_91(str) && str[91]
#define TERMINATED_91(str) TERMINATED_90(str) && str[90]
#define TERMINATED_90(str) TERMINATED_89(str) && str[89]
#define TERMINATED_89(str) TERMINATED_88(str) && str[88]
#define TERMINATED_88(str) TERMINATED_87(str) && str[87]
#define TERMINATED_87(str) TERMINATED_86(str) && str[86]
#define TERMINATED_86(str) TERMINATED_85(str) && str[85]
#define TERMINATED_85(str) TERMINATED_84(str) && str[84]
#define TERMINATED_84(str) TERMINATED_83(str) && str[83]
#define TERMINATED_83(str) TERMINATED_82(str) && str[82]
#define TERMINATED_82(str) TERMINATED_81(str) && str[81]
#define TERMINATED_81(str) TERMINATED_80(str) && str[80]
#define TERMINATED_80(str) TERMINATED_79(str) && str[79]
#define TERMINATED_79(str) TERMINATED_78(str) && str[78]
#define TERMINATED_78(str) TERMINATED_77(str) && str[77]
#define TERMINATED_77(str) TERMINATED_76(str) && str[76]
#define TERMINATED_76(str) TERMINATED_75(str) && str[75]
#define TERMINATED_75(str) TERMINATED_74(str) && str[74]
#define TERMINATED_74(str) TERMINATED_73(str) && str[73]
#define TERMINATED_73(str) TERMINATED_72(str) && str[72]
#define TERMINATED_72(str) TERMINATED_71(str) && str[71]
#define TERMINATED_71(str) TERMINATED_70(str) && str[70]

#define TERMINATED_70(str) TERMINATED_69(str) && str[69]
#define TERMINATED_69(str) TERMINATED_68(str) && str[68]
#define TERMINATED_68(str) TERMINATED_67(str) && str[67]
#define TERMINATED_67(str) TERMINATED_66(str) && str[66]
#define TERMINATED_66(str) TERMINATED_65(str) && str[65]
#define TERMINATED_65(str) TERMINATED_64(str) && str[64]
#define TERMINATED_64(str) TERMINATED_63(str) && str[63]
#define TERMINATED_63(str) TERMINATED_62(str) && str[62]
#define TERMINATED_62(str) TERMINATED_61(str) && str[61]
#define TERMINATED_61(str) TERMINATED_60(str) && str[60]
#define TERMINATED_60(str) TERMINATED_59(str) && str[59]
#define TERMINATED_59(str) TERMINATED_58(str) && str[58]
#define TERMINATED_58(str) TERMINATED_57(str) && str[57]
#define TERMINATED_57(str) TERMINATED_56(str) && str[56]
#define TERMINATED_56(str) TERMINATED_55(str) && str[55]
#define TERMINATED_55(str) TERMINATED_54(str) && str[54]
#define TERMINATED_54(str) TERMINATED_53(str) && str[53]
#define TERMINATED_53(str) TERMINATED_52(str) && str[52]
#define TERMINATED_52(str) TERMINATED_51(str) && str[51]
#define TERMINATED_51(str) TERMINATED_50(str) && str[50]
#define TERMINATED_50(str) TERMINATED_49(str) && str[49]
#define TERMINATED_49(str) TERMINATED_48(str) && str[48]
#define TERMINATED_48(str) TERMINATED_47(str) && str[47]
#define TERMINATED_47(str) TERMINATED_46(str) && str[46]
#define TERMINATED_46(str) TERMINATED_45(str) && str[45]
#define TERMINATED_45(str) TERMINATED_44(str) && str[44]
#define TERMINATED_44(str) TERMINATED_43(str) && str[43]
#define TERMINATED_43(str) TERMINATED_42(str) && str[42]
#define TERMINATED_42(str) TERMINATED_41(str) && str[41]
#define TERMINATED_41(str) TERMINATED_40(str) && str[40]
#define TERMINATED_40(str) TERMINATED_39(str) && str[39]
#define TERMINATED_39(str) TERMINATED_38(str) && str[38]
#define TERMINATED_38(str) TERMINATED_37(str) && str[37]
#define TERMINATED_37(str) TERMINATED_36(str) && str[36]
#define TERMINATED_36(str) TERMINATED_35(str) && str[35]
#define TERMINATED_35(str) TERMINATED_34(str) && str[34]
#define TERMINATED_34(str) TERMINATED_33(str) && str[33]
#define TERMINATED_33(str) TERMINATED_32(str) && str[32]
#define TERMINATED_32(str) TERMINATED_31(str) && str[31]
#define TERMINATED_31(str) TERMINATED_30(str) && str[30]
#define TERMINATED_30(str) TERMINATED_29(str) && str[29]
#define TERMINATED_29(str) TERMINATED_28(str) && str[28]
#define TERMINATED_28(str) TERMINATED_27(str) && str[27]
#define TERMINATED_27(str) TERMINATED_26(str) && str[26]
#define TERMINATED_26(str) TERMINATED_25(str) && str[25]
#define TERMINATED_25(str) TERMINATED_24(str) && str[24]
#define TERMINATED_24(str) TERMINATED_23(str) && str[23]
#define TERMINATED_23(str) TERMINATED_22(str) && str[22]
#define TERMINATED_22(str) TERMINATED_21(str) && str[21]
#define TERMINATED_21(str) TERMINATED_20(str) && str[20]
#define TERMINATED_20(str) TERMINATED_19(str) && str[19]
#define TERMINATED_19(str) TERMINATED_18(str) && str[18]
#define TERMINATED_18(str) TERMINATED_17(str) && str[17]
#define TERMINATED_17(str) TERMINATED_16(str) && str[16]
#define TERMINATED_16(str) TERMINATED_15(str) && str[15]
#define TERMINATED_15(str) TERMINATED_14(str) && str[14]
#define TERMINATED_14(str) TERMINATED_13(str) && str[13]
#define TERMINATED_13(str) TERMINATED_12(str) && str[12]
#define TERMINATED_12(str) TERMINATED_11(str) && str[11]
#define TERMINATED_11(str) TERMINATED_10(str) && str[10]
#define TERMINATED_10(str) TERMINATED_9(str) && str[9]
#define TERMINATED_9(str) TERMINATED_8(str) && str[8]
#define TERMINATED_8(str) TERMINATED_7(str) && str[7]
#define TERMINATED_7(str) TERMINATED_6(str) && str[6]
#define TERMINATED_6(str) TERMINATED_5(str) && str[5]
#define TERMINATED_5(str) TERMINATED_4(str) && str[4]
#define TERMINATED_4(str) TERMINATED_3(str) && str[3]
#define TERMINATED_3(str) TERMINATED_2(str) && str[2]
#define TERMINATED_2(str) TERMINATED_1(str) && str[1]
#define TERMINATED_1(str) str[0]

template<char... Cs>
struct char_pack {
    static constexpr char const arr[sizeof...(Cs) + 1] = {Cs..., 0};
    static constexpr std::size_t non_zero_count = (((Cs != 0) ? 1 : 0) + ...);
    // static_assert(non_zero_count < MAX_STRING_LITERAL_LENGTH, "You need to create more macros");
};

template<char... Cs>
constexpr char const char_pack<Cs...>::arr[sizeof...(Cs) + 1];

template<char... Cs>
constexpr std::size_t char_pack<Cs...>::non_zero_count;

template<class CP, class = void, class = std::make_index_sequence<CP::non_zero_count>>
struct string_literal;

template<char... Cs, std::size_t... Is>
struct string_literal<char_pack<Cs...>, std::enable_if_t<(Cs && ...)>, std::index_sequence<Is...>> {
    static constexpr char const s[sizeof...(Cs) + 1] = {Cs..., '\0'};
};

template<char... Cs, std::size_t... Is>
constexpr char const
    string_literal<char_pack<Cs...>, std::enable_if_t<(Cs && ...)>, std::index_sequence<Is...>>::s[sizeof...(Cs) + 1];

template<char... Cs, std::size_t... Is>
struct string_literal<char_pack<Cs...>, std::enable_if_t<!(Cs && ...)>, std::index_sequence<Is...>>
    : string_literal<char_pack<char_pack<Cs...>::arr[Is]...>> { };
namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Evaluate an RPN expression
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/expr.rs#L467
                // Input: RPN expression E, variables values V
                // Output: E(V) \in F_r
                template<typename ArithmetizationType, typename KimchiParamsType, const char *Expression,
                    std::size_t... WireIndexes>
                class rpn_expression;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         const char *Expression, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class rpn_expression<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                     KimchiParamsType, Expression, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                     W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, typename KimchiParamsType::curve_type,
                                                    KimchiParamsType::scalar_challenge_size, W0, W1, W2, W3, W4, W5, W6,
                                                    W7, W8, W9, W10, W11, W12, W13, W14>;

                    using poseidon_component = zk::components::poseidon<ArithmetizationType, BlueprintFieldType, 0, 1,
                                                                        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using exponentiation_component =
                        zk::components::exponentiation<ArithmetizationType, 64, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                       W10, W11, W12, W13, W14>;

                    using evaluations_type =
                        typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>;

                    constexpr static const std::size_t selector_seed = 0x0f31;

                    constexpr static const std::size_t mds_size = 3;

                    static std::array<std::array<var, mds_size>, mds_size> mds_vars(const std::size_t start_row) {
                        std::array<std::array<var, mds_size>, mds_size> result;
                        std::size_t mds_start_row = start_row;

                        for (std::size_t i = 0; i < mds_size; ++i) {
                            for (std::size_t j = 0; j < mds_size; ++j) {
                                result[i][j] =
                                    var(0, mds_start_row + i * mds_size + j, false, var::column_type::constant);
                            }
                        }
                        return result;
                    }

                    static var var_from_evals(const std::array<evaluations_type, KimchiParamsType::eval_points_amount>
                                                  evaluations,
                                              const std::size_t var_column,
                                              const std::size_t var_row) {
                        auto evals = evaluations[var_row];

                        /// 0 - witness_columns: witnesses
                        /// witness_columns + 1: z
                        /// witness_columns + 2: PoseidonSelector
                        /// witness_columns + 3: GenericSelector
                        /// witness_columns + 4: LookupAggreg
                        /// witness_columns + 5: LookupTable
                        /// witness_columns + 6: LookupRuntimeTable
                        /// witness_columns + 7+: LookupSorted

                        if (var_column < KimchiParamsType::witness_columns) {
                            return evals.w[var_column];
                        }

                        switch (var_column) {
                            case KimchiParamsType::witness_columns + 1:
                                return evals.z;
                            case KimchiParamsType::witness_columns + 2:
                                return evals.poseidon_selector;
                            case KimchiParamsType::witness_columns + 3:
                                return evals.generic_selector;
                            case KimchiParamsType::witness_columns + 4:
                                // TODO: lookups
                                return evals.z;
                            case KimchiParamsType::witness_columns + 5:
                                // TODO: lookups
                                return evals.z;
                            case KimchiParamsType::witness_columns + 6:
                                // TODO: lookups
                                return evals.z;
                            case KimchiParamsType::witness_columns + 7:
                                // TODO: lookups
                                return evals.z;
                            default:
                                throw std::runtime_error("Unknown column type");
                        }
                    }

                public:
                    constexpr static const std::string_view expression = Expression;
                    constexpr static std::size_t count_delimiters() {
                        size_t i = 0;
                        size_t cnt = 0;
                        for (; expression[i] != '\0'; i++) {
                            if (expression[i] == ';') {
                                cnt++;
                            }
                        }
                        return cnt;
                    }

                    constexpr static std::size_t strlen() {
                        size_t size = 0;
                        for (; expression[size] != '\0'; size++) {
                        }
                        return size;
                    }

                    constexpr static std::size_t find_str(const char *str, std::size_t n, std::size_t start_pos,
                                                          std::size_t end_pos) {
                        size_t j = 0;
                        size_t i = start_pos;
                        for (; i < end_pos; i++) {
                            for (j = 0; j < n && expression[i + j] == str[j]; j++)
                                ;
                            if (j == n) {
                                return i;
                            }
                        }
                        return std::string::npos;
                    }

                    constexpr static const std::size_t tokens_array_size = count_delimiters();
                    constexpr static const std::size_t literal_string_size = strlen();

                    constexpr static size_t rows() {
                        std::array<std::size_t, tokens_array_size> str_start = {};

                        std::array<std::size_t, tokens_array_size> str_end = {};
                        str_start[0] = 0;
                        str_end[tokens_array_size - 1] = literal_string_size;
                        size_t i = 0;
                        const char *alpha_c = "Alpha";
                        const char *beta_c = "Beta";
                        const char *gamma_c = "Gamma";
                        const char *joint_combiner_c = "JointCombiner";
                        const char *endo_coefficient_c = "EndoCoefficient";
                        const char *mds_c = "Mds";
                        const char *literal_c = "Literal";
                        const char *cell_c = "Cell";
                        const char *dup_c = "Dup";
                        const char *pow_c = "Pow";
                        const char *add_c = "Add";
                        const char *mul_c = "Mul";
                        const char *sub_c = "Sub";
                        const char *vanishes_on_last_4_rows_c = "VanishesOnLast4Rows";
                        const char *unnormalized_lagrange_basis_c = "UnnormalizedLagrangeBasis";
                        const char *store_c = "Store";
                        const char *load_c = "Load";
                        const char *del = ";";
                        for (i = 0; i < tokens_array_size - 1; i++) {
                            size_t pos = find_str(del, 1, str_start[i], literal_string_size);
                            str_end[i] = pos;
                            str_start[i + 1] = pos + 1;
                        }
                        size_t rows = 0;
                        size_t constant_rows = 3 + mds_size * mds_size;
                        for (i = 0; i < tokens_array_size; i++) {
                            if (find_str(literal_c, 7, str_start[i], str_end[i]) != std::string::npos) {
                                constant_rows++;
                            } else if (find_str(pow_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                                rows += exponentiation_component::rows_amount;
                                constant_rows++;
                            } else if (find_str(add_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                                rows += add_component::rows_amount;
                            } else if (find_str(mul_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                                rows += mul_component::rows_amount;
                            } else if (find_str(sub_c, 3, str_start[i], str_end[i]) != std::string::npos) {
                                rows += sub_component::rows_amount;
                            }
                        }

                        size_t res = std::max(rows, constant_rows);
                        return res;
                    }
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    enum token_type {
                        alpha,
                        beta,
                        gamma,
                        joint_combiner,
                        endo_coefficient,
                        mds,
                        literal,
                        cell,
                        dup,
                        pow,
                        add,
                        mul,
                        sub,
                        vanishes_on_last_4_rows,
                        unnormalized_lagrange_basis,
                        store,
                        load
                    };

                    struct params_type {
                        struct token_value_type {
                            token_type type;
                            std::pair<typename BlueprintFieldType::value_type, typename BlueprintFieldType::value_type>
                                value;
                        };

                        std::vector<token_value_type> tokens;

                        var alpha;
                        var beta;
                        var gamma;
                        var joint_combiner;

                        std::array<evaluations_type, KimchiParamsType::eval_points_amount> evaluations;
                    };

                    static std::vector<typename params_type::token_value_type> rpn_from_string() {

                        std::vector<std::string> tokens_str;
                        boost::split(tokens_str, expression, boost::is_any_of(";"));
                        for(std::size_t i = 0; i < tokens_str.size(); i++) {
                            boost::trim(tokens_str[i]);
                        }

                        std::vector<typename params_type::token_value_type> tokens;
                        for(std::size_t i = 0; i < tokens_str.size(); i++) {

                            std::string token_str = tokens_str[i];
                            if (token_str.empty()) {
                                continue;
                            }

                            typename params_type::token_value_type token;

                            if (token_str.find("Alpha") != std::string::npos) {
                                token.type = token_type::alpha;
                            } else if (token_str.find("Beta") != std::string::npos) {
                                token.type = token_type::beta;
                            } else if (token_str.find("Gamma") != std::string::npos) {
                                token.type = token_type::gamma;
                            } else if (token_str.find("JointCombiner") != std::string::npos) {
                                token.type = token_type::joint_combiner;
                            } else if (token_str.find("EndoCoefficient") != std::string::npos) {
                                token.type = token_type::endo_coefficient;
                            } else if (token_str.find("Mds") != std::string::npos) {
                                token.type = token_type::mds;
                                std::size_t row_pos = token_str.find("row");
                                row_pos += 5;
                                std::size_t row_end_pos = token_str.find(" ", row_pos);
                                std::string row_str = token_str.substr(row_pos, row_end_pos - row_pos);
                                token.value.first = std::stoi(row_str);

                                std::size_t col_pos = token_str.find("col");
                                col_pos += 5;
                                std::size_t col_end_pos = token_str.find(" ", col_pos);
                                std::string col_str = token_str.substr(col_pos, col_end_pos - col_pos);
                                token.value.second = std::stoi(col_str);
                            } else if (token_str.find("Literal") != std::string::npos) {
                                token.type = token_type::literal;
                                std::size_t value_start_pos = token_str.find("Literal") + 8;
                                std::size_t value_end_pos = token_str.find(";", value_start_pos);
                                std::string value_str =
                                    token_str.substr(value_start_pos, value_end_pos - value_start_pos);
                                token.value.first = multiprecision::cpp_int("0x" + value_str);
                            } else if (token_str.find("Cell") != std::string::npos) {
                                token.type = token_type::cell;

                                std::size_t row_pos = token_str.find("row");
                                std::size_t row;
                                if (token_str.find("Curr", row_pos) != std::string::npos) {
                                    row = 0;
                                } else {    // Next
                                    row = 1;
                                }

                                std::size_t col_pos = token_str.find("col");
                                std::size_t col;
                                if (token_str.find("Witness", col_pos) != std::string::npos) {
                                    // Witness(col)
                                    std::size_t witness_pos = token_str.find("Witness", col_pos);
                                    std::size_t col_start_pow = witness_pos + 8;
                                    std::size_t col_end_pow = token_str.find(")", col_start_pow);
                                    std::string col_str = token_str.substr(col_start_pow, col_end_pow - col_start_pow);
                                    col = std::stoi(col_str);
                                } else {
                                    std::array<std::string, 6> column_types = {"Z",           "Poseidon",
                                                                               "Generic",     "LookupAggreg",
                                                                               "LookupTable", "LookupRuntimeTable"};
                                    for (std::size_t i = 0; i < column_types.size(); i++) {
                                        if (token_str.find(column_types[i]) != std::string::npos) {
                                            col = KimchiParamsType::witness_columns + i + 1;
                                            break;
                                        }
                                    }

                                    // lookup_sorted
                                    if (token_str.find("LookupSorted") != std::string::npos) {
                                        std::size_t col_start_pos = token_str.find("LookupSorted", col_pos) + 14;
                                        std::size_t col_end_pos = token_str.find(")", col_start_pos);
                                        std::string col_str =
                                            token_str.substr(col_start_pos, col_end_pos - col_start_pos);
                                        col = KimchiParamsType::witness_columns + 6 + std::stoi(col_str);
                                    }
                                }

                                token.value.first = col;
                                token.value.second = row;
                            } else if (token_str.find("Dup") != std::string::npos) {
                                token.type = token_type::dup;
                            } else if (token_str.find("Pow") != std::string::npos) {
                                token.type = token_type::pow;

                                std::size_t exp_start_pos = token_str.find("Pow") + 4;
                                std::size_t exp_end_pos = token_str.find(")", exp_start_pos);
                                std::string exp_str = token_str.substr(exp_start_pos, exp_end_pos - exp_start_pos);
                                token.value.first = std::stoi(exp_str);
                            } else if (token_str.find("Add") != std::string::npos) {
                                token.type = token_type::add;
                            } else if (token_str.find("Mul") != std::string::npos) {
                                token.type = token_type::mul;
                            } else if (token_str.find("Sub") != std::string::npos) {
                                token.type = token_type::sub;
                            } else if (token_str.find("VanishesOnLast4Rows") != std::string::npos) {
                                token.type = token_type::vanishes_on_last_4_rows;
                            } else if (token_str.find("UnnormalizedLagrangeBasis") != std::string::npos) {
                                token.type = token_type::unnormalized_lagrange_basis;
                            } else if (token_str.find("Store") != std::string::npos) {
                                token.type = token_type::store;
                            } else if (token_str.find("Load") != std::string::npos) {
                                token.type = token_type::load;

                                std::size_t idx_start_pos = token_str.find("Load") + 5;
                                std::size_t idx_end_pos = token_str.find(")", idx_start_pos);
                                std::string idx_str = token_str.substr(idx_start_pos, idx_end_pos - idx_start_pos);
                                token.value.first = std::stoi(idx_str);
                            } else {
                                throw std::runtime_error("Unknown token type");
                            }

                            tokens.push_back(token);
                        }

                        return tokens;
                    }

                    //                    constexpr static std::size_t rows_by_expr(
                    //                        const std::string_view &str) {
                    //                        auto tokens = rpn_from_string(str);
                    //                        std::size_t rows = 0;
                    //                        std::size_t constant_rows = 3 + mds_size * mds_size;
                    //
                    //                        for (std::size_t i = 0; i < tokens.size(); i++) {
                    //                            auto token = tokens[i];
                    //                            if (token.type == token_type::literal || token.type ==
                    //                            token_type::pow) {
                    //                                constant_rows++;
                    //                            }
                    //                            switch (token.type) {
                    //                                case token_type::pow:
                    //                                    rows += exponentiation_component::rows_amount;
                    //                                    break;
                    //                                case token_type::add:
                    //                                    rows += add_component::rows_amount;
                    //                                    break;
                    //                                case token_type::mul:
                    //                                    rows += mul_component::rows_amount;
                    //                                    break;
                    //                                case token_type::sub:
                    //                                    rows += sub_component::rows_amount;
                    //                                    break;
                    //                                case token_type::vanishes_on_last_4_rows:
                    //                                    // TODO: lookups
                    //                                    break;
                    //                                case token_type::unnormalized_lagrange_basis:
                    //                                    // TODO: lookups
                    //                                    break;
                    //                                default:
                    //                                    break;
                    //                            }
                    //                        }
                    //
                    //                        return std::max(rows, constant_rows);
                    //                    }

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                        }

                        result_type() {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        generate_assignments_constants(assignment, params, start_row_index);

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        std::vector<var> stack;
                        std::vector<var> cache;

                        std::size_t constant_row = 0;

                        var endo_factor(0, constant_row, false, var::column_type::constant);
                        var zero(0, constant_row + 1, false, var::column_type::constant);
                        var one(0, constant_row + 2, false, var::column_type::constant);
                        constant_row += 3;

                        auto mds = mds_vars(constant_row);
                        constant_row += mds_size * mds_size;

                        for(typename params_type::token_value_type t : params.tokens) {
                            switch (t.type) {
                                case token_type::alpha:
                                    stack.emplace_back(params.alpha);
                                    break;
                                case token_type::beta:
                                    stack.emplace_back(params.beta);
                                    break;
                                case token_type::gamma:
                                    stack.emplace_back(params.gamma);
                                    break;
                                case token_type::joint_combiner:
                                    stack.emplace_back(params.joint_combiner);
                                    break;
                                case token_type::endo_coefficient:
                                    stack.emplace_back(endo_factor);
                                    break;
                                case token_type::mds: {
                                    std::size_t mds_row =
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t mds_col =
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    stack.emplace_back(mds[mds_row][mds_col]);
                                    break;
                                }
                                case token_type::literal: {
                                    var literal(0, constant_row, false, var::column_type::constant);
                                    stack.emplace_back(literal);
                                    constant_row++;
                                    break;
                                }
                                case token_type::cell: {
                                    std::size_t cell_col =
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t cell_row =
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    var cell_val = var_from_evals(params.evaluations, cell_col, cell_row);
                                    stack.emplace_back(cell_val);
                                    break;
                                }
                                case token_type::dup:
                                    stack.emplace_back(stack.back());
                                    break;
                                case token_type::pow: {
                                    var exponent(0, constant_row, false, var::column_type::constant);
                                                                        constant_row++;

                                                                        var res = zk::components::generate_circuit<exponentiation_component>(bp, assignment,
                                                                                                                             {stack.back(), exponent}, row)
                                                                                      .output;
                                                                        row += exponentiation_component::rows_amount;

                                                                        stack[stack.size() - 1] = res;
                                                                        break;
                                }
                                case token_type::add: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<add_component>(bp, assignment, {x, y}, row)
                                            .output;
                                    row += add_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::mul: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<mul_component>(bp, assignment, {x, y}, row)
                                            .output;
                                    row += mul_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::sub: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res =
                                        zk::components::generate_circuit<sub_component>(bp, assignment, {x, y}, row)
                                            .output;
                                    row += sub_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::vanishes_on_last_4_rows:
                                    // TODO: lookups
                                    break;
                                case token_type::unnormalized_lagrange_basis:
                                    // TODO: lookups
                                    break;
                                case token_type::store: {
                                    var x = stack.back();
                                    cache.emplace_back(x);
                                    break;
                                }
                                case token_type::load: {
                                    std::size_t idx = typename BlueprintFieldType::integral_type(t.value.first.data);
                                    stack.push_back(cache[idx]);
                                    break;
                                }
                            }
                        }

                        result_type res;
                        res.output = stack[stack.size() - 1];
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::vector<var> stack;
                        std::vector<var> cache;

                        std::size_t constant_row = 0;

                        var endo_factor(0, constant_row, false, var::column_type::constant);
                        var zero(0, constant_row + 1, false, var::column_type::constant);
                        var one(0, constant_row + 2, false, var::column_type::constant);
                        constant_row += 3;

                        auto mds = mds_vars(constant_row);
                        constant_row += mds_size * mds_size;

                        for (typename params_type::token_value_type t : params.tokens) {
                            switch (t.type) {
                                case token_type::alpha:
                                    stack.emplace_back(params.alpha);
                                    break;
                                case token_type::beta:
                                    stack.emplace_back(params.beta);
                                    break;
                                case token_type::gamma:
                                    stack.emplace_back(params.gamma);
                                    break;
                                case token_type::joint_combiner:
                                    stack.emplace_back(params.joint_combiner);
                                    break;
                                case token_type::endo_coefficient:
                                    stack.emplace_back(endo_factor);
                                    break;
                                case token_type::mds: {
                                    std::size_t mds_row =
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t mds_col =
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    stack.emplace_back(mds[mds_row][mds_col]);
                                    break;
                                }
                                case token_type::literal: {
                                    var literal(0, constant_row, false, var::column_type::constant);
                                    stack.emplace_back(literal);
                                    constant_row++;
                                    break;
                                }
                                case token_type::cell: {
                                    std::size_t cell_col =
                                        typename BlueprintFieldType::integral_type(t.value.first.data);
                                    std::size_t cell_row =
                                        typename BlueprintFieldType::integral_type(t.value.second.data);
                                    var cell_val = var_from_evals(params.evaluations, cell_col, cell_row);
                                    stack.emplace_back(cell_val);
                                    break;
                                }
                                case token_type::dup:
                                    stack.emplace_back(stack.back());
                                    break;
                                case token_type::pow: {
                                    var exponent(0, constant_row, false, var::column_type::constant);
                                    constant_row++;

                                    var res = exponentiation_component::generate_assignments(
                                                  assignment, {stack.back(), exponent}, row)
                                                  .output;
                                    row += exponentiation_component::rows_amount;

                                    stack[stack.size() - 1] = res;
                                    break;
                                }
                                case token_type::add: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = add_component::generate_assignments(assignment, {x, y}, row).output;
                                    row += add_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::mul: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = mul_component::generate_assignments(assignment, {x, y}, row).output;
                                    row += mul_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::sub: {
                                    var x = stack.back();
                                    stack.pop_back();
                                    var y = stack.back();
                                    stack.pop_back();
                                    var res = sub_component::generate_assignments(assignment, {x, y}, row).output;
                                    row += sub_component::rows_amount;
                                    stack.push_back(res);
                                    break;
                                }
                                case token_type::vanishes_on_last_4_rows:
                                    // TODO: lookups
                                    break;
                                case token_type::unnormalized_lagrange_basis:
                                    // TODO: lookups
                                    break;
                                case token_type::store: {
                                    var x = stack.back();
                                    cache.emplace_back(x);
                                    break;
                                }
                                case token_type::load: {
                                    std::size_t idx = typename BlueprintFieldType::integral_type(t.value.first.data);
                                    stack.push_back(cache[idx]);
                                    break;
                                }
                            }
                        }

                        result_type res;
                        res.output = stack[stack.size() - 1];
                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = endo_scalar_component::endo_factor;
                        row++;

                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;

                        std::array<std::array<typename BlueprintFieldType::value_type, mds_size>, mds_size> mds =
                            poseidon_component::mds_constants();
                        for (std::size_t i = 0; i < mds_size; i++) {
                            for (std::size_t j = 0; j < mds_size; j++) {
                                assignment.constant(0)[row] = mds[i][j];
                                row++;
                            }
                        }

                        for (typename params_type::token_value_type t : params.tokens) {
                            switch (t.type) {
                                case token_type::literal: {
                                    assignment.constant(W0)[row] = t.value.first;
                                    row++;
                                    break;
                                }
                                case token_type::pow: {
                                    assignment.constant(W0)[row] = t.value.first;
                                    row++;
                                    break;
                                }
                                case token_type::unnormalized_lagrange_basis:
                                    // TODO: lookups
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
