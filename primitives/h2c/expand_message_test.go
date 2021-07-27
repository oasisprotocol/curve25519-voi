// Copyright (c) 2021 Oasis Labs Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package h2c

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/sha3"
)

type expandMessageTestVector struct {
	msg      string
	expected string
}

func (vec *expandMessageTestVector) checkXMD(hFunc crypto.Hash, dst []byte) error {
	outLen := len(vec.expected) / 2 // Hex string to bytes
	out := make([]byte, outLen)

	if err := ExpandMessageXMD(out, hFunc, dst, []byte(vec.msg)); err != nil {
		return err
	}

	if outHex := hex.EncodeToString(out); outHex != vec.expected {
		return fmt.Errorf("output mismatch: got '%s'", outHex)
	}

	return nil
}

func (vec *expandMessageTestVector) checkXOF(xofFunc sha3.ShakeHash, dst []byte) error {
	outLen := len(vec.expected) / 2 // Hex string to bytes
	out := make([]byte, outLen)

	if err := ExpandMessageXOF(out, xofFunc, dst, []byte(vec.msg)); err != nil {
		return err
	}

	if outHex := hex.EncodeToString(out); outHex != vec.expected {
		return fmt.Errorf("output mismatch: got '%s'", outHex)
	}

	return nil
}

func TestExpandMessage(t *testing.T) {
	t.Run("XMD", testExpandMessageXMD)
	t.Run("XOF", testExpandMessageXOF)
}

func testExpandMessageXMD(t *testing.T) {
	t.Run("SHA-256", func(t *testing.T) {
		// K.1. expand_message_xmd(SHA-256)
		dst := []byte("QUUX-V01-CS02-with-expander")
		vecs := []expandMessageTestVector{
			{
				msg:      "",
				expected: "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88",
			},
			{
				msg:      "abc",
				expected: "1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7",
			},
			{
				msg:      "abcdef0123456789",
				expected: "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e1716b1b964e1c642",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c350db46f429b771b",
			},
			{
				msg:      "",
				expected: "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f",
			},
			{
				msg:      "abc",
				expected: "fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcfd318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192",
			},
			{
				msg:      "abcdef0123456789",
				expected: "c9ec7941811b1e19ce98e21db28d22259354d4d0643e301175e2f474e030d32694e9dd5520dde93f3600d8edad94e5c364903088a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c924e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "48e256ddba722053ba462b2b93351fc966026e6d6db493189798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd402cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3720fe96ba53db947842120a068816ac05c159bb5266c63658b4f000cbf87b1209a225def8ef1dca917bcda79a1e42acd8069",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "396962db47f749ec3b5042ce2452b619607f27fd3939ece2746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a842a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf378fba044a31f5cb44583a892f5969dcd73b3fa128816e",
			},
		}

		for i, vec := range vecs {
			if err := vec.checkXMD(crypto.SHA256, dst); err != nil {
				t.Fatalf("Test vector[%d]: %v", i, err)
			}
		}
	})
	t.Run("SHA-512", func(t *testing.T) {
		// K.2. expand_message_xmd(SHA-512)
		dst := []byte("QUUX-V01-CS02-with-expander")
		vecs := []expandMessageTestVector{
			{
				msg:      "",
				expected: "2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642",
			},
			{
				msg:      "abc",
				expected: "0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc608d2c13005553b0f",
			},
			{
				msg:      "abcdef0123456789",
				expected: "2e375fc05e05e80dbf3083796fde2911789d9e8847e1fcebf4ca4b36e239b338",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "c37f9095fe7fe4f01c03c3540c1229e6ac8583b07510085920f62ec66acc0197",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "af57a7f56e9ed2aa88c6eab45c8c6e7638ae02da7c92cc04f6648c874ebd560e",
			},
			{
				msg:      "",
				expected: "0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6dcd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c14e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf",
			},
			{
				msg:      "abc",
				expected: "779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3ef0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a",
			},
			{
				msg:      "abcdef0123456789",
				expected: "f0953d28846a50e9f88b7ae35b643fc43733c9618751b569a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12abfa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50c044130e480501046920ff090c1a091c88391502f0fbac",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "64d3e59f0bc3c5e653011c914b419ba8310390a9585311fddb26791d26663bd71971c347e1b5e88ba9274d2445ed9dcf48eea9528d807b7952924159b7c27caa4f25a2ea94df9508e70a7012dfce0e8021b37e59ea21b80aa9af7f1a1f2efa4fbe523c4266ce7d342acaacd438e452c501c131156b4945515e9008d2b155c258",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "01524feea5b22f6509f6b1e805c97df94faf4d821b01aadeebc89e9daaed0733b4544e50852fd3e019d58eaad6d267a134c8bc2c08bc46c10bfeff3ee03110bcd8a0d695d75a34092bd8b677bdd369a13325549abab54f4ac907b712bdd3567f38c4554c51902b735b81f43a7ef6f938c7690d107c052c7e7b795ac635b3200a",
			},
		}

		for i, vec := range vecs {
			if err := vec.checkXMD(crypto.SHA512, dst); err != nil {
				t.Fatalf("Test vector[%d]: %v", i, err)
			}
		}
	})
}

func testExpandMessageXOF(t *testing.T) {
	t.Run("SHAKE128", func(t *testing.T) {
		// K.3. expand_message_xof(SHAKE128)
		dst := []byte("QUUX-V01-CS02-with-expander")
		vecs := []expandMessageTestVector{
			{
				msg:      "",
				expected: "eca3fe8f7f5f1d52d7ed3691c321adc7d2a0fef1f843d221f7002530070746de",
			},
			{
				msg:      "abc",
				expected: "c79b8ea0af10fd8871eda98334ea9d54e9e5282be97521678f987718b187bc08",
			},
			{
				msg:      "abcdef0123456789",
				expected: "fb6f4af2a83f6276e9d41784f1e29da5e27566167c33e5cf2682c30096878b73",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "125d05850db915e0683d17d044d87477e6e7b3f70a450dd097761e18d1d1dcdf",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "beafd026cb942c86f6a2b31bb8e6bf7173fb1b0caf3c21ea4b3b9d05d904fd23",
			},
			{
				msg:      "",
				expected: "15733b3fb22fac0e0902c220aeea48e5e47d39f36c2cc03eac34367c48f2a3ebbcb3baa8a0cf17ab12fff4defc7ce22aed47188b6c163e828741473bd89cc646a082cb68b8e835b1374ea9a6315d61db0043f4abf506c26386e84668e077c85ebd9d632f4390559b979e70e9e7affbd0ac2a212c03b698efbbe940f2d164732b",
			},
			{
				msg:      "abc",
				expected: "4ccafb6d95b91537798d1fbb25b9fbe1a5bbe1683f43a4f6f03ef540b811235317bfc0aefb217faca055e1b8f32dfde9eb102cdc026ed27caa71530e361b3adbb92ccf68da35aed8b9dc7e4e6b5db0666c607a31df05513ddaf4c8ee23b0ee7f395a6e8be32eb13ca97da289f2643616ac30fe9104bb0d3a67a0a525837c2dc6",
			},
			{
				msg:      "abcdef0123456789",
				expected: "c8ee0e12736efbc9b47781db9d1e5db9c853684344a6776eb362d75b354f4b74cf60ba1373dc2e22c68efb76a022ed5391f67c77990802018c8cdc7af6d00c86b66a3b3ccad3f18d90f4437a165186f6601cf0bb281ea5d80d1de20fe22bb2e2d8acab0c043e76e3a0f34e0a1e66c9ade4fef9ef3b431130ad6f232babe9fe68",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "3eebe6721b2ec746629856dc2dd3f03a830dabfefd7e2d1e72aaf2127d6ad17c988b5762f32e6edf61972378a4106dc4b63fa108ad03b793eedf4588f34c4df2a95b30995a464cb3ee31d6dca30adbfc90ffdf5414d7893082c55b269d9ec9cd6d2a715b9c4fad4eb70ed56f878b55a17b5994ef0de5b338675aad35354195cd",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "858cb4a6a5668a97d0f7039b5d6d574dde18dd2323cf6b203945c66df86477d1f747b46401903b3fa66d1276108ea7187b4411b7499acf4600080ce34ff6d21555c2af16f091adf8b285c8439f2e47fa0553c3a6ef5a4227a13f34406241b7d7fd8853a080bad25ec4804cdfe4fda500e1c872e71b8c61a8e160691894b96058",
			},
		}

		for i, vec := range vecs {
			if err := vec.checkXOF(sha3.NewShake128(), dst); err != nil {
				t.Fatalf("Test vector[%d]: %v", i, err)
			}
		}
	})
	t.Run("SHAKE256", func(t *testing.T) {
		// K.4. expand_message_xof(SHAKE256)
		dst := []byte("QUUX-V01-CS02-with-expander")
		vecs := []expandMessageTestVector{
			{
				msg:      "",
				expected: "58e90433d81860c47d350b0bb6fb94f98f6b0f9657efd04d410ae743260c096d",
			},
			{
				msg:      "abc",
				expected: "c7f5e3c044790033707e24f21d971aaa03a760dfda6215bf0c8634da9012c8f8",
			},
			{
				msg:      "abcdef0123456789",
				expected: "f46930964d5d5006ef992f5878d7c255c9a92aed1032c9b9d4743ec1470a91e8",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "885baaf4841ad28aa853022289cb4841cc6c1bf200c579e8aebb8d005a8ff37f",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "4a9884b31a64772244df05622222db6cb9942034370d2400e39bb853cca727f7",
			},
			{
				msg:      "",
				expected: "4cbc65744a4a26c059472822a4647887abb4a3220d5c1e1155c4180a04c69541d437b77676fc5b6450faa5cb906d88a8fa7e1c6807d0a66f0092cc022812368e75ba41dcb4daab00a17e752d485f5e21f835ac36f05b9d0217c79376045e1360faa4652db9d7752af1ffb76ae14cf6aabd7b08b19032d213415d2cef8cd6b62f",
			},
			{
				msg:      "abc",
				expected: "c5f366dc668697014a0a90a40ae27c19edcb8500f6ad5d4234fbf4204f64df524a44adaecb42102fffeb7686949aa6785142b2510a419dd29dadf1f2b455688c043f6bc2fd76b101dd8e41cca4042514a6b15d137d958735961e3c32a49e0640ad564d533d20adc203c5befdb1186ca18646b729a5cb4531922d24a17b4389ea",
			},
			{
				msg:      "abcdef0123456789",
				expected: "34dcc64cee945b94c5e29a9aa6b859b8a9705fe020bf7443eaab4c8269e739904e2703cef64e1823b5c848570db97b28da7869f52c24573d8f759b7181726e186dcff940eea5f70a11ebd14b4c90c3b17805ce91dc3157ce635e9d11fe56d86dfa76a79e84c11e253653350d2f954922077f2ea6a17104dd0fd963d7fe4568d3",
			},
			{
				msg:      "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				expected: "b0adc10a4326ae3ddf11c42afb89058625f8812c76b2a0fb17570f7a2acb030e8dd20036d1326984fd0d973197d80fbf461fe18ef394b9a22e609e61d710df43476ddf3a8ca4d32b737bc265d14a204f32173e447db74bc68938b6a6a08e3e9a31968e5d05a0ca213c977e94cffc9a535b5c5198a6c5892bbce1a35ecc7ab2bd",
			},
			{
				msg:      "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				expected: "50a0cb335f3102a15f3dfed981b0a5fecb3136112532e129d39369a2a92c32a9b0a0181af9839039c0e98a3b66a0d209fa019134991055284c3f475c9f7c91169dea57aad442f0c98418d36e50fad68e8863109dac6d8cfc6c5fa63e8f1c0468af9980066e87b62caa87f4b3feef0dba8ef894f2957105d111439597d3265b1f",
			},
		}

		for i, vec := range vecs {
			if err := vec.checkXOF(sha3.NewShake256(), dst); err != nil {
				t.Fatalf("Test vector[%d]: %v", i, err)
			}
		}
	})
}
