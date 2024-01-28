import pytest
from random import randint
from src.ecdsa import Secp256k1, Signature, PrivateKey, PublicKey


class TestSecp256k1:

    test_secp256k1_verify_signature_parameter = [("Secp256k1().verify_signature(PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34), Signature(0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395, 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4), 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60)", True),
                                                 ("Secp256k1().verify_signature(PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34), Signature(0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c, 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6), 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d)", True),
                                                 ("Secp256k1().verify_signature(PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34), Signature(0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c, 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6), 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3e)", False),
                                                 ("Secp256k1().verify_signature(PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34), Signature(0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c, 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab7), 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d)", False),
                                                 ("Secp256k1().verify_signature(PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34), Signature(0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2e, 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6), 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d)", False)]
    
    
    def test_secp256k1_sign_data(self):
        private_key = PrivateKey(randint(0, Secp256k1().n))
        public_key = private_key.get_public_key()
        data = 123456789

        signature = Secp256k1().sign_data(private_key.get_private_key_int(), data)

        assert Secp256k1().verify_signature(public_key, signature, data) == True
    
    
    @pytest.mark.parametrize("test_input, expected", test_secp256k1_verify_signature_parameter)
    def test_secp256k1_verify_signature(self, test_input, expected):
        assert eval(test_input) == expected
      

class TestSignature:

    test_signature_init_parameter = [("Signature(0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395, 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4).r", 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395),
                                     ("Signature(0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395, 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4).s", 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4)]


    @pytest.mark.parametrize("test_input, expected", test_signature_init_parameter)
    def test_signature_init(self, test_input, expected):
        assert eval(test_input) == expected
    

class TestPublicKey:

    test_sec_format_parameter = {"private_key": [999**3, 123, 42424242],
                                 "uncompressed": ["049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9",
                                                  "04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b",
                                                  "04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3"],
                                 "compressed": ["039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5",
                                                "03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5",
                                                "03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e"]}
    

    test_parse_public_key_parameter = [("PublicKey.parse_public_key(bytes.fromhex('049d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d56fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9'))", PublicKey(0x9d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5, 0x6fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9)),
                                       ("PublicKey.parse_public_key(bytes.fromhex('039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'))", PublicKey(0x9d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5, 0x6fa15cc7f3d38cda98dee2419f415b7513dde1301f8643cd9245aea7f3f911f9)),
                                       ("PublicKey.parse_public_key(bytes.fromhex('04a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b'))", PublicKey(0xa598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5, 0x204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b)),
                                       ("PublicKey.parse_public_key(bytes.fromhex('03a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5'))", PublicKey(0xa598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5, 0x204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b)),
                                       ("PublicKey.parse_public_key(bytes.fromhex('04aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3'))", PublicKey(0xaee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e, 0x21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3)),
                                       ("PublicKey.parse_public_key(bytes.fromhex('03aee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e'))", PublicKey(0xaee2e7d843f7430097859e2bc603abcc3274ff8169c1a469fee0f20614066f8e, 0x21ec53f40efac47ac1c5211b2123527e0e9b57ede790c4da1e72c91fb7da54a3)),]


    def test_sec_format(self):

        for i in range(len(self.test_sec_format_parameter["private_key"])):
            private_key = PrivateKey(self.test_sec_format_parameter["private_key"][i])
            public_key = private_key.get_public_key()

            assert public_key.sec_format_uncompressed() == bytes.fromhex(self.test_sec_format_parameter["uncompressed"][i])
            assert public_key.sec_format_compressed() == bytes.fromhex(self.test_sec_format_parameter["compressed"][i])
    

    @pytest.mark.parametrize("test_input, expected", test_parse_public_key_parameter)
    def test_parse_public_key(self, test_input, expected):
        assert eval(test_input) == expected