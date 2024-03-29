from io import BytesIO
import json


import pytest
from src.transaction import CTx, CTxIn
from src.script import p2wpkh_script
from src.crypto import hash160


class TestTransaction:

    test_transaction_legacy = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"

    test_parse_version_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).version, 1)]
    
    test_parse_locktime_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).locktime, 410393)]

    tx = CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy)))
    test_serialize_transaction_legacy_parameter = [(tx.serialize_transaction().hex(), test_transaction_legacy)]

    test_transaction_segwit = "02000000000101102e92fdf555717908d12243868fadd92b7ac44a1d415bc9c9f4bcc41d1a9dcc0000000000feffffff02f82a000000000000160014231f90603ec02658e7f4e9e03d1b387da21cd61afdc0042a0100000016001483b6c3f7e8914ea252e4afc5bd2318c1b11f120f0247304402200101aa1b1787e0bb54eec064b1faa88e2970e6c00056914a4d8d6f249453f3c002207485f7ea06e8e50d3e4c0595b76f80f1c54af5590135b4156afe2a4641df82b3012102af88e7102c47de6ba6b2e6ae69a3da1f0c43747867dd9dbe4a7beb221358e8b500000000"
    segwit_tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_segwit)))
    test_parse_segwit_witness_data_parameter = [(segwit_tx_parsed.tx_ins[0].witness, ["304402200101aa1b1787e0bb54eec064b1faa88e2970e6c00056914a4d8d6f249453f3c002207485f7ea06e8e50d3e4c0595b76f80f1c54af5590135b4156afe2a4641df82b301", "02af88e7102c47de6ba6b2e6ae69a3da1f0c43747867dd9dbe4a7beb221358e8b5"])]

    test_serialize_transaction_segwit_parameter = [(segwit_tx_parsed.serialize_transaction().hex(), test_transaction_segwit)]
    
    test_get_fee_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).get_fee(), 40000)]


    test_get_sig_hash_for_legacy_transaction_parameter = [(tx.get_sig_hash_for_legacy_transaction(0), int('27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6', 16))]


    private_key = 8675309
    stream = BytesIO(bytes.fromhex('010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000'))
    tx_obj = CTx.parse_transaction(stream, is_testnet=True)
    tx_obj.sign_transaction(0, [private_key])
    test_sign_transaction_parameter = [(tx_obj.serialize_transaction().hex(), "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d0000006b4830450221008ed46aa2cf12d6d81065bfabe903670165b538f65ee9a3385e6327d80c66d3b502203124f804410527497329ec4715e18558082d489b218677bd029e7fa306a72236012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000")]


    @pytest.mark.parametrize("parsed_tx_value, expected_tx_value", test_parse_version_parameter)
    def test_parse_version(self, parsed_tx_value, expected_tx_value):
       assert parsed_tx_value == expected_tx_value


    @pytest.mark.parametrize("parsed_locktime_value, expected_locktime_value", test_parse_locktime_parameter)
    def test_parse_locktime(self, parsed_locktime_value, expected_locktime_value):
        assert parsed_locktime_value == expected_locktime_value
    

    @pytest.mark.parametrize("parsed_witness_data, expected_witness_data", test_parse_segwit_witness_data_parameter)
    def test_parse_segwit_witness_data(self, parsed_witness_data, expected_witness_data):
        for i in range(len(parsed_witness_data)):
            assert parsed_witness_data[i].hex() == expected_witness_data[i]
    
    
    @pytest.mark.parametrize("serialized_value, serialized_expected", test_serialize_transaction_legacy_parameter)
    def test_serialize_transaction_legacy(self, serialized_value, serialized_expected):
        assert serialized_value == serialized_expected

    
    @pytest.mark.parametrize("serialized_value, serialized_expected", test_serialize_transaction_segwit_parameter)
    def test_serialize_transaction_segwit(self, serialized_value, serialized_expected):
        assert serialized_value == serialized_expected


    @pytest.mark.parametrize("get_fee_calculated, get_fee_expected", test_get_fee_parameter)
    def test_get_fee(self, get_fee_calculated, get_fee_expected):
        assert get_fee_calculated == get_fee_expected


    @pytest.mark.parametrize("sig_hash_calculated, sig_hash_expected", test_get_sig_hash_for_legacy_transaction_parameter)
    def test_get_sig_hash_for_legacy_transaction(self, sig_hash_expected, sig_hash_calculated):
        assert sig_hash_calculated == sig_hash_expected

    
    @pytest.mark.parametrize("signed_transaction_calculated, signed_transaction_expected", test_sign_transaction_parameter)
    def test_sign_transaction(self, signed_transaction_calculated, signed_transaction_expected):
        assert signed_transaction_calculated == signed_transaction_expected


class TestTransactionInputs:

    test_transaction_legacy = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"

    test_parse_inputs_parameter = [(len(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins), 1),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].previous_transaction_id, bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].previous_transaction_index, 0),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].script_sig.serialize_script(), bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].sequence, 0xfffffffe)]
    
    tx_in = CTxIn(bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'), 0)
    test_input_values_parameter = [(tx_in.get_value(), 42505594)]

    test_get_script_pubkey_parameter = [(tx_in.get_script_pubkey().serialize_script(), bytes.fromhex('1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac'))]


    @pytest.mark.parametrize("parsed_input_value, expected_input_value", test_parse_inputs_parameter)
    def test_parse_inputs(self, parsed_input_value, expected_input_value):
        assert parsed_input_value == expected_input_value


    @pytest.mark.parametrize("input_value_calculated, input_value_expected", test_input_values_parameter)
    def test_input_values(self, input_value_calculated, input_value_expected):
        assert input_value_calculated == input_value_expected

    
    @pytest.mark.parametrize("script_pubkey_calculated, script_pubkey_expected", test_get_script_pubkey_parameter)
    def test_get_script_pubkey(self, script_pubkey_calculated, script_pubkey_expected):
        assert script_pubkey_calculated == script_pubkey_expected


class TestTransactionOutputs:

    test_transaction_legacy = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
    
    test_parse_outputs_parameter = [(len(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_outs), 2),
                                    (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_outs[0].amount, 32454049),
                                    (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_outs[0].script_pubkey.serialize_script(), bytes.fromhex('1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')),
                                    (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_outs[1].amount, 10011545),
                                    (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_outs[1].script_pubkey.serialize_script(), bytes.fromhex('1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac'))]
    

    @pytest.mark.parametrize("parsed_output_value, expected_output_value", test_parse_outputs_parameter)
    def test_parse_outputs(self, parsed_output_value, expected_output_value):
        assert parsed_output_value == expected_output_value


class TestTransactionSegWit:

    test_sighash_parameter = [("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000", 1, 6, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1", "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
                              ("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000", 1, 6, p2wpkh_script(hash160(bytes.fromhex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"))), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"),
                              ("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000", 0, 10, "001479091972186c449eb1ded22b78e40d009bdf0089", "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"),
                              ("010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000", 0, 9.87654321, "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae", "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c")]


    @pytest.mark.parametrize("transaction, transaction_index, input_amount, script_pubkey, expected_sighash", test_sighash_parameter)
    def test_sighash(self, transaction, transaction_index, input_amount, script_pubkey, expected_sighash):
        tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(transaction)))
        assert hex(tx_parsed.get_sig_hash_for_segwit_transaction(transaction_index, int(input_amount*100000000), script_pubkey))[2:] == expected_sighash