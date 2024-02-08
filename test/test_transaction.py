from io import BytesIO

import pytest
from src.transaction import CTx, CTxIn


class TestTransaction:

    test_transaction_legacy = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"

    test_parse_version_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).version, 1)]
    
    test_parse_locktime_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).locktime, 410393)]

    tx = CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy)))
    test_serialize_transaction_parameter = [(tx.serialize_transaction().hex(),test_transaction_legacy)]

    
    test_get_fee_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).get_fee(), 40000)]


    @pytest.mark.parametrize("parsed_tx_value, expected_tx_value", test_parse_version_parameter)
    def test_parse_version(self, parsed_tx_value, expected_tx_value):
        assert parsed_tx_value == expected_tx_value


    @pytest.mark.parametrize("parsed_locktime_value, expected_locktime_value", test_parse_locktime_parameter)
    def test_parse_locktime(self, parsed_locktime_value, expected_locktime_value):
        assert parsed_locktime_value == expected_locktime_value
    
    
    @pytest.mark.parametrize("serialized_value, serialized_expected", test_serialize_transaction_parameter)
    def test_serialize_transaction(self, serialized_value, serialized_expected):
        assert serialized_value == serialized_expected


    @pytest.mark.parametrize("get_fee_calculated, get_fee_expected", test_get_fee_parameter)
    def test_get_fee(self, get_fee_calculated, get_fee_expected):
        assert get_fee_calculated == get_fee_expected
    

    
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
   