from io import BytesIO

import pytest
from src.transaction import CTx


class TestTransaction:

    test_transaction_legacy = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"

    test_parse_version_parameter = [(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).version, 1)]
    test_parse_inputs_parameter = [(len(CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins), 1),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].previous_transaction_id, bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].previous_transaction_index, 0),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].script_sig.serialize_script(), bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')),
                                   (CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction_legacy))).tx_ins[0].sequence, 0xfffffffe)]
    

    @pytest.mark.parametrize("parsed_tx_value, expected_tx_value", test_parse_version_parameter)
    def test_parse_version(self, parsed_tx_value, expected_tx_value):
        assert parsed_tx_value == expected_tx_value


    @pytest.mark.parametrize("parsed_tx_value, expected_tx_value", test_parse_inputs_parameter)
    def test_parse_inputs(self, parsed_tx_value, expected_tx_value):
        assert parsed_tx_value == expected_tx_value