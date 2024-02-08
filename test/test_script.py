from io import BytesIO
import pytest

from src.script import Script
from src.helper import int_to_little_endian


class TestScript:

    script_pubkey_bytes = bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
    script_pubkey = BytesIO(script_pubkey_bytes)
    script = Script.parse_script(script_pubkey)
    test_parse_script_parameter = [(script.commands[0].hex(), bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601').hex()),
                                   (script.commands[1], bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))]

    test_serialize_script_parameter = [(script.serialize_script(), script_pubkey_bytes)]    
    
    
    def test_parse_script_for_syntax_error(self):
        with pytest.raises(SyntaxError, match="parsing script failed"):
            script_pubkey_fail = BytesIO(bytes.fromhex('5a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
            Script.parse_script(script_pubkey_fail)
            

    @pytest.mark.parametrize("parsing_result_calculated, parsing_result_expected", test_parse_script_parameter)
    def test_parse_script(self, parsing_result_calculated, parsing_result_expected):
        assert parsing_result_calculated == parsing_result_expected
    

    def test_serialize_script_for_value_error(self):
        with pytest.raises(ValueError, match="command is too long"):
            script_pubkey_fail = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
            script = Script.parse_script(script_pubkey_fail)
            script.commands[1] = int_to_little_endian(0x035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937, 521)

            script.serialize_script()


    @pytest.mark.parametrize("serializing_result_calculated, serializing_result_expected", test_serialize_script_parameter)
    def test_serialize_script(self, serializing_result_calculated, serializing_result_expected):
        assert  serializing_result_calculated == serializing_result_expected
    
    