from format_converter import Converter
import pytest

def test_convert_endianes_hex_str():
    converter = Converter()
    assert(converter.convert_endianes_hex_str("76a914cb0b589d96c4e88684e39a990712ecdbe3cd727188ac")) == "ac887172cde3dbec1207999ae38486e8c4969d580bcb14a976"

def test_convert_format_satoshi_amounts():
    converter = Converter()
    assert(converter.convert_format_satoshi_amounts(1000)) == "e803000000000000"