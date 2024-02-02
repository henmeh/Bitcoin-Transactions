import pytest
from src.fieldelement import FieldElement

class TestFieldElement:

    test_eq_ne_parameter = [("FieldElement(3,10) != FieldElement(4,10)", True),
                            ("FieldElement(3,10) == FieldElement(4,10)", False),
                            ("FieldElement(3,10) == FieldElement(3,10)", True),
                            ("FieldElement(3,10) != FieldElement(3,10)", False)]
    
    test_add_parameter = [("FieldElement(2,31) + FieldElement(15,31)", FieldElement(17,31)),
                          ("FieldElement(17,31) + FieldElement(21,31)", FieldElement(7,31))]

    test_sub_parameter = [("FieldElement(29,31) - FieldElement(4,31)", FieldElement(25,31)),
                          ("FieldElement(15,31) - FieldElement(30,31)", FieldElement(16,31))]
    
    test_mul_parameter = [("FieldElement(24,31) * FieldElement(19,31)", FieldElement(22,31))]

    test_pow_parameter = [("FieldElement(17,31)**3", FieldElement(15,31)),
                          ("FieldElement(5,31)**5 * FieldElement(18,31)", FieldElement(16,31))]

    test_div_parameter = [("FieldElement(3,31) / FieldElement(24,31)", FieldElement(4,31)),
                          ("FieldElement(17,31)**-3", FieldElement(29,31)),
                          ("FieldElement(4,31)**-4 * FieldElement(11,31)", FieldElement(13,31))]


    def test_init_for_value_error(self):
        with pytest.raises(ValueError, match="Num 10 not in field range 0 to 2"):
            FieldElement(10,3)


    def test_init_correct(self):
        x = FieldElement(3,10)

        assert x.num == 3
        assert x.prime == 10


    def test_repr(self):
        x = FieldElement(3,10)

        assert(repr(x) == "FieldElement_3(10)")


    @pytest.mark.parametrize("test_input, expected", test_eq_ne_parameter)
    def test_eq(self, test_input, expected):
        assert eval(test_input) == expected


    @pytest.mark.parametrize("test_input, expected", test_eq_ne_parameter)
    def test_ne(self, test_input, expected):
        assert eval(test_input) == expected


    @pytest.mark.parametrize("test_input, expected", test_add_parameter)
    def test_add(self, test_input, expected):
        assert eval(test_input) == expected


    def test_add_for_type_error(self):
        with pytest.raises(TypeError, match="Numbers must be in the same modulo field"):
            x = FieldElement(3, 10) + FieldElement(4, 11)


    @pytest.mark.parametrize("test_input, expected", test_sub_parameter)
    def test_sub(self, test_input, expected):
        assert eval(test_input) == expected


    def test_sub_for_type_error(self):
        with pytest.raises(TypeError, match="Numbers must be in the same modulo field"):
            x = FieldElement(3, 10) - FieldElement(4, 11)


    @pytest.mark.parametrize("test_input, expected", test_mul_parameter)
    def test_mul(self, test_input, expected):
        assert eval(test_input) == expected


    def test_mul_for_type_error(self):
        with pytest.raises(TypeError, match="Numbers must be in the same modulo field"):
            x = FieldElement(3, 10) * FieldElement(4, 11)


    @pytest.mark.parametrize("test_input, expected", test_pow_parameter)
    def test_pow(self, test_input, expected):
        assert eval(test_input) == expected


    @pytest.mark.parametrize("test_input, expected", test_div_parameter)
    def test_div(self, test_input, expected):
        assert eval(test_input) == expected


    def test_div_for_type_error(self):
        with pytest.raises(TypeError, match="Numbers must be in the same modulo field"):
            x = FieldElement(3, 10) / FieldElement(4, 11)