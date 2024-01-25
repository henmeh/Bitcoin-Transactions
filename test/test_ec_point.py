import pytest
from src.ec_point import ECPoint
from src.fieldelement import FieldElement

class TestECCalculation:

    test_eq_ne_parameter = [("ECPoint(3, -7, 5, 7) == ECPoint(3, -7, 5, 7)", True),
                            ("ECPoint(3, -7, 5, 7) == ECPoint(18, 77, 5, 7)", False),
                            ("ECPoint(3, -7, 5, 7) != ECPoint(18, 77, 5, 7)", True),
                            ("ECPoint(3, -7, 5, 7) != ECPoint(3, -7, 5, 7)", False)]


    test_repr_parameter = [("repr(ECPoint(None, None, 5, 7))", "Point(infinity)_5_7"),
                           ("repr(ECPoint(3, -7, 5, 7))", "Point(3,-7)_5_7"),
                           ("repr(ECPoint(FieldElement(192, 223), FieldElement(105, 223), FieldElement(0, 223), FieldElement(7, 223)))", "Point(192,105)_0_7_223")]


    test_add_parameter = [("ECPoint(None, None, 5, 7) + ECPoint(2, 5, 5, 7)", ECPoint(2, 5, 5, 7)),
                          ("ECPoint(2, 5, 5, 7) + ECPoint(None, None, 5, 7)", ECPoint(2, 5, 5, 7)),
                          ("ECPoint(2, 5, 5, 7) + ECPoint(2, -5, 5, 7)", ECPoint(None, None, 5, 7)),
                          ("ECPoint(3, 7, 5, 7) + ECPoint(-1, -1, 5, 7)", ECPoint(2, -5, 5, 7)),
                          ("ECPoint(0, 0, 0, 0) + ECPoint(0, 0, 0, 0)", ECPoint(None, None, 0, 0)),
                          ("ECPoint(-1, 1, 5, 7) + ECPoint(-1, 1, 5, 7)", ECPoint(18, -77, 5, 7))]


    def test_init_for_value_error(self):
        with pytest.raises(ValueError) as excinfo:
            ECPoint(-2, 4, 5, 7)
        assert "-2, 4 is not on the curve" in str(excinfo.value)


    def test_init_for_none(self):
        point = ECPoint(None, None, 0, 0) 
        assert point.x_coordinate == None
        assert point.y_coordinate == None
        assert point.a_param == 0
        assert point.b_param == 0
    

    def test_init_true_point(self):
        point = ECPoint(3, 7, 5, 7) 
        assert point.x_coordinate == 3
        assert point.y_coordinate == 7
        assert point.a_param == 5
        assert point.b_param == 7
    

    @pytest.mark.parametrize("test_input, expected", test_eq_ne_parameter)
    def test_eq(self, test_input, expected):
        assert eval(test_input) == expected
    

    @pytest.mark.parametrize("test_input, expected", test_eq_ne_parameter)
    def test_ne(self, test_input, expected):
        assert eval(test_input) == expected
    

    @pytest.mark.parametrize("test_input, expected", test_repr_parameter)
    def test_repr(self, test_input, expected):
        assert eval(test_input) == expected
    

    def test_add_for_type_error(self):
        with pytest.raises(TypeError) as excinfo:
            ECPoint(3, 7, 5, 7) + ECPoint(None, None, 4, 5)
        assert "Points Point(3,7)_5_7, Point(infinity)_4_5 are not on the same curve" in str(excinfo.value)
    
    
    @pytest.mark.parametrize("test_input, expected", test_add_parameter)
    def test_add(self, test_input, expected):
        assert eval(test_input) == expected
    
    