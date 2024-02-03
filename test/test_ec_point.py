import re

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
    

    test_add_parameter_for_adding_fieldelements = [(192, 105, 17, 56, 170, 142), (47, 71, 117, 141, 60, 139), (143, 98, 76, 66, 47, 71)]


    test_add_parameter_for_rmul_fieldelements = [(2, 192, 105, 49, 71), (2, 143, 98, 64, 168), (2, 47, 71, 36, 111), (4, 47, 71, 194, 51), (8, 47, 71, 116, 55), (21, 47, 71, None, None)]


    def test_init_for_value_error(self):
        with pytest.raises(ValueError, match="-2, 4 is not on the curve"):
            ECPoint(-2, 4, 5, 7)


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
        with pytest.raises(TypeError, match=re.escape("Points Point(3,7)_5_7, Point(infinity)_4_5 are not on the same curve")):
            ECPoint(3, 7, 5, 7) + ECPoint(None, None, 4, 5)
    
    
    @pytest.mark.parametrize("test_input, expected", test_add_parameter)
    def test_add(self, test_input, expected):
        assert eval(test_input) == expected
    

    def test_add_for_adding_fieldelements(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in self.test_add_parameter_for_adding_fieldelements:
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = ECPoint(x1, y1, a, b)
            x2 = FieldElement(x2_raw, prime)
            y2 = FieldElement(y2_raw, prime)
            p2 = ECPoint(x2, y2, a, b)
            x3 = FieldElement(x3_raw, prime)
            y3 = FieldElement(y3_raw, prime)
            p3 = ECPoint(x3, y3, a, b)
            
            assert p1 + p2 == p3


    def test_rmul(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        
        for s, x1_raw, y1_raw, x2_raw, y2_raw in self.test_add_parameter_for_rmul_fieldelements:
            x1 = FieldElement(x1_raw, prime)
            y1 = FieldElement(y1_raw, prime)
            p1 = ECPoint(x1, y1, a, b)
            if x2_raw is None:
                p2 = ECPoint(None, None, a, b)
            else:
                x2 = FieldElement(x2_raw, prime)
                y2 = FieldElement(y2_raw, prime)
                p2 = ECPoint(x2, y2, a, b)

            assert s * p1 == p2