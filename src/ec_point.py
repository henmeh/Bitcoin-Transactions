from src.fieldelement import FieldElement


class ECPoint:
    """
        y³ = x² + a * x + b
    """
    def __init__(self, x_coordinate, y_coordinate, a_param, b_param):
        self.a_param = a_param
        self.b_param = b_param
        self.x_coordinate = x_coordinate
        self.y_coordinate = y_coordinate
        if self.x_coordinate is None and self.y_coordinate is None:
            return
        if self.y_coordinate**2 != self.x_coordinate**3 + a_param * x_coordinate + b_param:
            raise ValueError(f'{x_coordinate}, {y_coordinate} is not on the curve')


    def __eq__(self, other):
        return self.x_coordinate == other.x_coordinate and self.y_coordinate == other.y_coordinate \
            and self.a_param == other.a_param and self.b_param == other.b_param


    def __ne__(self, other):
        return not (self == other)


    def __repr__(self):
        if self.x_coordinate is None:
            return f'Point(infinity)_{self.a_param}_{self.b_param}'
        elif isinstance(self.x_coordinate, FieldElement):
            return f'Point({self.x_coordinate.num},{self.y_coordinate.num})_{self.a_param.num}_{self.b_param.num}_{self.x_coordinate.prime}'
        else:
            return f'Point({self.x_coordinate},{self.y_coordinate})_{self.a_param}_{self.b_param}'


    def __add__(self, other):
        if self.a_param != other.a_param or self.b_param != other.b_param:
            raise TypeError(f'Points {self}, {other} are not on the same curve')
        if self.x_coordinate is None:
            return other
        if other.x_coordinate is None:
            return self
        if self.x_coordinate == other.x_coordinate and self.y_coordinate != other.y_coordinate:
            return self.__class__(None, None, self.a_param, self.b_param)
        if self.x_coordinate != other.x_coordinate:
            s = (other.y_coordinate - self.y_coordinate) / (other.x_coordinate - self.x_coordinate)
            x = s**2 - self.x_coordinate - other.x_coordinate
            y = s * (self.x_coordinate - x) - self.y_coordinate
            return self.__class__(x, y, self.a_param, self.b_param)
        if self == other and self.y_coordinate == 0 * self.x_coordinate:
            return self.__class__(None, None, self.a_param, self.b_param)
        if self == other:
            s = (3 * self.x_coordinate**2 + self.a_param) / (2 * self.y_coordinate)
            x = s**2 - 2 * self.x_coordinate
            y = s * (self.x_coordinate - x) - self.y_coordinate
            return self.__class__(x, y, self.a_param, self.b_param)


    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a_param, self.b_param)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result
