fn main(x: [Field; 2], y: pub [Field; 2]) -> pub [Field; 2] {
    assert_eq(x[0] * y[0], 1);
    assert_eq(x[1] * y[1], 1);
    [y[0] + 2, y[1] + 2]
}

