import libzkp


def test_range():
    proof = libzkp.prove_range(10, 0, 20)
    assert libzkp.verify_range(proof, 0, 20)

def test_equality():
    proof = libzkp.prove_equality(5, 5)
    assert libzkp.verify_equality(proof, 5, 5)

def test_threshold():
    proof = libzkp.prove_threshold([1, 2, 3], 5)
    assert libzkp.verify_threshold(proof, 5)

def test_membership():
    proof = libzkp.prove_membership(3, [1, 2, 3])
    assert libzkp.verify_membership(proof, [1, 2, 3])

def test_improvement():
    proof = libzkp.prove_improvement(1, 8)
    assert libzkp.verify_improvement(proof, 1)

def test_consistency():
    proof = libzkp.prove_consistency([1, 2, 3])
    assert libzkp.verify_consistency(proof)
