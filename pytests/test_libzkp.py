import libzkp


def test_range():
    proof, comm = libzkp.prove_range(10, 0, 20)
    assert libzkp.verify_range(proof, comm, 0, 20)

def test_equality():
    proof, comm = libzkp.prove_equality(5, 5)
    assert libzkp.verify_equality(proof, comm, 5, 5)

def test_threshold():
    proof, comm = libzkp.prove_threshold([1, 2, 3], 5)
    assert libzkp.verify_threshold(proof, comm, 5)

def test_membership():
    proof, comm = libzkp.prove_membership(3, [1, 2, 3])
    assert libzkp.verify_membership(proof, comm, [1, 2, 3])

def test_improvement():
    proof, comm = libzkp.prove_improvement(1, 2)
    assert libzkp.verify_improvement(proof, comm, 1)

def test_consistency():
    proof, comm = libzkp.prove_consistency([1, 2, 3])
    assert libzkp.verify_consistency(proof, comm)
