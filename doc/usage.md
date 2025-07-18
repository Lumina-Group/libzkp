# 利用方法

## Rust から利用する場合
Cargo でビルドおよびテストを実行できます。
```bash
cargo test
```

## Python から利用する場合
maturin を用いて wheel を作成し、`pip install` します。
```bash
maturin build -r -F pyo3/extension-module
pip install target/wheels/libzkp-*.whl
```
インストール後は以下のように呼び出せます。
```python
import libzkp
proof, comm = libzkp.prove_equality(5, 5)
assert libzkp.verify_equality(proof, comm, 5, 5)
```
