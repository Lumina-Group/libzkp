# libzkp

Rustで実装された簡易ゼロ知識証明ライブラリです。範囲証明や等価性証明、
閾値証明など複数のスキームを提供し、PyO3経由でPythonから利用できます。

## 特徴
- Rustによる高速かつ安全な実装
- Pythonバインディングを標準搭載
- Bulletproofs/SNARK/STARK など複数バックエンドの切り替えに対応

## 使い方
### Rust
```bash
cargo test
```

### Python
maturin でビルドした wheel をインストールします。
```bash
maturin build -r -F pyo3/extension-module
pip install target/wheels/libzkp-*.whl
```
Python からは以下のように利用できます。
```python
import libzkp
proof, comm = libzkp.prove_range(10, 0, 20)
assert libzkp.verify_range(proof, comm, 0, 20)
```

詳細なアーキテクチャやAPIの設計方針については `doc/` 以下を参照してください。
