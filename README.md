# libzkp

libzkp は、Python から利用可能なゼロ知識証明 (ZKP) ライブラリです。Rust で実装されており、`maturin` を用いて Python モジュールとしてビルドできます。

このライブラリでは以下の証明を提供します。

- 範囲証明 (range proof)
- 値の等価性証明 (equality proof)
- しきい値達成証明 (threshold proof)
- 集合所属証明 (set membership proof)
- 向上証明 (improvement proof)
- 整合性証明 (consistency proof)

各証明は Rust 側で実装された複数のバックエンドを利用しており、Bulletproofs、SNARK、STARK を扱えるようになっています。

## インストール

ビルドには [maturin](https://github.com/PyO3/maturin) が必要です。

```bash
# Python モジュールとしてビルド
maturin develop
```

## 使い方

Python から呼び出す例：

```python
import libzkp

proof = libzkp.prove_range(10, 0, 20)
assert libzkp.verify_range(proof, 0, 20)
```

詳細な API については `docs/` 配下のドキュメントを参照してください。
