# ドキュメント

ここでは `libzkp` の各 API について簡単に説明します。

## Python API

| 関数名 | 説明 |
| --- | --- |
| `prove_range(value, min, max)` | `min` 以上 `max` 以下に値が存在することを示す範囲証明を生成します。 |
| `verify_range(proof, min, max)` | 範囲証明を検証します。 |
| `prove_equality(val1, val2)` | 2 つの値が等しいことを示す証明を生成します。 |
| `verify_equality(proof, val1, val2)` | 等価性証明を検証します。 |
| `prove_threshold(values, threshold)` | `values` の総和が `threshold` 以上であることを示す証明を生成します。 |
| `verify_threshold(proof, threshold)` | しきい値証明を検証します。 |
| `prove_membership(value, set)` | 値が集合 `set` に含まれることを示す証明を生成します。 |
| `verify_membership(proof, set)` | 集合所属証明を検証します。 |
| `prove_improvement(old, new)` | `old` から `new` へ値が増加したことを示す証明を生成します。 |
| `verify_improvement(proof, old)` | 向上証明を検証します。 |
| `prove_consistency(data)` | 昇順に並んだデータ列であることを示す整合性証明を生成します。 |
| `verify_consistency(proof)` | 整合性証明を検証します。 |

## ビルド方法

```
maturin develop
```

Rust のテストは以下で実行できます。

```
cargo test
```

Python 側のテストは次のように実行します。

```
pytest
```
