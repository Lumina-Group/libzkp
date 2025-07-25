# libzkp
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)

libzkp は、Python、Rust から利用可能な高性能なゼロ知識証明 (Zero-Knowledge Proof) ライブラリです。Rust で実装されており、PyO3 と maturin を用いて Python モジュールとしてビルドできます。

## 特徴

- **高性能**: Rust による実装で高速な証明生成・検証
- **多様な証明タイプ**: 6種類の実用的なゼロ知識証明をサポート
- **複数のバックエンド**: Bulletproofs、SNARK、STARK の3つのバックエンド
- **Python統合**: シンプルで使いやすい Python API
- **型安全**: Rust の型システムによる安全性

## サポートする証明タイプ

| 証明タイプ | 説明 | 用途例 |
|-----------|------|--------|
| **範囲証明** (Range Proof) | 値が指定された範囲内にあることを証明 | 年齢証明、残高証明 |
| **等価性証明** (Equality Proof) | 2つの値が等しいことを証明 | 身元確認、データ整合性 |
| **しきい値証明** (Threshold Proof) | 値の合計が閾値以上であることを証明 | 投票システム、資産証明 |
| **集合所属証明** (Set Membership Proof) | 値が特定の集合に含まれることを証明 | ホワイトリスト、権限管理 |
| **向上証明** (Improvement Proof) | 値が増加したことを証明 | 成績向上、パフォーマンス改善 |
| **整合性証明** (Consistency Proof) | データが昇順に並んでいることを証明 | データ検証、監査 |

## バックエンド

- **Bulletproofs**: 効率的な範囲証明に特化
- **SNARK** (Succinct Non-interactive ARgument of Knowledge): 簡潔な証明サイズ
- **STARK** (Scalable Transparent ARgument of Knowledge): 量子耐性と透明性

## 必要な環境

- **Rust**: 1.70 以上
- **Python**: 3.8 以上
- **maturin**: 1.0 以上

## インストール

### 開発環境のセットアップ

1. Rust をインストール:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

2. maturin をインストール:
```bash
pip install maturin
```

3. プロジェクトをビルド:
```bash
maturin develop
```

## 使い方

### 基本的な使用例

```python
import libzkp
import hashlib

# 範囲証明: 値10が0以上20以下の範囲にあることを証明
proof = libzkp.prove_range(10, 0, 20)
assert libzkp.verify_range(proof, 0, 20)

# 等価性証明: 2つの値が等しいことを証明
proof = libzkp.prove_equality(5, 5)
commit = hashlib.sha256((5).to_bytes(8, 'little')).digest()
assert libzkp.verify_equality(proof, commit)

# しきい値証明: 値の合計が閾値以上であることを証明
proof = libzkp.prove_threshold([1, 2, 3], 5)
assert libzkp.verify_threshold(proof, 5)

# 集合所属証明: 値が集合に含まれることを証明
proof = libzkp.prove_membership(3, [1, 2, 3])
assert libzkp.verify_membership(proof, [1, 2, 3])

# 向上証明: 値が増加したことを証明
proof = libzkp.prove_improvement(1, 8)
assert libzkp.verify_improvement(proof, 1)

# 整合性証明: データが昇順であることを証明
proof = libzkp.prove_consistency([1, 2, 3])
assert libzkp.verify_consistency(proof)
```

### 実用的な例

```python
import libzkp

# 年齢証明（18歳以上であることを年齢を明かさずに証明）
def prove_adult_age(actual_age):
    if actual_age < 18:
        return None
    return libzkp.prove_range(actual_age, 18, 150)

def verify_adult_age(proof):
    return libzkp.verify_range(proof, 18, 150)

# 使用例
age_proof = prove_adult_age(25)  # 実際の年齢は秘匿
is_adult = verify_adult_age(age_proof)  # True
```
