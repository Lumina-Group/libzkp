# libzkp
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)

libzkp は、Python、Rust から利用可能なゼロ知識証明 (Zero-Knowledge Proof) ライブラリです。Rust で実装されており、PyO3 と maturin を用いて Python モジュールとしてビルドできます。

## 特徴

### 基本機能
- **高性能**: Rust による実装で高速な証明生成・検証
- **多様な証明タイプ**: 6種類の実用的なゼロ知識証明をサポート
- **複数のバックエンド**: Bulletproofs、SNARK、STARK の3つのバックエンド
- **Python統合**: シンプルで使いやすい Python API
- **型安全**: Rust の型システムによる安全性

### 高度な機能
- **証明合成**: 複数の証明を組み合わせた複合証明の作成・検証
- **パフォーマンス最適化**: キャッシング、並列処理、メモリプール
- **バッチ処理**: 複数の証明を効率的に一括生成
- **メタデータサポート**: 証明にコンテキスト情報を付加
- **エラーハンドリング**: 包括的なエラー処理と検証
- **ベンチマーク機能**: パフォーマンス測定とプロファイリング
- **ユーティリティ**: 共通処理の統合とコード重複の削減

## サポートする証明タイプ

| 証明タイプ | 説明 | 用途例 | バックエンド |
|-----------|------|--------|-------------|
| **範囲証明** (Range Proof) | 値が指定された範囲内にあることを証明 | 年齢証明、残高証明 | Bulletproofs |
| **等価性証明** (Equality Proof) | 2つの値が等しいことを証明 | 身元確認、データ整合性 | SNARK (Groth16) |
| **しきい値証明** (Threshold Proof) | 値の合計が閾値以上であることを証明 | 投票システム、資産証明 | Bulletproofs |
| **集合所属証明** (Set Membership Proof) | 値が特定の集合に含まれることを証明 | ホワイトリスト、権限管理 | Pedersenコミットメント＋整合検証 |
| **向上証明** (Improvement Proof) | 値が増加したことを証明 | 成績向上、パフォーマンス改善 | STARK |
| **整合性証明** (Consistency Proof) | データが昇順に並んでいることを証明 | データ検証、監査 | Bulletproofs |

## バックエンド

### Bulletproofs
- **特徴**: 効率的な範囲証明に特化、証明サイズが対数的
- **用途**: 範囲証明、しきい値証明、集合所属証明、整合性証明
- **実装**: curve25519-dalek と bulletproofs クレートを使用

### SNARK (Groth16)
- **特徴**: 非常に小さい証明サイズ、高速な検証
- **用途**: 等価性証明（8バイトLE整数のSHA-256コミットメントを公開入力として32個のフィールド要素にマッピングして検証）
- **実装**: arkworks ライブラリ (ark-groth16) を使用

### STARK
- **特徴**: 量子耐性、透明性（信頼されたセットアップ不要）
- **用途**: 向上証明
- **実装**: winterfell フレームワークを使用

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

2. Python 仮想環境を作成:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# または
venv\Scripts\activate  # Windows
```

3. maturin をインストール:
```bash
pip install maturin
```

4. プロジェクトをビルド:
```bash
maturin develop --release
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
# 値による検証
assert libzkp.verify_equality(proof, 5, 5)
# コミットメント指定による検証（32バイト）
commit = hashlib.sha256((5).to_bytes(8, 'little')).digest()
assert libzkp.verify_equality_with_commitment(proof, commit)

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

### 高度な機能

#### 証明の合成と組み合わせ

```python
# 複数の証明を組み合わせて複合証明を作成
range_proof = libzkp.prove_range(25, 18, 65)
equality_proof = libzkp.prove_equality(100, 100)
threshold_proof = libzkp.prove_threshold([50, 30, 20], 90)

# 複合証明の作成
composite_proof = libzkp.create_composite_proof([range_proof, equality_proof, threshold_proof])

# 複合証明の検証
is_valid = libzkp.verify_composite_proof(composite_proof)
```

#### パフォーマンス最適化とキャッシング

```python
# キャッシュ機能付きの証明生成（高速化）
proof = libzkp.prove_range_cached(50, 0, 100)

# 並列検証
proofs = [(proof1, "range"), (proof2, "equality"), (proof3, "threshold")]
results = libzkp.verify_proofs_parallel(proofs)

# パフォーマンスベンチマーク
metrics = libzkp.benchmark_proof_generation("range", 100)
print(f"平均時間: {float(metrics['avg_time_ms']):.2f}ms")
print(f"スループット: {float(metrics['proofs_per_second']):.2f} proofs/sec")
```

#### メタデータ付き証明

```python
import time

# メタデータを含む証明の作成
metadata = {
    "purpose": b"identity_verification",
    "timestamp": str(int(time.time())).encode(),
    "issuer": b"authority"
}
proof_with_metadata = libzkp.create_proof_with_metadata(proof, metadata)

# メタデータの抽出
extracted_metadata = libzkp.extract_proof_metadata(proof_with_metadata)
```

#### バッチ処理

```python
# バッチ処理による効率化
batch_id = libzkp.create_proof_batch()

# 各種証明をバッチに追加
libzkp.batch_add_range_proof(batch_id, 25, 18, 65)
libzkp.batch_add_equality_proof(batch_id, 100, 100)
libzkp.batch_add_threshold_proof(batch_id, [10, 20, 30], 50)

# バッチの状態確認
status = libzkp.get_batch_status(batch_id)
print(f"Total operations: {status['total_operations']}")
print(f"Range proofs: {status['range_proofs']}")

# バッチを処理して全ての証明を生成
batch_results = libzkp.process_batch(batch_id)
```

### 実用的な例

#### 年齢証明システム

```python
import libzkp
import time

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

#### 金融サービスのKYC（本人確認）

```python
def create_kyc_proof(age, balance, country_code):
    """包括的なKYC証明を作成"""
    # バッチ処理で効率的に生成
    batch_id = libzkp.create_proof_batch()

    # 年齢証明（18歳以上）
    libzkp.batch_add_range_proof(batch_id, age, 18, 150)

    # 残高証明（最低残高以上）
    libzkp.batch_add_range_proof(batch_id, balance, 1000, 10000000)

    # 国籍証明（承認された国のリスト）
    approved_countries = [1, 2, 3, 44, 81]  # USA, Canada, France, UK, Japan
    libzkp.batch_add_membership_proof(batch_id, country_code, approved_countries)

    # バッチ処理（全証明を生成）
    proofs = libzkp.process_batch(batch_id)

    # 複合証明の作成
    kyc_proof = libzkp.create_composite_proof(proofs)
    
    # メタデータの追加
    metadata = {
        "verification_type": b"financial_kyc",
        "timestamp": str(int(time.time())).encode(),
        "risk_level": b"low"
    }
    
    return libzkp.create_proof_with_metadata(kyc_proof, metadata)

# 使用例
kyc_proof = create_kyc_proof(age=25, balance=5000, country_code=1)
is_verified = libzkp.verify_composite_proof(kyc_proof)
```

## エラーハンドリング

libzkp は包括的なエラーハンドリングを提供します：

```python
try:
    # 範囲外の値
    proof = libzkp.prove_range(150, 0, 100)
except ValueError as e:
    print(f"検証エラー: {e}")
    # "Invalid input: Value 150 is outside the valid range [0, 100]"

try:
    # 整数オーバーフロー
    proof = libzkp.prove_threshold([2**63, 2**63], 2**64)
except OverflowError as e:
    print(f"オーバーフローエラー: {e}")

try:
    # 無効なバッチID
    libzkp.get_batch_status(999999)
except ValueError as e:
    print(f"バッチエラー: {e}")
    # "Invalid input: Invalid batch ID: 999999"
```

## パフォーマンス

### ベンチマーク結果（参考値）

| 証明タイプ | 生成時間 | 検証時間 | 証明サイズ |
|-----------|---------|---------|------------|
| 範囲証明 | ~5ms | ~2ms | ~1KB |
| 等価性証明 | ~10ms | ~3ms | ~200B |
| しきい値証明 | ~8ms | ~3ms | ~1.5KB |
| 集合所属証明 | ~6ms | ~2ms | ~1KB |
| 向上証明 | ~15ms | ~5ms | ~2KB |
| 整合性証明 | ~10ms | ~4ms | ~2KB |

### 最適化のヒント

1. **バッチ処理**: 複数の証明を生成する場合は、バッチ処理APIを使用
2. **並列検証**: 複数の証明を検証する場合は、`verify_proofs_parallel`を使用
3. **キャッシング**: 同じパラメータで繰り返し証明を生成する場合は、キャッシュ機能を活用
4. **パフォーマンス監視**: `enable_performance_monitoring`でメトリクスを収集

## API リファレンス

詳細なAPIドキュメントは[api.md](docs/api.md)を参照してください。

## 貢献

プルリクエストを歓迎します。大きな変更を行う場合は、まずissueを開いて変更内容について議論してください。

## ライセンス

Apache License 2.0 - 詳細は[LICENSE](LICENSE)ファイルを参照してください。
