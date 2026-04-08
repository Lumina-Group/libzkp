# libzkp
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Lumina-Group/libzkp)

libzkp は、Python、Rust から利用可能なゼロ知識証明 (Zero-Knowledge Proof) ライブラリです。Rust で実装されており、PyO3 と maturin を用いて Python モジュールとしてビルドできます。

## 特徴

### 基本機能
- **高性能**: Rust による実装で高速な証明生成・検証
- **多様な証明タイプ**: 6種類の実用的なゼロ知識証明をサポート
- **複数のバックエンド**: Bulletproofs、SNARK、STARK の3つのバックエンド
- **Python統合**: シンプルで使いやすい Python API
- **Rust での堅牢性**: 型と所有権により実装ミスを抑止（暗号スキームとしての安全性は各バックエンドの仮定に依存）

### 高度な機能
- **証明合成**: 複数の証明を組み合わせた複合証明の作成・検証
- **パフォーマンス最適化**: キャッシング、並列処理、メモリプール
- **バッチ処理**: 複数の証明を効率的に一括生成
- **メタデータサポート**: 証明にコンテキスト情報を付加
- **エラーハンドリング**: 包括的なエラー処理と検証
- **ベンチマーク機能**: パフォーマンス測定とプロファイリング
- **ユーティリティ**: 共通処理の統合とコード重複の削減
- **SNARKキー永続化**: 環境変数`LIBZKP_SNARK_KEY_DIR`や`set_snark_key_dir`でGroth16鍵をディスク保存・再利用

## サポートする証明タイプ

| 証明タイプ | 説明 | 用途例 | バックエンド |
|-----------|------|--------|-------------|
| **範囲証明** (Range Proof) | 値が指定された範囲内にあることを証明 | 年齢証明、残高証明 | Bulletproofs |
| **等価性証明** (Equality Proof) | 2つの値が等しいことを証明 | 身元確認、データ整合性 | SNARK (Groth16) |
| **しきい値証明** (Threshold Proof) | 値の合計が閾値以上であることを証明 | 投票システム、資産証明 | Bulletproofs |
| **集合所属証明** (Set Membership Proof) | 値が集合のいずれかに等しいことを、値と選択インデックスを秘匿して証明（**集合そのものは検証時に検証者が知る公開入力**） | ホワイトリスト、権限管理 | SNARK (Groth16) |
| **向上証明** (Improvement Proof) | `old` から `new` へ値が増加したことを証明（**証明バイトに `new` が含まれる**ため、新値を検証者に秘匿する用途には不向き） | 成績向上、パフォーマンス改善 | STARK |
| **整合性証明** (Consistency Proof) | データ列が**単調非減少**であることを証明（隣接で `a[i] <= a[i+1]`、同一値の連続を許す） | データ検証、監査 | Bulletproofs |

## バックエンド

### Bulletproofs
- **特徴**: 効率的な範囲証明に特化、証明サイズが対数的
- **用途**: 範囲証明、しきい値証明、整合性証明
- **実装**: curve25519-dalek と bulletproofs クレートを使用

### SNARK (Groth16)
- **特徴**: 非常に小さい証明サイズ、高速な検証
- **用途**: 等価性・集合所属。公開入力の値コミットメントは **MiMC-5（BN254 Fr）から導いた 32 バイト**（SHA-256 ではない）。`verify_equality_with_commitment` では `snark_commit_value` で同じコミットメントを計算する。
- **実装**: arkworks ライブラリ (ark-groth16) を使用

### STARK
- **特徴**: 透明性（trusted setup 不要）。「量子耐性」や実効セキュリティは **Winterfell のパラメータ（クエリ数・ブローアップ・フィールドサイズ等）に依存**し、用途に応じた評価が必要。
- **用途**: 向上証明（証明ペイロード先頭に `old` / `new` が平文で含まれる）
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

Python バインディングなしで Rust ライブラリのみビルドする場合（デフォルト機能の `python` を外します）:

```bash
cargo build --no-default-features
```

## 使い方

### 基本的な使用例

```python
import libzkp

# 範囲証明: 値10が0以上20以下の範囲にあることを証明
proof = libzkp.prove_range(10, 0, 20)
assert libzkp.verify_range(proof, 0, 20)

# 等価性証明: 2つの値が等しいことを証明
proof = libzkp.prove_equality(5, 5)
# 値による検証
assert libzkp.verify_equality(proof, 5, 5)
# コミットメント指定による検証（32バイト、Groth16 用 MiMC コミットメント）
commit = libzkp.snark_commit_value(5)
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

# 整合性証明: データが単調非減少であることを証明
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

プロセス内キャッシュに秘密値をキーとして載せないよう、運用上のキー設計に注意してください（詳細は下記「プライバシーと運用」）。

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

#### バッチのディスク永続化（オプション）

```python
# ディレクトリを指定（または環境変数 LIBZKP_BATCH_DIR）
libzkp.set_batch_store_dir("C:/zkp_batches")

bid = libzkp.create_proof_batch()
libzkp.batch_add_range_proof(bid, 10, 0, 100)
# 別プロセスが同じバッチ ID のファイルへ追記したあと、このプロセスのメモリへ反映:
libzkp.refresh_batch_from_store(bid)

# 再起動後など、まだメモリに載っていない ID をディスクから読み込む:
# libzkp.open_batch_from_store(existing_id)
```

同一 `batch_id` に対する複数プロセスからの同時 `batch_add_*` は想定外です（単一ライター推奨）。バッチファイルにはパラメータが平文で含まれます。

#### SNARK鍵の永続化と再利用

```python
# Groth16 の鍵をディスクに保存・再利用（初回のみ生成）
# 環境変数でも指定可能: LIBZKP_SNARK_KEY_DIR=/path/to/keys
libzkp.set_snark_key_dir("C:/zkp_keys")

print(libzkp.is_snark_setup_initialized())  # 既にメモリにロード済みか確認

# その後に等価性・集合所属の証明/検証を実行
proof = libzkp.prove_equality(10, 10)
assert libzkp.verify_equality(proof, 10, 10)
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
4. **パフォーマンス監視**: `get_performance_metrics`でメトリクスを取得（収集は初回利用時に初期化）

## プライバシーと運用

- **複合証明の `composition_hash`**: 末尾の値は証明列とメタデータに対する **整合性用の SHA-256 ダイジェスト**です。**鍵を伴わない**ため、同じ内容を知る者は誰でも同じ値を再計算でき、MAC のような発行者認証や秘匿性はありません。束ねたバイト列が意図したものかの検査に使い、**偽証耐性は各内側証明の暗号検証**に依存します。発行者認証が必要な場合は、複合証明バイト列に対する **アプリ層の署名や MAC** を別途使ってください。
- **キャッシュ**: `prove_range_cached` 等は **プロセス内**のキャッシュにパラメータ由来の情報が残り得ます。キャッシュキーにはプロセス固有の値が混ざりますが、同一プロセス内では入力に応じて一意に決まります。秘密をそのままキーに含めないでください。機密性の高い環境では **`clear_cache` を使う**か、キャッシュを使わない通常の証明 API を選んでください。
- **バッチ**: バッチ ID は **暗号学的乱数（`u64`）**で同一プロセス内の推測を緩和しています。デフォルトではレジストリは **インメモリ**です。オプションで `set_batch_store_dir` または `LIBZKP_BATCH_DIR` によりディスクへ永続化し、他プロセスが書いた内容は `refresh_batch_from_store`、コールドスタートは `open_batch_from_store` で取り込めます（詳細は [api.md](docs/api.md)）。
- **依存関係**: 公開されている脆弱性への対応のため、**`cargo audit`（または同等）でアドバイザリを追跡**してください。本リポジトリでは CI で `cargo audit` を実行します（`.github/workflows` を参照）。

## API リファレンス

詳細なAPIドキュメントは[api.md](docs/api.md)を参照してください。

## 貢献

プルリクエストを歓迎します。大きな変更を行う場合は、まずissueを開いて変更内容について議論してください。

## ライセンス

Apache License 2.0 - 詳細は[LICENSE](LICENSE)ファイルを参照してください。
