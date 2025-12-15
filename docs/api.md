# libzkp API リファレンス

## 目次

1. [基本的な証明関数](#基本的な証明関数)
2. [高度な機能](#高度な機能)
3. [バッチ処理](#バッチ処理)
4. [パフォーマンス機能](#パフォーマンス機能)
5. [ユーティリティ関数](#ユーティリティ関数)
6. [エラー型](#エラー型)

## 基本的な証明関数

### 範囲証明 (Range Proof)

#### `prove_range(value: int, min: int, max: int) -> bytes`
指定された値が範囲内にあることを証明する証明を生成します。

**パラメータ:**
- `value`: 証明する値
- `min`: 範囲の最小値（含む）
- `max`: 範囲の最大値（含む）

**戻り値:** 証明データ（バイト列）

**例外:**
- `ValueError`: 値が範囲外の場合、または min > max の場合

**例:**
```python
proof = libzkp.prove_range(25, 18, 65)
```

#### `verify_range(proof: bytes, min: int, max: int) -> bool`
範囲証明を検証します。

**パラメータ:**
- `proof`: 証明データ
- `min`: 範囲の最小値
- `max`: 範囲の最大値

**戻り値:** 証明が有効な場合 True、無効な場合 False

### 等価性証明 (Equality Proof)

#### `prove_equality(val1: int, val2: int) -> bytes`
2つの値が等しいことを証明する証明を生成します。

**パラメータ:**
- `val1`: 最初の値
- `val2`: 2番目の値

**戻り値:** 証明データ（バイト列）

**例外:**
- `ValueError`: val1 != val2 の場合

#### `verify_equality(proof: bytes, val1: int, val2: int) -> bool`
等価性証明を検証します。

**パラメータ:**
- `proof`: 証明データ
- `val1`: 1つ目の値
- `val2`: 2つ目の値

**戻り値:** 証明が有効な場合 True

#### `verify_equality_with_commitment(proof: bytes, expected_commitment: bytes) -> bool`
コミットメント（32バイト）を明示的に指定して等価性証明を検証します。

等価性証明は、`a == b` に加えて、`a` の 64-bit 整数のリトルエンディアン表現（8バイト）に対する `SHA-256` の値が公開入力のコミットメントと一致することを回路内で拘束します。したがって `expected_commitment` は以下のように計算してください。

```python
import hashlib

val = 42
expected_commitment = hashlib.sha256(val.to_bytes(8, byteorder="little")).digest()
is_valid = libzkp.verify_equality_with_commitment(proof, expected_commitment)
```

**パラメータ:**
- `proof`: 証明データ
- `expected_commitment`: 期待される32バイトのコミットメント（SHA-256）

**戻り値:** 証明が有効な場合 True

### しきい値証明 (Threshold Proof)

#### `prove_threshold(values: List[int], threshold: int) -> bytes`
値の合計が閾値以上であることを証明します。

**パラメータ:**
- `values`: 値のリスト
- `threshold`: 閾値

**戻り値:** 証明データ

**例外:**
- `ValueError`: 合計が閾値未満、または内部計算に問題がある場合

#### `verify_threshold(proof: bytes, threshold: int) -> bool`
しきい値証明を検証します。

### 集合所属証明 (Set Membership Proof)

SNARK（Groth16）により、値とインデックスを秘匿したまま「値が集合 set のいずれかに等しい」ことを証明します。集合サイズは **最大64** まで対応（回路の公開入力としては 64 要素にパディングされます）。コミットメントは `SHA-256(value.to_le_bytes(8))` を公開入力として検証します。

#### `prove_membership(value: int, set: List[int]) -> bytes`
値が集合に含まれることを零知識で証明する証明を生成します（値・インデックスは非公開）。

**パラメータ:**
- `value`: 証明する値
- `set`: 値の集合（**1〜64要素**。重複は技術的には許容されますが、意味の曖昧さを避けるためユニークを推奨）

**戻り値:** 証明データ

**例外:**
- `ValueError`: 空集合、または値が集合に含まれない場合
- `RuntimeError`: 集合サイズが大きすぎる等により SNARK 証明生成に失敗した場合

#### `verify_membership(proof: bytes, set: List[int]) -> bool`
集合所属証明を検証します（公開入力は `set` と `SHA-256(value.to_le_bytes(8))` に対応）。

注意: 証明バイト列には検証のための最小限のセット情報が埋め込まれます（サイズと内容）。検証時に渡した `set` と一致するかをチェックした上で、SNARK検証を行います。値と一致インデックスは秘匿されます。

### 向上証明 (Improvement Proof)

#### `prove_improvement(old: int, new: int) -> bytes`
値が増加したことを証明します（STARKバックエンド使用）。

**パラメータ:**
- `old`: 古い値
- `new`: 新しい値

**戻り値:** 証明データ

**例外:**
- `ValueError`: new <= old の場合

#### `verify_improvement(proof: bytes, old: int) -> bool`
向上証明を検証します。

### 整合性証明 (Consistency Proof)

#### `prove_consistency(data: List[int]) -> bytes`
データが昇順に並んでいることを証明します。

**パラメータ:**
- `data`: 整数のリスト

**戻り値:** 証明データ

**例外:**
- `ValueError`: データが昇順でない場合、または空の場合

#### `verify_consistency(proof: bytes) -> bool`
整合性証明を検証します。

## 高度な機能

### 複合証明

#### `create_composite_proof(proofs: List[bytes]) -> bytes`
複数の証明を組み合わせて複合証明を作成します。

**パラメータ:**
- `proofs`: 証明のリスト

**戻り値:** 複合証明データ

#### `verify_composite_proof(composite_proof: bytes) -> bool`
複合証明を検証します。

### メタデータ付き証明

#### `create_proof_with_metadata(proof: bytes, metadata: Dict[str, bytes]) -> bytes`
証明にメタデータを付加します。

**パラメータ:**
- `proof`: 元の証明データ
- `metadata`: メタデータの辞書（キーは文字列、値はバイト列）

**戻り値:** メタデータ付き証明

#### `extract_proof_metadata(proof_with_metadata: bytes) -> Dict[str, bytes]`
証明からメタデータを抽出します。

## バッチ処理

### バッチ管理

#### `create_proof_batch() -> int`
新しい証明バッチを作成します。

**戻り値:** バッチID

#### `get_batch_status(batch_id: int) -> Dict[str, int]`
バッチの状態を取得します。

**戻り値:** 状態情報の辞書
- `total_operations`: 総操作数
- `range_proofs`: 範囲証明の数
- `equality_proofs`: 等価性証明の数
- `threshold_proofs`: しきい値証明の数
- `membership_proofs`: 集合所属証明の数
- `improvement_proofs`: 向上証明の数
- `consistency_proofs`: 整合性証明の数

#### `clear_batch(batch_id: int) -> None`
指定されたバッチをクリアします。

### バッチへの証明追加

#### `batch_add_range_proof(batch_id: int, value: int, min: int, max: int) -> None`
範囲証明をバッチに追加します。

#### `batch_add_equality_proof(batch_id: int, val1: int, val2: int) -> None`
等価性証明をバッチに追加します。

#### `batch_add_threshold_proof(batch_id: int, values: List[int], threshold: int) -> None`
しきい値証明をバッチに追加します。

### バッチ処理

#### `process_batch(batch_id: int) -> List[bytes]`
バッチ内の全ての証明を並列で生成します。

**戻り値:** 生成された証明のリスト

**例外:**
- `ValueError`: 無効なバッチIDの場合
- `RuntimeError`: 証明生成に失敗した場合

注意: `process_batch` は内部レジストリからバッチを **取り除いて処理します**（バッチIDは消費されます）。そのため、`process_batch` 実行後に同じ `batch_id` で `get_batch_status` や `batch_add_*` を呼ぶと失敗します。

## パフォーマンス機能

### キャッシング

#### `prove_range_cached(value: int, min: int, max: int) -> bytes`
キャッシュを使用した範囲証明の生成。

#### `clear_cache() -> None`
グローバル証明キャッシュをクリアします。

#### `get_cache_stats() -> Dict[str, int]`
キャッシュの統計情報を取得します。

### パフォーマンス監視

#### `enable_performance_monitoring() -> bool`
パフォーマンス監視（メトリクス収集器）を初期化します。成功時に True を返します。

#### `get_performance_metrics() -> Dict[str, float]`
パフォーマンスメトリクスを取得します。

#### `benchmark_proof_generation(proof_type: str, iterations: int) -> Dict[str, str]`
証明生成のベンチマークを実行します。

**パラメータ:**
- `proof_type`: 証明タイプ（"range", "equality", "threshold", "membership", "improvement", "consistency"）
- `iterations`: 繰り返し回数

**戻り値:** すべて文字列として返されます（必要に応じて `float(...)` で変換してください）。
- `proof_type`: テストされた証明タイプ
- `iterations`: 要求された繰り返し回数
- `successful_iterations`: 成功した繰り返し回数
- `success_rate`: 成功率（パーセント）
- `total_time_ms`: 総実行時間（ミリ秒）
- `avg_time_ms`: 平均実行時間（ミリ秒）
- `min_time_ms`: 最小実行時間（ミリ秒）
- `max_time_ms`: 最大実行時間（ミリ秒）
- `std_dev_ms`: 標準偏差（ミリ秒）
- `proofs_per_second`: 1秒あたりの証明生成数
- `throughput_ms_per_proof`: 証明1つあたりの処理時間（ミリ秒）

**例外:**
- `ValueError`: 無効な証明タイプまたは繰り返し回数の場合
- `RuntimeError`: 証明生成に失敗した場合

### 並列処理

#### `verify_proofs_parallel(proofs: List[Tuple[bytes, str]]) -> List[bool]`
複数の証明を並列で検証します（各タイプに対してバックエンド検証を実行）。

**パラメータ:**
- `proofs`: (証明データ, 証明タイプ) のタプルのリスト
  - 証明タイプ: "range", "equality", "threshold", "membership", "improvement", "consistency"

**戻り値:** 各証明の検証結果のリスト

### バッチ追加APIの拡充

#### `batch_add_membership_proof(batch_id: int, value: int, set: List[int]) -> None`
集合所属証明をバッチに追加します。

#### `batch_add_improvement_proof(batch_id: int, old: int, new: int) -> None`
向上証明をバッチに追加します。

#### `batch_add_consistency_proof(batch_id: int, data: List[int]) -> None`
整合性証明をバッチに追加します。

## ユーティリティ関数

### 証明情報

#### `get_proof_info(proof: bytes) -> Dict[str, Any]`
証明の詳細情報を取得します。

**戻り値:**
- `version`: 証明のバージョン
- `scheme`: 証明スキームID
- `proof_size`: 証明サイズ（バイト）
- `commitment_size`: コミットメントサイズ

### 証明チェーン検証

#### `validate_proof_chain(proofs: List[bytes]) -> bool`
証明チェーンの整合性を検証します。

### 最適化された証明生成

#### `prove_equality_advanced(val1: int, val2: int, context: Optional[bytes]) -> bytes`
コンテキスト付きの高度な等価性証明を生成します。

#### `prove_threshold_optimized(values: List[int], threshold: int) -> bytes`
最適化されたしきい値証明を生成します。

## エラー型

libzkpは以下のPython例外を発生させる可能性があります：

- `ValueError`: 無効な入力パラメータ
- `OverflowError`: 整数オーバーフロー
- `TypeError`: 無効な証明フォーマット
- `RuntimeError`: バックエンドエラー、証明生成失敗など

各関数は適切なエラーメッセージと共に例外を発生させます。