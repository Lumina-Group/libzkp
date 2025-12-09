# libzkp ドキュメント

`libzkp` は高性能なゼロ知識証明ライブラリです。Rustで実装され、Pythonバインディングを提供します。等価性証明については SNARK (Groth16) を用い、回路内で 64-bit 整数制約と SHA-256 コミットメント整合性を検証します（8バイトLEの整数に対するSHA-256の32バイト値を公開入力として32個のフィールド要素にマップして検証）。

## 主な特徴

- **3つの暗号学的バックエンド**: Bulletproofs、SNARK (Groth16)、STARK
- **6種類の証明タイプ**: 範囲、等価性、しきい値、集合所属、向上、整合性
- **高度な機能**: バッチ処理、並列検証、キャッシング、メタデータサポート
 - **包括的なエラーハンドリング**: 詳細なエラーメッセージと型安全性（内部のロック失敗やセットアップ失敗は例外として返却）
- **SNARK鍵の永続化**: 環境変数`LIBZKP_SNARK_KEY_DIR`またはPython API `set_snark_key_dir`でGroth16鍵をディスクに保存し、再起動後も再利用

## Python API

### 基本的な証明関数

| 関数名 | 説明 | バックエンド |
| --- | --- | --- |
| `prove_range(value, min, max)` | `min` 以上 `max` 以下に値が存在することを示す範囲証明を生成します。 | Bulletproofs |
| `verify_range(proof, min, max)` | 範囲証明を検証します。 | Bulletproofs |
| `prove_equality(val1, val2)` | 2 つの値が等しいことを示す証明を生成します。 | SNARK |
| `verify_equality(proof, val1, val2)` | 等価性証明を値を用いて検証します。 | SNARK |
| `verify_equality_with_commitment(proof, expected_commitment)` | 期待コミットメント（32バイト）を用いて検証します。 | SNARK |
| `prove_threshold(values, threshold)` | `values` の総和が `threshold` 以上であることを示す証明を生成します。 | Bulletproofs |
| `verify_threshold(proof, threshold)` | しきい値証明を検証します。 | Bulletproofs |
| `prove_membership(value, set)` | 値が集合 `set` に含まれることを、値とインデックスを秘匿したまま証明します。 | SNARK |
| `verify_membership(proof, set)` | 集合所属証明を検証します。 | SNARK |
| `prove_improvement(old, new)` | `old` から `new` へ値が増加したことを示す証明を生成します。 | STARK |
| `verify_improvement(proof, old)` | 向上証明を検証します。 | STARK |
| `prove_consistency(data)` | 昇順に並んだデータ列であることを示す整合性証明を生成します。 | Bulletproofs |
| `verify_consistency(proof)` | 整合性証明を検証します。 | Bulletproofs |

### 高度な機能

#### バッチ処理
| 関数名 | 説明 |
| --- | --- |
| `create_proof_batch()` | 新しい証明バッチを作成し、バッチIDを返します。 |
| `batch_add_range_proof(batch_id, value, min, max)` | 範囲証明をバッチに追加します。 |
| `batch_add_equality_proof(batch_id, val1, val2)` | 等価性証明をバッチに追加します。 |
| `batch_add_threshold_proof(batch_id, values, threshold)` | しきい値証明をバッチに追加します。 |
| `batch_add_membership_proof(batch_id, value, set)` | 集合所属証明をバッチに追加します。 |
| `batch_add_improvement_proof(batch_id, old, new)` | 向上証明をバッチに追加します。 |
| `batch_add_consistency_proof(batch_id, data)` | 整合性証明をバッチに追加します。 |
| `process_batch(batch_id)` | バッチ内の全証明を並列生成します。 |
| `get_batch_status(batch_id)` | バッチの状態を取得します。 |
| `clear_batch(batch_id)` | バッチをクリアします。 |

#### パフォーマンス機能
| 関数名 | 説明 |
| --- | --- |
| `prove_range_cached(value, min, max)` | キャッシュを使用した範囲証明の生成。 |
| `clear_cache()` | グローバルキャッシュをクリアします。 |
| `get_cache_stats()` | キャッシュ統計（`size`）を返します。 |
| `verify_proofs_parallel(proofs)` | 複数の証明を並列で検証します。 |
| `benchmark_proof_generation(proof_type, iterations)` | 証明生成のベンチマークを実行します。 |
| `enable_performance_monitoring()` | パフォーマンス監視を初期化します。 |
| `get_performance_metrics()` | パフォーマンスメトリクスを取得します。 |

#### 複合証明とメタデータ
| 関数名 | 説明 |
| --- | --- |
| `create_composite_proof(proofs)` | 複数の証明を組み合わせて複合証明を作成します。 |
| `verify_composite_proof(composite_proof)` | 複合証明を検証します。 |
| `create_proof_with_metadata(proof, metadata)` | 証明にメタデータを付加します。 |
| `extract_proof_metadata(proof_with_metadata)` | 証明からメタデータを抽出します。 |

## ビルド方法

### 開発環境のセットアップ

1. Python仮想環境を作成:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# または
venv\Scripts\activate  # Windows
```

2. 必要なパッケージをインストール:
```bash
pip install maturin
```

3. ライブラリをビルド:
```bash
maturin develop --release
```

### テストの実行

Rust のテスト:
```bash
cargo test
```

## アーキテクチャ

### ディレクトリ構造
```
libzkp/
├── src/
│   ├── backend/          # 暗号学的バックエンド
│   │   ├── bulletproofs.rs
│   │   ├── snark.rs
│   │   └── stark.rs
│   ├── proof/            # 各証明の実装
│   │   ├── range_proof.rs
│   │   ├── equality_proof.rs
│   │   ├── threshold_proof.rs
│   │   ├── set_membership.rs
│   │   ├── improvement_proof.rs
│   │   └── consistency_proof.rs
│   ├── advanced/         # 複合・バッチ・拡張API
│   │   ├── composite.rs
│   │   └── batch.rs
│   ├── utils/            # ユーティリティ
│   │   ├── commitment.rs
│   │   ├── composition.rs
│   │   ├── error_handling.rs
│   │   ├── performance.rs
│   │   ├── proof_helpers.rs
│   │   ├── serialization.rs
│   │   └── validation.rs
│   └── lib.rs
├── docs/                 # ドキュメント
├── README.md
└── Cargo.toml
```

### エラーハンドリング

libzkpは以下のエラータイプを提供します：

- `InvalidInput`: 無効な入力パラメータ
- `ProofGenerationFailed`: 証明生成の失敗
- `VerificationFailed`: 検証の失敗
- `InvalidProofFormat`: 無効な証明フォーマット
- `BackendError`: バックエンドエラー
- `SerializationError`: シリアライズ/デシリアライズ失敗
- `ValidationError`: 入力検証エラー
- `IntegerOverflow`: 整数オーバーフロー
- `CryptoError`: 暗号処理の失敗
- `ConfigError`: 設定値の不正

詳細なAPIリファレンスは[api.md](api.md)を参照してください。
