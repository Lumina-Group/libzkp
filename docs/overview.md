# libzkp ドキュメント

`libzkp` は高性能なゼロ知識証明ライブラリです。Rustで実装され、Pythonバインディングを提供します。

## 主な特徴

- **3つの暗号学的バックエンド**: Bulletproofs、SNARK (Groth16)、STARK
- **6種類の証明タイプ**: 範囲、等価性、しきい値、集合所属、向上、整合性
- **高度な機能**: バッチ処理、並列検証、キャッシング、メタデータサポート
- **包括的なエラーハンドリング**: 詳細なエラーメッセージと型安全性

## Python API

### 基本的な証明関数

| 関数名 | 説明 | バックエンド |
| --- | --- | --- |
| `prove_range(value, min, max)` | `min` 以上 `max` 以下に値が存在することを示す範囲証明を生成します。 | Bulletproofs |
| `verify_range(proof, min, max)` | 範囲証明を検証します。 | Bulletproofs |
| `prove_equality(val1, val2)` | 2 つの値が等しいことを示す証明を生成します。 | SNARK |
| `verify_equality(proof, commitment)` | 等価性証明を検証します。 | SNARK |
| `prove_threshold(values, threshold)` | `values` の総和が `threshold` 以上であることを示す証明を生成します。 | Bulletproofs |
| `verify_threshold(proof, threshold)` | しきい値証明を検証します。 | Bulletproofs |
| `prove_membership(value, set)` | 値が集合 `set` に含まれることを示す証明を生成します。 | Bulletproofs |
| `verify_membership(proof, set)` | 集合所属証明を検証します。 | Bulletproofs |
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
| `process_batch(batch_id)` | バッチ内の全証明を並列生成します。 |
| `get_batch_status(batch_id)` | バッチの状態を取得します。 |
| `clear_batch(batch_id)` | バッチをクリアします。 |

#### パフォーマンス機能
| 関数名 | 説明 |
| --- | --- |
| `prove_range_cached(value, min, max)` | キャッシュを使用した範囲証明の生成。 |
| `verify_proofs_parallel(proofs)` | 複数の証明を並列で検証します。 |
| `benchmark_proof_generation(proof_type, iterations)` | 証明生成のベンチマークを実行します。 |
| `enable_performance_monitoring(enabled)` | パフォーマンス監視を有効/無効にします。 |
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

Python のテスト:
```bash
python test_improvements.py
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
│   ├── utils/           # ユーティリティ
│   │   ├── error_handling.rs
│   │   ├── performance.rs
│   │   └── validation.rs
│   └── *.rs            # 各証明タイプの実装
├── docs/               # ドキュメント
├── examples/           # サンプルコード
└── tests/             # テストコード
```

### エラーハンドリング

libzkpは以下のエラータイプを提供します：

- `InvalidInput`: 無効な入力パラメータ
- `ProofGenerationFailed`: 証明生成の失敗
- `VerificationFailed`: 検証の失敗
- `IntegerOverflow`: 整数オーバーフロー
- `BackendError`: バックエンドエラー

詳細なAPIリファレンスは[api.md](api.md)を参照してください。
