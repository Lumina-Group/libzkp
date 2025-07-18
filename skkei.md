# libzkp 設計概要

---

## 0. 移行・拡張方針

- **本プロジェクトでは、既存の `bulletproofs_rs` ライブラリを `libzkp` に名称変更し、今後は範囲証明（range proof）だけでなく等価性証明・閾値証明・改善証明・一貫性証明など多様なZKPスキームをRustで実装・拡張していきます。**
- `libzkp` はVinciプロトコルのZKP基盤として、利用・拡張性・安全性を重視した設計となります。
- 既存の `bulletproofs_rs` コード・APIは `libzkp` に統合され、今後は `libzkp` 名義で開発・保守・拡張を行います。

### 詳細な説明

- **移行理由**: bulletproofs_rsは範囲証明（range proof）に特化していましたが、時代の要請に応えるため、より多様なZKP（等価性・閾値・改善・一貫性・集合メンバーシップ等）を統一的に扱える基盤が必要となりました。そのため、名称をlibzkpとし、ZKPの総合的な拡張・運用を目指します。
- **設計の特徴**:
    - Rustによる高速・安全なZKPロジック
    - PyO3バインディングでPythonからの利用を容易に
    - スキームごとに `prove_xxx`/`verify_xxx` APIを提供し、拡張・自動化に強い
    - 型安全・エラー処理・テスト容易性を重視
- **既存のbulletproofs_rsユーザーは、libzkpへの移行でAPIの上位互換性を維持しつつ、今後の新機能・新スキームを享受できます。**

### 今後の拡張例

- **zk-SNARKs/zk-STARKs等の先進的ZKPスキームの追加**
    - 任意の論理式・回路のZKPをRustで実装し、libzkpから呼び出し可能に
- **集合メンバーシップ証明の高度化**
    - Merkle Tree＋ZKPや、集合多項式コミットメント等の導入
- **汎用論理式ZKP**
    - AND/OR/NOT等の論理演算や、複雑な条件式のZKP化
- **パフォーマンス最適化・バッチ証明**
    - 複数証明の同時生成・検証や、証明サイズ圧縮
- **セキュリティ強化**
    - 最新の暗号ライブラリ・安全な乱数生成・鍵管理の強化

---

## 1. 概要

**libzkp** は、Vinciプロトコルのための多様なゼロ知識証明（ZKP）をRustで実装し、Pythonから高速・安全に利用できるZKPエンジンです

---

## 2. 設計思想

- **多様なZKPスキーム**（範囲・等価性・閾値・改善・一貫性など）を統一APIで提供
- **Rust実装＋PyO3バインディング**により、高速・安全・型安全なZKPをPython利用可能
- **ZKPバックエンドの抽象化**: `bulletproofs`に限定せず、将来的に異なるZKPライブラリ（`bellman`, `arkworks`など）をプラグインのように追加できるよう、バックエンドを抽象化する層を導入します。
- **回路記述言語/DSLのサポート**: 任意の論理式や計算をZKPで証明できるよう、回路記述言語（R1CSなど）やDSL（Domain Specific Language）のサポートを検討します。
- **汎用的な証明・検証API**: 特定のスキームに依存しない、汎用的な`prove`と`verify`のAPIを定義し、内部で適切なZKPバックエンドと回路を呼び出すようにします。
- **スキーム名による動的切替**（"range"/"equality"/"threshold" など）
- **拡張容易**：新しいZKPスキームをRustで追加→Pythonから即利用

---

## 3. Rust側構成

```
l3_trust/zkp/schemes/libzkp/
  ├── Cargo.toml
  └── src/
      ├── lib.rs
      ├── range_proof.rs
      ├── equality_proof.rs
      ├── threshold_proof.rs
      ├── improvement_proof.rs
      ├── consistency_proof.rs
      └── utils.rs
```

- 各ZKPごとに `prove_xxx`/`verify_xxx` 関数を `#[pyfunction]` で公開
- PyO3で `libzkp` Pythonモジュールとしてビルド

---

## 4. PythonラッパーAPI

```python
import importlib
libzkp = importlib.import_module("libzkp")

class LibZKPEngine:
    def prove_range(self, value, min_val, max_val):
        return libzkp.prove_range(value, min_val, max_val)
    def verify_range(self, proof_bytes, commitment_bytes, min_val, max_val):
        return libzkp.verify_range(proof_bytes, commitment_bytes, min_val, max_val)
    def prove_equality(self, value1, value2):
        return libzkp.prove_equality(value1, value2)
    def verify_equality(self, proof_bytes, commitment_bytes, value1, value2):
        return libzkp.verify_equality(proof_bytes, commitment_bytes, value1, value2)
    # ...他のZKPも同様
```

---

## 5. 利用例

- **ZKPスキームの自動選択・呼び出し**
- **証明生成・検証の自動化**

```python
zkp = LibZKPEngine()
# 範囲証明
proof, commitment = zkp.prove_range(42, 0, 100)
assert zkp.verify_range(proof, commitment, 0, 100)
# 等価性証明
proof, commitment = zkp.prove_equality("alice", "alice")
assert zkp.verify_equality(proof, commitment, "alice", "alice")
```

---

## 6. 拡張性・カスタマイズ

- Rust側で新しいZKP（例: set_membership, snark_proof等）を追加→Pythonから即利用可能
- 型安全な引数・戻り値設計

---

## 7. テスト・CI

- Rust: `cargo test` でZKPロジックの単体・結合テスト
- Python: `pytest` でバインディング経由のテスト

---

## 8. 参考

- [PyO3公式](https://pyo3.rs/)
- [Bulletproofs論文](https://eprint.iacr.org/2017/1066.pdf)
- [zk-SNARKs](https://zokrates.github.io/introduction.html)

---

## 9. 高度なZKPスキームへの拡張

### 9.1. ZKPバックエンドの抽象化

- **目的**: 特定のZKPライブラリ（例: `bulletproofs`）への依存を減らし、将来的にzk-SNARKs (`bellman`, `arkworks`), zk-STARKs (`Winterfell`) など、異なる特性を持つZKPシステムを容易に統合できるようにします。
- **設計**: `libzkp`内部に`zkp_backend`トレイト（RustのTrait）を定義し、各ZKPシステムはこのトレイトを実装します。これにより、上位層のAPIは特定のバックエンドに依存せず、抽象化されたインターフェースを通じて証明生成・検証を行います。
- **構成例**:
  ```
  libzkp/src/
    ├── lib.rs
    ├── zkp_backends/
    │   ├── mod.rs
    │   ├── bulletproofs_backend.rs  // bulletproofsの実装
    │   ├── snark_backend.rs       // bellman/arkworks等のSNARK実装
    │   └── stark_backend.rs       // Winterfell等のSTARK実装
    ├── circuits/                  // 回路定義（R1CS, AIRなど）
    │   ├── mod.rs
    │   ├── range_circuit.rs
    │   ├── equality_circuit.rs
    │   └── generic_circuit.rs     // 汎用的な回路記述
    └── schemes/                  // 各ZKPスキームのAPI層
        ├── mod.rs
        ├── range_proof.rs
        ├── equality_proof.rs
        └── generic_proof.rs       // 汎用的な証明API
  ```

### 9.2. 汎用的な回路記述と証明API

- **目的**: 任意の計算や論理式をZKPで証明できるように、特定のZKPスキームに限定されない汎用的なインターフェースを提供します。
- **設計**: 
    - **回路記述言語 (DSL)**: 高度なZKPシステムでは、証明したい計算をR1CS (Rank-1 Constraint System) やAIR (Algebraic Intermediate Representation) などの形式で記述します。`libzkp`は、これらの回路をRustで直接記述する、または外部のDSLコンパイラ（例: `circom`, `zokrates`）で生成された回路定義をインポートする機能を提供します。
    - **汎用証明API**: `prove_generic(circuit_id, public_inputs, private_inputs)` のようなAPIを導入し、`circuit_id`に基づいて適切な回路とZKPバックエンドを選択・実行します。
    - **汎用検証API**: `verify_generic(circuit_id, public_inputs, proof)` のようなAPIを導入し、同様に検証を行います。

### 9.3. パフォーマンスとスケーラビリティの考慮

- **バッチ証明**: 複数の独立した証明をまとめて生成・検証することで、オーバーヘッドを削減し、スループットを向上させます。ZKPバックエンドがバッチ証明をサポートしている場合、その機能を活用します。
- **並列処理**: 証明生成は計算コストが高いため、マルチコアCPUやGPUを活用した並列処理を導入します。
- **証明サイズの最適化**: SNARKsのように証明サイズが小さいZKPシステムを優先的に採用し、オンチェーンでの検証コストを削減します。

### 9.4. セキュリティと監査

- **形式検証**: 重要なZKP回路やプロトコルに対して、形式検証ツールを用いた数学的な正当性の証明を検討します。
- **第三者監査**: 暗号学的な実装の安全性確保のため、専門家によるコード監査を定期的に実施します。
- **鍵管理**: 証明キーと検証キーの安全な生成、保管、配布に関するベストプラクティスを確立します。

### 9.5. 集合メンバーシップ証明の高度化

- **目的**: Merkle TreeやAccumulatorを用いた、より効率的でスケーラブルな集合メンバーシップ証明を実装します。
- **設計**: 
    - Merkle Treeの構築と更新機能を提供し、特定の要素がツリーに含まれることのZKPを生成・検証します。
    - 集合多項式コミットメント（例: KZGコミットメント）のような先進的な技術を導入し、よりコンパクトな証明と高速な検証を実現します。

---
