
# 🎯 libzkp 設計方針

## 1. **目的・ゴール**
- **範囲証明・等価性証明・閾値証明・集合メンバーシップ証明・一貫性証明など、用途が明確なZKPスキームのみ**をRustで高速・安全に実装
- **Python（PyO3）から簡単に呼び出せるAPI**を提供
- **拡張性・型安全性・テスト容易性**を重視

---

## 2. **ディレクトリ・ファイル構成例**

```
libzkp/
  src/
    lib.rs                 # ルートモジュール（PyO3バインディング含む）
    range_proof.rs         # 範囲証明
    equality_proof.rs      # 等価性証明
    threshold_proof.rs     # 閾値証明
    set_membership.rs      # 集合メンバーシップ証明
    improvement_proof.rs   # 改善証明
    consistency_proof.rs   # 一貫性証明
    backend/               # ZKPバックエンド抽象化（bulletproofs, snark, stark等）
      mod.rs
      bulletproofs.rs
      snark.rs
      stark.rs
      #etc...
    utils.rs               # 共通ユーティリティ
  tests/                   # Rustのユニット・統合テスト
  Cargo.toml
  README.md
```

---

## 3. **アーキテクチャ・設計思想**

- **ZKPスキームごとに独立したAPI・モジュール設計**
  - 例：`prove_range`, `verify_range`, `prove_equality`, `verify_equality` など
- **ZKPバックエンドの抽象化**
  - bulletproofs等の暗号ライブラリをラップし、将来の差し替えも容易に
- **PyO3でPythonバインディング**
  - Pythonから`libzkp.prove_range(...)`のように直接呼び出せる
---

## 4. **API設計例（Rust側）**

```rust
#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<(Vec<u8>, Vec<u8>)> { ... }

#[pyfunction]
pub fn verify_range(proof: Vec<u8>, commitment: Vec<u8>, min: u64, max: u64) -> PyResult<bool> { ... }

#[pyfunction]
pub fn prove_equality(val1: u64, val2: u64) -> PyResult<(Vec<u8>, Vec<u8>)> { ... }

#[pyfunction]
pub fn verify_equality(proof: Vec<u8>, commitment: Vec<u8>, val1: u64, val2: u64) -> PyResult<bool> { ... }
```

---

## 5. **Pythonバインディング例**

```python
import libzkp

proof, commitment = libzkp.prove_range(42, 0, 100)
assert libzkp.verify_range(proof, commitment, 0, 100)
```

---

## 6. **拡張性・将来性**

- **新しいZKPスキーム（例：新しい集合証明や閾値証明）が必要になった場合は、Rustで個別に追加**
- **APIは一貫性を保ちつつ、内部実装を柔軟に切り替え可能**
- **型安全・エラー処理・ドキュメントもRust流で徹底**

---

## 7. **セキュリティ・パフォーマンス**

- **暗号ライブラリの選定・依存管理を厳格に**
- **Rustの型安全性・所有権モデルでバグや脆弱性を防止**
- **バッチ証明・並列処理・証明サイズ最適化も設計段階から考慮**

---
