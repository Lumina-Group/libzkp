# Contributing to libzkp

libzkpへの貢献を検討していただき、ありがとうございます！このドキュメントでは、プロジェクトへの貢献方法について説明します。

## 貢献の方法

### バグ報告

バグを発見した場合は、以下の情報を含めてIssueを作成してください：

1. **環境情報**
   - OS（Linux/Mac/Windows）とバージョン
   - Rustのバージョン（`rustc --version`）
   - Pythonのバージョン（`python --version`）
   - libzkpのバージョン

2. **再現手順**
   - バグを再現するための最小限のコード例
   - 期待される動作
   - 実際の動作

3. **エラーメッセージ**
   - 完全なエラーメッセージとスタックトレース

### 機能リクエスト

新機能の提案は大歓迎です！以下の情報を含めてIssueを作成してください：

1. **機能の説明**
   - 提案する機能の詳細な説明
   - ユースケース

2. **実装案**（オプション）
   - 可能であれば、実装方法の提案

### プルリクエスト

#### 開発環境のセットアップ

```bash
# リポジトリをクローン
git clone https://github.com/yourusername/libzkp.git
cd libzkp

# 開発用ブランチを作成
git checkout -b feature/your-feature-name

# Rust環境のセットアップ
rustup update
rustup component add rustfmt clippy

# Python仮想環境のセットアップ
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
pip install maturin pytest black mypy
```

#### コーディング規約

**Rust:**
- `rustfmt`を使用してコードをフォーマット
- `clippy`の警告を解決
- 安全でないコード（`unsafe`）は必要最小限に
- 適切なエラーハンドリング

```bash
# フォーマット
cargo fmt

# リント
cargo clippy -- -D warnings

# テスト
cargo test
```

**Python:**
- PEP 8に準拠
- 型ヒントを使用
- doctestを含める

```bash
# フォーマット
black .

# 型チェック
mypy .

# テスト
pytest
```

#### コミットメッセージ

[Conventional Commits](https://www.conventionalcommits.org/)形式を使用してください：

```
<type>(<scope>): <subject>

<body>

<footer>
```

**タイプ:**
- `feat`: 新機能
- `fix`: バグ修正
- `docs`: ドキュメントのみの変更
- `style`: コードの意味に影響しない変更
- `refactor`: バグ修正や機能追加を含まないコード変更
- `perf`: パフォーマンス改善
- `test`: テストの追加や修正
- `chore`: ビルドプロセスやツールの変更

**例:**
```
feat(batch): add support for membership proof in batch processing

- Implement batch_add_membership_proof function
- Update batch processor to handle membership proofs
- Add tests for new functionality

Closes #123
```

#### プルリクエストのプロセス

1. **ブランチを最新に保つ**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **テストを実行**
   ```bash
   cargo test
   maturin develop
   pytest
   ```

3. **ドキュメントを更新**
   - 新機能の場合は、README.mdとdocs/を更新
   - APIの変更がある場合は、docs/api.mdを更新
   - CHANGELOG.mdに変更を記録

4. **プルリクエストを作成**
   - 明確なタイトルと説明
   - 関連するIssueへのリンク
   - 変更の理由と影響の説明

### テスト

新機能やバグ修正には、必ずテストを含めてください：

**Rustテストの例:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // テストコード
        assert_eq!(2 + 2, 4);
    }
}
```

**Pythonテストの例:**
```python
def test_new_feature():
    """Test the new feature."""
    result = libzkp.new_feature(param1, param2)
    assert result == expected_value
```

### ドキュメント

- すべての公開APIにはドキュメントコメントを追加
- 複雑なアルゴリズムには説明コメントを追加
- サンプルコードを含める

**Rustドキュメントの例:**
```rust
/// Generates a proof that a value is within a specified range.
///
/// # Arguments
///
/// * `value` - The value to prove
/// * `min` - The minimum bound (inclusive)
/// * `max` - The maximum bound (inclusive)
///
/// # Returns
///
/// A byte vector containing the proof data
///
/// # Errors
///
/// Returns an error if the value is outside the range
///
/// # Example
///
/// ```
/// let proof = prove_range(25, 0, 100)?;
/// ```
pub fn prove_range(value: u64, min: u64, max: u64) -> Result<Vec<u8>, Error> {
    // 実装
}
```

## セキュリティ

セキュリティの脆弱性を発見した場合は、公開のIssueではなく、プライベートに報告してください。

## ライセンス

貢献されたコードは、プロジェクトと同じApache License 2.0でライセンスされます。

## 質問

質問がある場合は、Discussionsセクションで気軽に質問してください。

ありがとうございます！ 🦀🐍