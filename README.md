# 🔎 Sensitive Info Scanner

![GitHub release](https://img.shields.io/github/v/release/seu-usuario/sensitive-info-scanner)
![GitHub](https://img.shields.io/github/license/seu-usuario/sensitive-info-scanner)
![GitHub language count](https://img.shields.io/github/languages/count/seu-usuario/sensitive-info-scanner)

A simple and extensible CLI tool to detect sensitive information in your projects before publishing to public repositories.

---

## 🚀 Features

- Detect common patterns of secrets, API keys, and sensitive files
- Support for custom regex patterns
- Clear and summarized terminal output
- Skips common directories automatically

---

## ⚙️ Installation

```bash
npm install -g sensitive-info-scanner
```

Or use without installing globally:

```bash
npx sensitive-info-scanner ./my-folder
```

---

## 💻 Usage

```bash
sensitive-info-scanner <path>
```

Example:

```bash
sensitive-info-scanner ./my-app
```

---

## 🛠️ Custom Patterns

You can add custom regex patterns by editing `src/patterns.ts`.

---

## ✅ Best Practices

- Always scan before pushing to public repositories
- Combine with pre-commit hooks
- Regularly update patterns to include new secret types

---

## 🧑‍💻 Contributing

Contributions and suggestions are welcome! Please open an issue or pull request.

---

## 📄 License

MIT License