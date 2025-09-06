# Bloggable (Coming Soon...)

> An open source CLI tool to generate blog posts from git commits in a particular voice using LLMs

Transform git commits into engaging content with one command. Bloggable analyzes your code changes, intelligently gathers context, and generates posts in different voices - from technical deep-dives to Twitter threads to release notes.

## ✨ Features

- **Multiple Voices**: Choose from pre-built voices or create custom ones
  - 📚 **Technical-Detailed**: Deep technical explanations with full context
  - 🐦 **Twitter-Thread**: Concise, engaging social medium content  
  - 📋 **Release-Notes**: Professional changelog format
- **Intent-Driven**: Guide the output with specific goals ("focus on performance improvements", "explain the trade-offs")
- **Multi-turn Context Gathering**: Uses LLMs to intelligently request the exact context needed from your codebase
- **Repository Intelligence**: Builds semantic maps of your codebase to understand relationships
- **Multi-Language Support**: Works with Rust, Python, JavaScript, TypeScript, and more

## 🚀 Quick Start

### Installation

```bash
# Install from crates.io
cargo install bloggable

# Or build from source
git clone https://github.com/JacobDahan/bloggable
cd bloggable
cargo build --release
```

### Basic Usage

```bash
# Generate a technical blog post from recent commits
bloggable generate --commits HEAD~3..HEAD --voice technical --medium blog

# Create a playful Twitter thread about a specific feature
bloggable generate --commits abc123f --voice playful --medium twitter-thread --intent "announce new user authentication system"

# Generate release notes
bloggable generate --commits v1.0.0..HEAD --voice concise --medium release-notes
```

### Configuration

Create a `.bloggable.toml` in your project or home directory:

```toml
[api_keys]
openai = "your-openai-api-key"

[defaults]
voice = "educational"
medium = "blog"
output = "json"
max_turns = 5
context_limit = 8000
```

> [!TIP]
> You can now use `bloggable init` to easily create your `toml` config!

## 📖 How It Works

1. **Repository Analysis**: Bloggable builds a semantic map of your codebase, identifying functions, classes, dependencies, and relationships

2. **Intelligent Context Gathering**: Using multi-turn conversations, the LLM requests specific context it needs:
   ```
   LLM: "I need to see the login_user function implementation"
   Bloggable: [provides function code]
   LLM: "Show me the User model definition"  
   Bloggable: [provides model code]
   LLM: "Now I can write the blog post..."
   ```

3. **Voice-Specific Generation**: Different voices have different context requirements and writing styles

4. **Output**: Formatted post ready for publishing

## 🎯 Examples

### Technical Deep-Dive
```bash
bloggable generate \
  --commits HEAD~1..HEAD \
  --voice technical \
  --medium blog \
  --intent "explain the algorithm choice and performance implications"
```

**Output Preview**:
> ## Optimizing User Search with Trie Data Structures
> 
> In this commit, we replaced the naive string matching approach with a trie-based
> search algorithm. The key insight was that our user search queries follow predictable
> patterns...

### Twitter Thread
```bash
bloggable generate --commits feature/auth --voice concise --medium twitter-thread
```

**Output Preview**:
> 🧵 Just shipped a major authentication system update! Here's what changed:
>
> 1/6 Added multi-factor authentication support with time-based tokens
>
> 2/6 The new `AuthService` handles session management more securely...

## 🔧 Command Reference

### Core Options
- `--commits <RANGE>`: Git commit range (e.g., `HEAD~5..HEAD`, `v1.0..v1.1`)
- `--voice <VOICE>`: Writing voice (`educational`, `technical`, `playful`, `concise`)
- `--medium <MEDIUM>`: Target medium for the post (`blog`, `release-notes`, `twitter-thread`)
- `--intent <TEXT>`: Specific focus or goal for the post
- `--output <FILE>`: Save to file instead of stdout
- `--format <FORMAT>`: Output format (`markdown`, `plain`, `json`)

### Context Control
- `--dry-run`: Show prioritized context for the commit range without sending to the LLM
- `--max-turns <N>`: Limit multi-turn conversation rounds
- `--context-limit <TOKENS>`: Maximum context size

### Configuration
- `--config <FILE>`: Use specific config file
- `--api-key <KEY>`: Override API key for this run

## 🏗️ Architecture

Bloggable uses a multi-stage approach:

```
Git Commits → Repository Analysis → Context Prioritization → Multi-turn LLM → Blog Post
     ↓               ↓                      ↓                    ↓            ↓
 Diff parsing    Semantic map        Smart context       Tool calling    Formatted
 File changes    Function sigs       Token budgeting     view_file()      output
 Commit msgs     Dependencies        Relevance ranking   search_code()
```

### Key Components

- **Repository Mapper**: Uses tree-sitter to build semantic understanding
- **Context Engine**: Prioritizes what information the LLM needs
- **Tool System**: Handles LLM requests for more context
- **Voice Engine**: Manages different writing styles and requirements

## 🛠️ Development

### Building

```bash
git clone https://github.com/your-username/bloggable
cd bloggable
cargo build
```

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests (requires API keys)
cargo test --features integration-tests

# Test with recorded LLM conversations (no API calls)
cargo test --features mock-llm
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure tests pass (`cargo test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📊 Roadmap

### v1.0 - Core CLI
- [ ] Multi-turn context gathering
- [ ] Basic voice system
- [ ] Repository analysis
- [X] Git integration

### v1.1 - Enhanced Voices
- [ ] More pre-built voices (changelog, technical-beginner, social-medium)
- [ ] Custom voice templates
- [ ] Voice testing framework

### v2.0 - Web Platform
- [ ] Web interface for non-technical users
- [ ] Custom voices
- [ ] Recursive processing with iterative feedback

## 🔐 Privacy & Security

- **API Keys**: Stored locally, never transmitted except to specified LLM providers
- **Code Analysis**: All analysis happens locally; only selected context is sent to LLMs
- **No Data Collection**: Bloggable doesn't collect or store usage data

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [tree-sitter](https://tree-sitter.github.io/) for code parsing
- Thanks to the Rust community for excellent tooling

## 💬 Support

- 🐛 **Bug reports**: [GitHub Issues](https://github.com/JacobDahan/bloggable/issues)
- 💡 **Feature requests**: [GitHub Discussions](https://github.com/JacobDahan/bloggable/discussions)

---

**Built with ❤️ for developers who want to share their work without the writing friction.**