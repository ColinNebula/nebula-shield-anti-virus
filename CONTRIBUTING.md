# Contributing to Nebula Shield Anti-Virus

Thank you for your interest in contributing to Nebula Shield! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

---

## 🤝 Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please:

- Be respectful and inclusive
- Exercise empathy and kindness
- Give and accept constructive feedback gracefully
- Focus on what is best for the community
- Show courtesy and respect towards other community members

---

## 🚀 Getting Started

### Prerequisites

**Frontend (React):**
- Node.js 16+ and npm 7+
- Modern web browser (Chrome, Firefox, Edge)

**Backend (C++):**
- Visual Studio 2019/2022 with "Desktop development with C++"
- CMake 3.16+
- vcpkg package manager
- Windows 10/11 (for Windows-specific features)

### Quick Start

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```powershell
   git clone https://github.com/YOUR-USERNAME/nebula-shield-anti-virus.git
   cd nebula-shield-anti-virus
   ```

3. **Add upstream remote:**
   ```powershell
   git remote add upstream https://github.com/ORIGINAL-OWNER/nebula-shield-anti-virus.git
   ```

4. **Install dependencies:**
   ```powershell
   npm install
   ```

5. **Create a feature branch:**
   ```powershell
   git checkout -b feature/your-feature-name
   ```

---

## 💻 Development Setup

### Frontend Setup

1. **Install npm dependencies:**
   ```powershell
   npm install
   ```

2. **Create environment file:**
   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

3. **Start development server:**
   ```powershell
   npm start
   ```

   The React app will open at `http://localhost:3000`

### Backend Setup

1. **Install vcpkg (if not already installed):**
   ```powershell
   cd C:\
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   ```

2. **Install C++ dependencies:**
   ```powershell
   cd C:\vcpkg
   .\vcpkg install sqlite3:x64-windows
   .\vcpkg install openssl:x64-windows
   .\vcpkg integrate install
   ```

3. **Build the backend:**
   ```powershell
   cd backend
   mkdir build
   cd build
   cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build . --config Release
   ```

4. **Run the backend:**
   ```powershell
   .\build\bin\Release\nebula_shield_backend.exe
   ```

   The backend API will start at `http://localhost:8080`

---

## 📁 Project Structure

```
nebula-shield-anti-virus/
├── public/                      # Static assets
│   ├── index.html              # HTML template
│   └── manifest.json           # PWA manifest
│
├── src/                        # React frontend source
│   ├── components/             # React components
│   │   ├── Dashboard.js       # Main dashboard
│   │   ├── Scanner.js         # File scanner
│   │   ├── Quarantine.js      # Threat management
│   │   ├── Settings.js        # App settings
│   │   └── Sidebar.js         # Navigation sidebar
│   │
│   ├── services/              # API services
│   │   ├── antivirusApi.js   # Backend API client
│   │   ├── pdfReportService.js # PDF generation
│   │   └── virusTotalService.js # VirusTotal integration
│   │
│   ├── App.js                # Main app component
│   ├── App.css               # App styles
│   ├── index.js              # Entry point
│   └── index.css             # Global styles
│
├── backend/                   # C++ backend
│   ├── include/              # Header files
│   │   ├── http_server.h
│   │   ├── scanner.h
│   │   ├── database.h
│   │   └── file_monitor.h
│   │
│   ├── src/                  # Source files
│   │   ├── http_server.cpp
│   │   ├── scanner.cpp
│   │   ├── database.cpp
│   │   └── file_monitor.cpp
│   │
│   ├── data/                 # Configuration and data
│   │   ├── config.json       # Backend configuration
│   │   └── signatures.db     # Virus signatures
│   │
│   └── CMakeLists.txt       # CMake build configuration
│
├── .github/                  # GitHub configuration
│   ├── workflows/           # GitHub Actions
│   │   └── security.yml    # Security scanning
│   └── dependabot.yml      # Dependency updates
│
├── package.json             # npm dependencies
├── README.md               # Main documentation
├── SECURITY.md             # Security policy
├── CONTRIBUTING.md         # This file
└── .gitignore             # Git ignore rules
```

---

## 🎨 Coding Standards

### JavaScript/React Standards

**Style Guide:**
- Use ES6+ features (arrow functions, destructuring, async/await)
- 2-space indentation
- Single quotes for strings
- Semicolons at end of statements
- Meaningful variable and function names

**Example:**
```javascript
// ✅ Good
const fetchSystemStatus = async () => {
  try {
    const response = await axios.get('http://localhost:8080/api/status');
    setSystemStatus(response.data);
  } catch (error) {
    console.error('Failed to fetch status:', error);
    toast.error('Could not connect to backend');
  }
};

// ❌ Bad
function getStatus() {
  axios.get('http://localhost:8080/api/status').then(function(res) {
    setSystemStatus(res.data)
  })
}
```

**React Component Structure:**
```javascript
import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import './Component.css';

const Component = ({ prop1, prop2 }) => {
  // 1. State declarations
  const [state, setState] = useState(initialValue);
  
  // 2. Effects
  useEffect(() => {
    // Effect logic
  }, [dependencies]);
  
  // 3. Event handlers
  const handleClick = () => {
    // Handler logic
  };
  
  // 4. Render
  return (
    <div className="component">
      {/* JSX */}
    </div>
  );
};

Component.propTypes = {
  prop1: PropTypes.string.isRequired,
  prop2: PropTypes.number
};

export default Component;
```

### C++ Standards

**Style Guide:**
- Follow Google C++ Style Guide
- 4-space indentation
- camelCase for variables and functions
- PascalCase for classes
- UPPERCASE for constants
- Use modern C++ (C++17/20) features

**Example:**
```cpp
// ✅ Good
class FileScanner {
public:
    explicit FileScanner(const std::string& configPath);
    
    ScanResult scanFile(const std::filesystem::path& filePath);
    std::vector<Threat> getThreats() const;
    
private:
    bool isFileInfected(const std::string& signature) const;
    std::unique_ptr<Database> database_;
    const int MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
};

// ❌ Bad
class file_scanner {
    public:
        file_scanner(std::string p) {}
        int scan_file(char* path);
    private:
        int db;
};
```

**Memory Management:**
- Prefer smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Use RAII (Resource Acquisition Is Initialization)
- Avoid raw `new` and `delete`

**Error Handling:**
```cpp
// Use exceptions for exceptional cases
try {
    auto result = scanFile(path);
} catch (const std::exception& e) {
    log("Scan failed: " + std::string(e.what()));
}

// Use return values for expected failures
std::optional<ScanResult> tryScanFile(const std::string& path) {
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }
    // ... scan logic
}
```

### CSS Standards

**Organization:**
```css
/* Component-specific styles */
.component {
  /* Layout */
  display: flex;
  flex-direction: column;
  
  /* Box model */
  margin: 1rem;
  padding: 1.5rem;
  
  /* Typography */
  font-size: 1rem;
  color: var(--text-primary);
  
  /* Visual */
  background: var(--card-bg);
  border-radius: 12px;
  
  /* Animation */
  transition: all 0.3s ease;
}
```

**Naming:**
- BEM-style naming: `.block__element--modifier`
- Use CSS custom properties for theme values
- Mobile-first responsive design

---

## 🧪 Testing

### Frontend Testing

**Run tests:**
```powershell
npm test
```

**Write component tests:**
```javascript
import { render, screen } from '@testing-library/react';
import Dashboard from './Dashboard';

test('renders dashboard title', () => {
  render(<Dashboard />);
  const title = screen.getByText(/Dashboard/i);
  expect(title).toBeInTheDocument();
});
```

### Backend Testing

**Build and run tests:**
```powershell
cd backend/build
cmake --build . --config Debug --target tests
ctest --output-on-failure
```

### Manual Testing

Before submitting a PR, please test:

- [ ] All navigation links work correctly
- [ ] API endpoints return expected data
- [ ] Error states display properly
- [ ] Forms validate input correctly
- [ ] File scanning completes successfully
- [ ] PDF reports generate without errors
- [ ] Mobile responsiveness works (test at 480px, 768px, 1024px)

---

## 📤 Submitting Changes

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(scanner): add support for custom scan paths

fix(dashboard): correct chart rendering on mobile devices

docs(readme): update build instructions for Windows

refactor(api): simplify error handling in HTTP server
```

### Pull Request Process

1. **Update your fork:**
   ```powershell
   git fetch upstream
   git checkout main
   git merge upstream/main
   git push origin main
   ```

2. **Create a feature branch:**
   ```powershell
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following coding standards

4. **Commit your changes:**
   ```powershell
   git add .
   git commit -m "feat(component): add new feature"
   ```

5. **Push to your fork:**
   ```powershell
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub:
   - Provide a clear title and description
   - Reference any related issues (#123)
   - Include screenshots for UI changes
   - List any breaking changes

7. **Address review feedback:**
   - Make requested changes
   - Push updates to the same branch
   - Respond to comments

### PR Checklist

- [ ] Code follows project coding standards
- [ ] All tests pass (`npm test`)
- [ ] No new warnings or errors
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow convention
- [ ] No merge conflicts with main
- [ ] Changes are focused (one feature/fix per PR)
- [ ] Security implications considered

---

## 🔒 Security

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Use GitHub Security Advisories (preferred)
2. See [SECURITY.md](SECURITY.md) for details

### Security Best Practices

When contributing code:

- [ ] Validate all user inputs
- [ ] Sanitize data before display
- [ ] Never commit secrets or API keys
- [ ] Use parameterized queries for database access
- [ ] Follow principle of least privilege
- [ ] Keep dependencies updated
- [ ] Review [SECURITY.md](SECURITY.md) guidelines

---

## 🎯 Areas for Contribution

### High Priority

- **Cross-platform support**: Linux and macOS compatibility
- **Performance optimization**: Faster scanning algorithms
- **Signature updates**: Expand virus signature database
- **Test coverage**: Increase test coverage to 80%+

### Medium Priority

- **UI/UX improvements**: Enhanced user interface
- **Internationalization**: Multi-language support
- **Accessibility**: WCAG 2.1 AA compliance
- **Documentation**: API docs, tutorials, examples

### Low Priority

- **Themes**: Additional color themes
- **Plugins**: Extension system for custom features
- **Mobile app**: Native mobile client
- **Cloud integration**: Cloud-based scanning

### Good First Issues

Look for issues labeled `good first issue` on GitHub. These are:
- Well-documented
- Limited in scope
- Good for new contributors
- Have mentorship available

---

## 📚 Resources

### Documentation

- [Main README](README.md) - Project overview and setup
- [Security Policy](SECURITY.md) - Security guidelines
- [Backend README](backend/README.md) - C++ backend documentation

### External Resources

- [React Documentation](https://react.dev/)
- [C++ Reference](https://en.cppreference.com/)
- [CMake Tutorial](https://cmake.org/cmake/help/latest/guide/tutorial/index.html)
- [Git Handbook](https://guides.github.com/introduction/git-handbook/)

### Development Tools

- **Frontend:**
  - [React DevTools](https://react.dev/learn/react-developer-tools)
  - [VS Code](https://code.visualstudio.com/) with ESLint and Prettier
  
- **Backend:**
  - [Visual Studio](https://visualstudio.microsoft.com/)
  - [CLion](https://www.jetbrains.com/clion/) (alternative IDE)
  - [Vcpkg](https://vcpkg.io/) for package management

---

## 🙋 Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussions
- **Pull Requests**: Code review and technical discussions

### Questions?

If you have questions:

1. Check existing [GitHub Issues](https://github.com/owner/nebula-shield-anti-virus/issues)
2. Search [GitHub Discussions](https://github.com/owner/nebula-shield-anti-virus/discussions)
3. Create a new discussion if your question is unique

---

## 📜 License

By contributing to Nebula Shield Anti-Virus, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](LICENSE) file).

---

## 🙏 Recognition

Contributors will be recognized in:
- The project's README.md
- GitHub's Contributors page
- Release notes for significant contributions

Thank you for contributing to Nebula Shield Anti-Virus! 🛡️

---

**Last Updated**: December 2024  
**Maintained By**: Nebula Shield Development Team
