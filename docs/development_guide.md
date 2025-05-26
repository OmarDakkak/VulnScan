# VulnScan Development Guide

This document provides guidelines for developers who want to contribute to the VulnScan project.

## Project Structure

```
vulnscan/
├── src/
│   └── vulnscan/
│       ├── __init__.py
│       ├── cli.py          # Command-line interface
│       ├── scanner.py      # Core port scanning functionality
│       ├── web_scanner.py  # Web vulnerability scanning
│       ├── service_scanner.py  # Service fingerprinting
│       ├── database.py     # Database operations
│       └── utils.py        # Utility functions
├── tests/
│   └── [Test scripts]
├── docs/
│   └── [Documentation files]
└── [Project files]
```

## Development Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/OmarDakkak/VulnScan.git
cd VulnScan
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If you have separate dev dependencies
```

### 4. Install the Package in Development Mode

```bash
pip install -e .
```

## Coding Standards

We follow PEP 8 Python style guidelines with the following specifics:

- Use 4 spaces for indentation (no tabs)
- Maximum line length of 88 characters
- Use docstrings for all functions and classes
- Include type hints where appropriate

### Code Formatting

We use Black for code formatting:

```bash
black src/ tests/
```

### Linting

We use flake8 for linting:

```bash
flake8 src/ tests/
```

### Type Checking

We use mypy for type checking:

```bash
mypy src/
```

## Testing

### Running Tests

Use the test scripts in the `tests/` directory:

```bash
# Run all tests
./tests/run_all_tests.sh

# Run a specific test
./tests/test_port_scan.sh
```

### Writing Tests

When adding new features, please include tests. For vulnerability checks, consider:

1. Tests with mock data to prevent actual vulnerability testing
2. Tests against safe endpoints (like httpbin.org)
3. Tests that verify proper error handling

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure everything works
5. Update documentation as needed
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Pull Request Template

```markdown
## Description
[Description of the changes made]

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have added tests for new functionality
- [ ] All tests pass locally
- [ ] I have updated the documentation
```

## Adding New Features

### Adding New Scanning Capability

1. Decide if it fits in an existing scanner class or needs a new one
2. Implement the core scanning logic
3. Add CLI integration in `cli.py`
4. Add appropriate tests
5. Update documentation

Example for adding a new web vulnerability scanner:

```python
# In web_scanner.py
def scan_new_vulnerability_type(self):
    """Scan for a new type of vulnerability"""
    results = []
    
    # Implement scanning logic
    
    return results

# Then in the WebScanner.run_scan method
def run_scan(self):
    results = {}
    # Existing code...
    
    results['new_vulnerability_type'] = self.scan_new_vulnerability_type()
    
    return results
```

### Adding CLI Options

Add new options to the CLI in `cli.py`:

```python
@cli.command()
@click.argument('target_ip')
@click.option('--new-option', is_flag=True, help='Description of new option')
def scan(target_ip, new_option, ...):
    """Scan a target IP address for vulnerabilities"""
    # Existing code...
    
    if new_option:
        # Implement new option functionality
        pass
```

## Database Schema Modifications

If you need to modify the database schema:

1. Update the table creation SQL in `database.py`
2. Add a migration function to handle existing databases
3. Update related functions that interact with the modified tables

## Documentation

Please update these documentation files when making changes:

1. `user_guide.md` for user-facing changes
2. `api_reference.md` for API changes
3. `examples.md` for new usage examples
4. `ethical_usage.md` for new ethical considerations

## Release Process

1. Update version number in appropriate files
2. Update CHANGELOG.md
3. Create a release branch (`git checkout -b release/v1.0.1`)
4. Submit PR for review
5. After approval, merge to main
6. Tag the release (`git tag v1.0.1`)
7. Push tags (`git push --tags`)

## Getting Help

If you need assistance with development:

1. Check existing issues and documentation
2. Create a new issue with the "question" label
3. Reach out to the maintainers directly (see MAINTAINERS.md)

Thank you for contributing to VulnScan!