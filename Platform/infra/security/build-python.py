#!/usr/bin/env python3
"""
Build script for CoyoteSense Security Infrastructure Component (Python)

This script handles building, testing, and packaging the Python implementation
of the security component.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path


def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result"""
    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        if e.stderr:
            print(f"Error: {e.stderr}")
        if check:
            sys.exit(1)
        return e


def check_dependencies():
    """Check if required tools are available"""
    print("Checking dependencies...")
    
    required_tools = ['python', 'pip']
    for tool in required_tools:
        try:
            subprocess.run([tool, '--version'], check=True, capture_output=True)
            print(f"✓ {tool} is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"✗ {tool} is not available or not in PATH")
            return False
    
    return True


def clean(src_dir):
    """Clean build artifacts"""
    print("Cleaning build artifacts...")
    
    clean_patterns = [
        "**/__pycache__",
        "**/*.pyc", 
        "**/*.pyo",
        "**/*.egg-info",
        "**/build",
        "**/dist",
        "**/.pytest_cache",
        "**/.coverage",
        "**/htmlcov"
    ]
    
    import shutil
    import glob
    
    for pattern in clean_patterns:
        for path in glob.glob(str(src_dir / pattern), recursive=True):
            if os.path.isdir(path):
                print(f"Removing directory: {path}")
                shutil.rmtree(path, ignore_errors=True)
            elif os.path.isfile(path):
                print(f"Removing file: {path}")
                os.unlink(path)


def install_dependencies(src_dir):
    """Install dependencies"""
    print("Installing dependencies...")
    
    # Install in development mode with all optional dependencies
    run_command([
        sys.executable, '-m', 'pip', 'install', '-e', '.[dev,test,all]'
    ], cwd=src_dir)


def run_linting(src_dir):
    """Run code linting"""
    print("Running linting...")
    
    # Black formatting
    print("Running black...")
    run_command([
        sys.executable, '-m', 'black', '--check', '--diff', '.'
    ], cwd=src_dir, check=False)
    
    # isort import sorting
    print("Running isort...")
    run_command([
        sys.executable, '-m', 'isort', '--check-only', '--diff', '.'
    ], cwd=src_dir, check=False)
    
    # flake8 linting
    print("Running flake8...")
    run_command([
        sys.executable, '-m', 'flake8', '.'
    ], cwd=src_dir, check=False)


def run_type_checking(src_dir):
    """Run type checking"""
    print("Running type checking...")
    
    run_command([
        sys.executable, '-m', 'mypy', '.'
    ], cwd=src_dir, check=False)


def run_tests(src_dir, test_dir):
    """Run tests"""
    print("Running tests...")
    
    # Run pytest with coverage
    run_command([
        sys.executable, '-m', 'pytest', 
        str(test_dir),
        '--cov=coyote_infra_security',
        '--cov-report=html',
        '--cov-report=term',
        '--cov-report=xml',
        '-v'
    ], cwd=src_dir, check=False)


def build_package(src_dir):
    """Build package"""
    print("Building package...")
    
    # Build wheel and source distribution
    run_command([
        sys.executable, '-m', 'build'
    ], cwd=src_dir)


def run_examples(src_dir, examples_dir):
    """Run examples to verify functionality"""
    print("Running examples...")
    
    example_files = [
        examples_dir / 'python' / 'auth_examples.py',
        examples_dir / 'python' / 'trading_bot_example.py'
    ]
    
    for example_file in example_files:
        if example_file.exists():
            print(f"Running example: {example_file.name}")
            run_command([
                sys.executable, str(example_file)
            ], cwd=src_dir, check=False)


def main():
    """Main build function"""
    parser = argparse.ArgumentParser(description='Build CoyoteSense Security Component (Python)')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts')
    parser.add_argument('--install', action='store_true', help='Install dependencies')
    parser.add_argument('--lint', action='store_true', help='Run linting')
    parser.add_argument('--type-check', action='store_true', help='Run type checking')
    parser.add_argument('--test', action='store_true', help='Run tests')
    parser.add_argument('--build', action='store_true', help='Build package')
    parser.add_argument('--examples', action='store_true', help='Run examples')
    parser.add_argument('--all', action='store_true', help='Run all build steps')
    parser.add_argument('--no-deps', action='store_true', help='Skip dependency check')
    
    args = parser.parse_args()
    
    # Determine script location and directories
    script_dir = Path(__file__).parent.absolute()
    src_dir = script_dir / 'src' / 'python'
    test_dir = script_dir / 'tests' / 'python'
    examples_dir = script_dir / 'examples'
    
    print(f"Security Component Build Script")
    print(f"Source directory: {src_dir}")
    print(f"Test directory: {test_dir}")
    print(f"Examples directory: {examples_dir}")
    print()
    
    # Check dependencies unless skipped
    if not args.no_deps and not check_dependencies():
        print("Dependency check failed. Use --no-deps to skip.")
        sys.exit(1)
    
    # Determine what to run
    run_all = args.all or not any([
        args.clean, args.install, args.lint, args.type_check, 
        args.test, args.build, args.examples
    ])
    
    try:
        if args.clean or run_all:
            clean(src_dir)
        
        if args.install or run_all:
            install_dependencies(src_dir)
        
        if args.lint or run_all:
            run_linting(src_dir)
        
        if args.type_check or run_all:
            run_type_checking(src_dir)
        
        if args.test or run_all:
            run_tests(src_dir, test_dir)
        
        if args.build or run_all:
            build_package(src_dir)
        
        if args.examples or run_all:
            run_examples(src_dir, examples_dir)
        
        print("\n✓ Build completed successfully!")
        
    except KeyboardInterrupt:
        print("\n✗ Build interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
