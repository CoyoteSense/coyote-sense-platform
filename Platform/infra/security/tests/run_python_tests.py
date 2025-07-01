#!/usr/bin/env python3
"""
Simple Python test runner with timeout handling to prevent hanging
"""
import subprocess
import sys
import time
import os
from pathlib import Path

def run_python_tests():
    """Run Python tests with timeout protection"""
    print("🐍 Running Python OAuth2 Authentication Tests...")
    
    # Change to the correct directory
    test_dir = Path(__file__).parent / "python"
    os.chdir(test_dir)
    
    # Test files to run
    test_files = [
        "unit/test_oauth2_auth_client.py", 
        "test_structure_basic.py"
    ]
    
    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest",
        "--tb=short",
        "-v",
        "--timeout=30",
        "--timeout-method=thread"
    ] + test_files
    
    print(f"Running command: {' '.join(cmd)}")
    print(f"Working directory: {os.getcwd()}")
    
    try:
        # Run with timeout
        start_time = time.time()
        result = subprocess.run(
            cmd,
            timeout=60,  # Overall timeout
            capture_output=True,
            text=True
        )
        
        elapsed = time.time() - start_time
        print(f"\n⏱️  Tests completed in {elapsed:.2f} seconds")
        
        # Print output
        if result.stdout:
            print("\n📊 Test Output:")
            print(result.stdout)
        
        if result.stderr:
            print("\n⚠️  Warnings/Errors:")
            print(result.stderr)
        
        success = result.returncode == 0
        if success:
            print("\n✅ Python tests passed successfully!")
        else:
            print(f"\n❌ Python tests failed with exit code {result.returncode}")
        
        return success
        
    except subprocess.TimeoutExpired:
        print("\n⏰ Tests timed out - force killing any hanging processes")
        return False
    except Exception as e:
        print(f"\n💥 Error running tests: {e}")
        return False

if __name__ == "__main__":
    success = run_python_tests()
    sys.exit(0 if success else 1)
