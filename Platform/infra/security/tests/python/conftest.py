"""
Pytest configuration and fixtures for security tests
"""
import asyncio
import pytest
import warnings
from typing import Generator, AsyncGenerator

# Suppress specific warnings that are not actionable
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pytest_asyncio")

@pytest.fixture(scope="session")
def event_loop_policy():
    """Set the event loop policy for all tests"""
    return asyncio.WindowsProactorEventLoopPolicy()

@pytest.fixture(scope="function")
async def event_loop():
    """Create an event loop for each test function"""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    
    # Clean up any remaining tasks
    try:
        pending = asyncio.all_tasks(loop)
        if pending:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
    except Exception:
        pass
    finally:
        loop.close()

def pytest_configure(config):
    """Configure pytest"""
    # Set asyncio mode
    config.option.asyncio_mode = "auto"

def pytest_unconfigure(config):
    """Cleanup after pytest"""
    # Force cleanup of any remaining event loops
    try:
        asyncio.set_event_loop_policy(None)
    except Exception:
        pass
