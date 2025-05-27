"""
HTTP Client Example

This example demonstrates how to use the Python HTTP client in different modes,
mirroring the C++ example but using Python idioms.
"""

import os
import json
import sys
from pathlib import Path

# Add the http root directory to the path so we can import the modules
http_root = str(Path(__file__).parent.parent)
sys.path.insert(0, http_root)

from factory.py.http_client_factory import make_http_client, HttpClientFactory, RuntimeMode
from interfaces.py.http_client import HttpRequest, HttpMethod


def demonstrate_basic_usage():
    """Demonstrate basic HTTP client usage."""
    print("=== Basic HTTP Client Usage ===")
    
    # Create client using factory (will use environment variable or default to production)
    client = make_http_client()
    
    # Simple GET request
    print("\n1. Simple GET request:")
    response = client.get("https://httpbin.org/get")
    print(f"Status: {response.status_code}")
    print(f"Success: {response.is_success}")
    if response.is_success:
        data = json.loads(response.body)
        print(f"Origin IP: {data.get('origin', 'Unknown')}")
    else:
        print(f"Error: {response.error_message}")
    
    # POST request with JSON data
    print("\n2. POST request with JSON:")
    json_data = {"name": "CoyoteSense", "type": "HTTP Client", "version": "1.0"}
    headers = {"Content-Type": "application/json"}
    
    response = client.post(
        "https://httpbin.org/post",
        json.dumps(json_data),
        headers
    )
    print(f"Status: {response.status_code}")
    if response.is_success:
        result = json.loads(response.body)
        print(f"Echo data: {result.get('json', {})}")
    
    # PUT request
    print("\n3. PUT request:")
    response = client.put(
        "https://httpbin.org/put",
        json.dumps({"updated": True}),
        {"Content-Type": "application/json"}
    )
    print(f"Status: {response.status_code}")
    
    # DELETE request
    print("\n4. DELETE request:")
    response = client.delete("https://httpbin.org/delete")
    print(f"Status: {response.status_code}")
    
    # Test connectivity
    print("\n5. Ping test:")
    is_reachable = client.ping("https://httpbin.org/get")
    print(f"Httpbin.org is reachable: {is_reachable}")


def demonstrate_mock_mode():
    """Demonstrate mock mode usage."""
    print("\n=== Mock Mode Demonstration ===")
    
    # Create mock client explicitly
    mock_client = HttpClientFactory.create_client(RuntimeMode.MOCK)
    
    # Set up mock responses
    print("\n1. Setting up mock responses:")
    mock_client.add_json_response(200, {"message": "Hello from mock!", "user_id": 123})
    mock_client.add_success_response("User created successfully")
    mock_client.add_error_response(404, "User not found")
    
    print(f"Queued responses: {mock_client.get_queued_response_count()}")
    
    # Enable request recording
    mock_client.enable_request_recording(True)
    
    # Make requests that will use mock responses
    print("\n2. Making requests:")
    
    # First request - will get JSON response
    response1 = mock_client.get("http://mock-api.com/users/123")
    print(f"Response 1: {response1.status_code} - {response1.body}")
    
    # Second request - will get success response
    response2 = mock_client.post("http://mock-api.com/users", '{"name": "John"}')
    print(f"Response 2: {response2.status_code} - {response2.body}")
    
    # Third request - will get error response
    response3 = mock_client.get("http://mock-api.com/users/999")
    print(f"Response 3: {response3.status_code} - {response3.body}")
    
    # Fourth request - will get default response (queue is empty)
    response4 = mock_client.get("http://mock-api.com/users/456")
    print(f"Response 4: {response4.status_code} - {response4.body}")
    
    # Show recorded requests
    print("\n3. Recorded requests:")
    recorded_requests = mock_client.get_recorded_requests()
    for i, request in enumerate(recorded_requests, 1):
        print(f"  Request {i}: {request.method.name} {request.url}")
        if request.body:
            print(f"    Body: {request.body}")


def demonstrate_error_simulation():
    """Demonstrate error simulation features."""
    print("\n=== Error Simulation Demonstration ===")
    
    mock_client = HttpClientFactory.create_client(RuntimeMode.MOCK)
    
    # Simulate network errors
    print("\n1. Network error simulation:")
    mock_client.simulate_network_error(True, "Simulated connection timeout")
    
    response = mock_client.get("http://example.com")
    print(f"Status: {response.status_code}")
    print(f"Error: {response.error_message}")
    
    # Disable network error simulation
    mock_client.simulate_network_error(False)
    
    # Simulate latency
    print("\n2. Latency simulation (200ms):")
    import time
    mock_client.set_latency_simulation(200)
    
    start_time = time.time()
    response = mock_client.get("http://example.com")
    elapsed = (time.time() - start_time) * 1000
    print(f"Request took {elapsed:.0f}ms")
    print(f"Status: {response.status_code}")
    
    # Simulate random failures
    print("\n3. Random failure simulation (50% rate):")
    mock_client.set_failure_rate(0.5)
    mock_client.set_latency_simulation(0)  # Disable latency for this test
    
    success_count = 0
    total_requests = 10
    
    for i in range(total_requests):
        response = mock_client.get(f"http://example.com/test/{i}")
        if response.is_success:
            success_count += 1
    
    print(f"Success rate: {success_count}/{total_requests} ({success_count/total_requests*100:.0f}%)")


def demonstrate_advanced_configuration():
    """Demonstrate advanced configuration options."""
    print("\n=== Advanced Configuration ===")
    
    client = make_http_client()
    
    # Set default configuration
    client.set_default_timeout(5000)  # 5 seconds
    client.set_default_headers({
        "User-Agent": "CoyoteSense-Example/1.0",
        "Accept": "application/json"
    })
    
    # SSL configuration (for real client)
    client.set_verify_peer(True)
    # client.set_ca_certificate("/path/to/ca.pem")
    # client.set_client_certificate("/path/to/cert.pem", "/path/to/key.pem")
    
    print("Configuration applied successfully")
    
    # Test with custom request
    print("\nTesting custom request:")
    request = HttpRequest(
        url="https://httpbin.org/headers",
        method=HttpMethod.GET,
        timeout_ms=3000
    )
    request.set_header("X-Custom-Header", "test-value")
    
    response = client.execute(request)
    print(f"Status: {response.status_code}")
    if response.is_success:
        data = json.loads(response.body)
        headers = data.get("headers", {})
        print(f"Custom header echoed: {headers.get('X-Custom-Header', 'Not found')}")


def main():
    """Main function to run all demonstrations."""
    print("CoyoteSense HTTP Client Python Example")
    print("=" * 50)
    
    # Check current runtime mode
    print(f"Environment variable: {os.getenv('COYOTE_RUNTIME_MODE') or os.getenv('MODE') or 'default'}")
    
    try:
        # Run demonstrations
        demonstrate_basic_usage()
        demonstrate_mock_mode()
        demonstrate_error_simulation()
        demonstrate_advanced_configuration()
        
        print("\n" + "=" * 50)
        print("All demonstrations completed successfully!")
        
    except ImportError as e:
        print(f"\nImport error: {e}")
        print("Make sure the requests library is installed: pip install requests")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
