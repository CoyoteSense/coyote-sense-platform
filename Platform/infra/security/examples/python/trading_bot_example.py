"""
Simple Trading Bot Authentication Example

This example shows how a trading bot would authenticate and use tokens
to access trading APIs.
"""

import asyncio
import json
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from interfaces import AuthClientConfig, AuthMode
from factory import create_auth_client
from interfaces import ConsoleAuthLogger


class TradingBot:
    """Simple trading bot that uses authentication"""
    
    def __init__(self, auth_client):
        self.auth_client = auth_client
        self.is_running = False
    
    async def start(self):
        """Start the trading bot"""
        print("🤖 Starting Trading Bot...")
        
        # Authenticate first
        result = await self.auth_client.authenticate_client_credentials_async(
            scopes=["trading", "market-data"]
        )
        
        if not result.success:
            print(f"❌ Authentication failed: {result.error_description}")
            return
        
        print("✅ Bot authenticated successfully!")
        print(f"   Token expires at: {result.token.expires_at}")
        
        self.is_running = True
        
        # Simulate trading loop
        await self.trading_loop()
    
    async def trading_loop(self):
        """Main trading loop"""
        iteration = 0
        
        while self.is_running and iteration < 5:  # Run 5 iterations for demo
            iteration += 1
            print(f"\n📊 Trading Iteration {iteration}")
            
            # Check if we have a valid token
            token = await self.auth_client.get_valid_token_async()
            if not token:
                print("❌ No valid token available, stopping bot")
                break
            
            # Simulate API calls with authentication
            await self.fetch_market_data(token)
            await self.place_trade(token)
            await self.check_positions(token)
            
            # Wait before next iteration
            await asyncio.sleep(2)
        
        print("🛑 Trading bot stopped")
    
    async def fetch_market_data(self, token):
        """Simulate fetching market data"""
        print("   📈 Fetching market data...")
        # In real implementation, would make HTTP request with:
        # headers = {"Authorization": token.get_authorization_header()}
        await asyncio.sleep(0.1)  # Simulate API call
        print("   ✅ Market data fetched")
    
    async def place_trade(self, token):
        """Simulate placing a trade"""
        print("   💰 Placing trade order...")
        # In real implementation, would make HTTP request with:
        # headers = {"Authorization": token.get_authorization_header()}
        await asyncio.sleep(0.1)  # Simulate API call
        print("   ✅ Trade order placed")
    
    async def check_positions(self, token):
        """Simulate checking positions"""
        print("   📋 Checking portfolio positions...")
        # In real implementation, would make HTTP request with:
        # headers = {"Authorization": token.get_authorization_header()}
        await asyncio.sleep(0.1)  # Simulate API call
        print("   ✅ Positions checked")
    
    def stop(self):
        """Stop the trading bot"""
        self.is_running = False


async def main():
    """Main function"""
    print("CoyoteSense Trading Bot Authentication Example")
    print("=" * 50)
    
    # Configure authentication
    config = AuthClientConfig(
        server_url="https://api.coyotesense.io/auth",
        client_id="trading-bot-001",
        client_secret="super-secret-bot-key",
        auth_mode=AuthMode.CLIENT_CREDENTIALS,
        default_scopes=["trading", "market-data", "portfolio"],
        auto_refresh=True,
        refresh_buffer_seconds=300  # Refresh 5 minutes before expiry
    )
    
    # Create authentication client (using mock mode for demo)
    auth_client = create_auth_client(
        config,
        mode="debug",  # Use debug mode to see detailed logs
        logger=ConsoleAuthLogger("TradingBot"),
        custom_config={
            "trace_requests": True,
            "performance_tracking": True
        }
    )
    
    # Create and start trading bot
    bot = TradingBot(auth_client)
    
    try:
        await bot.start()
    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user")
        bot.stop()
    except Exception as e:
        print(f"❌ Bot error: {e}")
        bot.stop()
    
    # Show debug information if available
    if hasattr(auth_client, 'get_performance_stats'):
        print("\n📊 Performance Statistics:")
        stats = auth_client.get_performance_stats()
        for method, data in stats.items():
            print(f"   {method}: {data['call_count']} calls, "
                  f"last duration: {data['last_duration_seconds']:.3f}s")


if __name__ == "__main__":
    asyncio.run(main())
