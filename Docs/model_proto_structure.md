# Model Proto File Structure

Proto files define core data models and interfaces. They enable language-agnostic, performant communication, ideal for hybrid event-driven and actor-based systems, including AI agent and finance/payment integration.

Generated code resides in `Models/generated/<language>/`.

# Model Proto File Structure

The `proto/` directory contains Protocol Buffer (`.proto`) files that define the data models and service interfaces for the platform. Each file focuses on a specific domain or extension, enabling modularity and clarity.

| Proto file              | Description                                      |
|-------------------------|--------------------------------------------------|
| account.proto           | Account info, margin, balances                   |
| bracket_oco.proto       | Bracket/OCO/conditional order linking            |
| crypto_extensions.proto | Crypto/Digital asset specific fields             |
| dapp_extensions.proto   | Ethereum, Solidity, DApp, smart contract info    |
| fix_extensions.proto    | Custom FIX tags/fields support                   |
| hft_extensions.proto    | HFT-specific metrics (latency, timing, etc)      |
| instrument.proto        | Instrument/security info                         |
| option_extensions.proto | Option/greek/expiry/derivative extensions        |
| order.proto             | Orders, cancels, modifies, status                |
| position.proto          | Position and portfolio info                      |
| spread.proto            | Spread, basket, multi-leg orders                 |
| strategy.proto          | Strategy (stat arb, market making, HFT, etc)     |
| trade.proto             | Executions/fills/trades                          |
| **ai_agent.proto**      | **AI agent requests, responses, and analytics**  |
| **payment.proto**       | **Payment, transaction, settlement, finance ops**|

## Organization Logic
- Each `.proto` file represents a logical domain or extension.
- Core trading concepts (orders, trades, positions, accounts, instruments) are separated for clarity and reusability.
- Extensions (FIX, crypto, options, HFT, DApp) are modular, allowing for targeted enhancements without impacting core models.
- Specialized files (bracket_oco, spread, strategy) support advanced trading features.
- **AI agent and payment/finance proto files enable intelligent automation and seamless financial operations.**

All `.proto` files are located in the `Models/proto/` directory. 
Generated code for each language is placed in the corresponding `Models/generated/<language>/` folder.