#include "BaseUnit.h"
#include <csignal>
#include <atomic>

using namespace coyote::baseunit;

std::atomic<bool> g_running{true};

void signalHandler(int signal) {
    g_running = false;
}

// Example implementation of a trading unit
class ExampleTradingUnit : public BaseUnit {
public:
    explicit ExampleTradingUnit(const std::string& configPath) 
        : BaseUnit(configPath),
          m_dataFeedHandler(std::make_unique<DataFeedHandler>(this)),
          m_commandHandler(std::make_unique<CommandHandler>(this)) {
    }

protected:
    bool onInitialize() override {
        logInfo("Initializing ExampleTradingUnit");
        
        // Subscribe to market data from other units
        subscribeToChannel("market-data", 
            [this](const std::string& channel, const std::string& message) {
                onMarketData(channel, message);
            });
        
        // Subscribe to order updates
        subscribeToChannel("order-updates",
            [this](const std::string& channel, const std::string& message) {
                onOrderUpdate(channel, message);
            });
        
        return true;
    }

    bool onStart() override {
        logInfo("Starting ExampleTradingUnit");
        
        // Start components
        m_dataFeedHandler->start();
        m_commandHandler->start();
        
        return true;
    }

    void onStop() override {
        logInfo("Stopping ExampleTradingUnit");
        
        // Stop components
        if (m_dataFeedHandler) {
            m_dataFeedHandler->stop();
        }
        
        if (m_commandHandler) {
            m_commandHandler->stop();
        }
    }

    void onHeartbeat() override {
        // Custom heartbeat logic
        updateMetrics("orders_processed", m_ordersProcessed);
        updateMetrics("market_data_received", m_marketDataReceived);
    }

    void onMessage(const std::string& channel, const std::string& message) override {
        if (channel == "command") {
            try {
                auto json = nlohmann::json::parse(message);
                std::string command = json.value("command", "");
                m_commandHandler->handleCommand(command, json);
            } catch (const std::exception& e) {
                logError("Error processing command: " + std::string(e.what()));
            }
        }
    }

private:
    std::unique_ptr<DataFeedHandler> m_dataFeedHandler;
    std::unique_ptr<CommandHandler> m_commandHandler;
    
    // Metrics
    std::atomic<int> m_ordersProcessed{0};
    std::atomic<int> m_marketDataReceived{0};
    
    void onMarketData(const std::string& channel, const std::string& message) {
        m_marketDataReceived++;
        
        try {
            auto json = nlohmann::json::parse(message);
            std::string symbol = json.value("symbol", "");
            double price = json.value("price", 0.0);
            double volume = json.value("volume", 0.0);
            
            logInfo("Received market data: " + symbol + " price=" + std::to_string(price) + 
                   " volume=" + std::to_string(volume));
            
            // Process market data - implement trading logic here
            processMarketData(symbol, price, volume);
            
        } catch (const std::exception& e) {
            logError("Error processing market data: " + std::string(e.what()));
        }
    }
    
    void onOrderUpdate(const std::string& channel, const std::string& message) {
        m_ordersProcessed++;
        
        try {
            auto json = nlohmann::json::parse(message);
            std::string orderId = json.value("orderId", "");
            std::string status = json.value("status", "");
            
            logInfo("Received order update: " + orderId + " status=" + status);
            
            // Process order update
            processOrderUpdate(orderId, status);
            
        } catch (const std::exception& e) {
            logError("Error processing order update: " + std::string(e.what()));
        }
    }
    
    void processMarketData(const std::string& symbol, double price, double volume) {
        // Example trading logic
        if (symbol == "BTCUSD" && price > 150.0) {
            // Simulate placing a sell order
            std::string orderId = "order-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
            
            nlohmann::json orderData;
            orderData["type"] = "new_order";
            orderData["orderId"] = orderId;
            orderData["symbol"] = symbol;
            orderData["side"] = "SELL";
            orderData["price"] = price;
            orderData["quantity"] = 1.0;
            orderData["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            std::string orderChannel = getUnitId() + "-order-notification";
            publishMessage(orderChannel, orderData.dump());
            
            logInfo("Placed sell order: " + orderId + " for " + symbol + " at " + std::to_string(price));
        }
    }
    
    void processOrderUpdate(const std::string& orderId, const std::string& status) {
        // Handle order status changes
        if (status == "FILLED") {
            logInfo("Order filled: " + orderId);
        } else if (status == "REJECTED") {
            logWarning("Order rejected: " + orderId);
        }
    }
};

int main(int argc, char* argv[]) {
    // Set up signal handling
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::string configPath = "config.json";
    if (argc > 1) {
        configPath = argv[1];
    }

    try {
        // Create and run the trading unit
        ExampleTradingUnit unit(configPath);
        
        std::cout << "Starting ExampleTradingUnit..." << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;
        
        // Initialize and start the unit
        if (!unit.initialize()) {
            std::cerr << "Failed to initialize unit" << std::endl;
            return 1;
        }
        
        if (!unit.start()) {
            std::cerr << "Failed to start unit" << std::endl;
            return 1;
        }
        
        // Main loop
        while (g_running && unit.getState() == UnitState::RUNNING) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "Shutting down..." << std::endl;
        unit.stop();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
