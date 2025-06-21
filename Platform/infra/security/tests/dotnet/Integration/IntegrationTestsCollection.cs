using Xunit;

namespace Coyote.Infra.Security.Tests.Integration;

/// <summary>
/// Collection definition for integration tests to ensure they run sequentially
/// </summary>
[CollectionDefinition("IntegrationTests")]
public class IntegrationTestsCollection : ICollectionFixture<IntegrationTestsFixture>
{
}

/// <summary>
/// Fixture for integration tests
/// </summary>
public class IntegrationTestsFixture
{
    // Can contain shared setup/teardown logic if needed
}
