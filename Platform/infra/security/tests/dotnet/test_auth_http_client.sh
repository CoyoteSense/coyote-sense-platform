#!/bin/bash
# Script to test only the AuthHttpClientIntegrationTests class

cd "c:\CoyoteSense\coyote-sense-platform\Platform\infra\security\tests\dotnet"

echo "Building the test project..."
dotnet build --no-restore

if [ $? -eq 0 ]; then
    echo "Build successful. Running AuthHttpClientIntegrationTests..."
    dotnet test --filter "ClassName=CoyoteSense.OAuth2.Client.Tests.Integration.AuthHttpClientIntegrationTests" --no-build --verbosity normal
else
    echo "Build failed. Cannot run tests."
fi
