FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["worker/Coyote.Units.KeyVault.csproj", "worker/"]
RUN dotnet restore "worker/Coyote.Units.KeyVault.csproj"
COPY . .
WORKDIR "/src/worker"
RUN dotnet build "Coyote.Units.KeyVault.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Coyote.Units.KeyVault.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Coyote.Units.KeyVault.dll"]
