# Use the official .NET 8.0 SDK image for the build phase
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy the .csproj file first for restore
COPY *.csproj ./
RUN dotnet restore --verbosity detailed

# Copy the rest of the source code
COPY . . 

# Build and publish the application
RUN dotnet publish -c Release -o out

# Use the official .NET 8.0 ASP.NET runtime image for the final image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# Set the entry point for running the app
ENTRYPOINT ["dotnet", "YourAppName.dll"]
