# Use the official .NET 8 SDK image
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy and restore project dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy the rest of the project files and build the app
COPY . ./
RUN dotnet publish -c Release -o out

# Use the runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# Expose the app on port 8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "YourProjectName.dll"]
