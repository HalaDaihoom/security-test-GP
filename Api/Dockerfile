# Use the .NET 8 SDK image (specific version) to build the application
FROM mcr.microsoft.com/dotnet/sdk:8.0.100 AS build

# Set the working directory
WORKDIR /app

# Copy the project file and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy the rest of the application
COPY . ./

# Build the application
RUN dotnet restore --verbosity detailed

# Use the .NET 8 runtime image (specific version) to run the application
FROM mcr.microsoft.com/dotnet/aspnet:8.0.0

WORKDIR /app

# Copy the published files from the build image
COPY --from=build /app/out .

# Set the entry point for the application
ENTRYPOINT ["dotnet", "SECURITY-TEST-GP.Api.dll"]


# # Use the .NET 8 SDK image to build the application
# FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

# # Set the working directory
# WORKDIR /app

# # Copy the project file and restore dependencies
# COPY *.csproj ./
# RUN dotnet restore

# # Copy the rest of the application
# COPY . ./

# # Build the application
# RUN dotnet publish -c Release -o out

# # Use the .NET 8 runtime image to run the application
# FROM mcr.microsoft.com/dotnet/aspnet:8.0

# WORKDIR /app

# # Copy the published files from the build image
# COPY --from=build /app/out .

# # Set the entry point for the application
# ENTRYPOINT ["dotnet", "SECURITY-TEST-GP.Api.dll"]
