# Use the official .NET SDK image for the build phase
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy only the .csproj file to restore dependencies
COPY *.csproj ./
RUN dotnet restore --verbosity detailed

# Copy the rest of the source code
COPY . . 

# Build the application
RUN dotnet publish -c Release -o out

# Use the ASP.NET Core runtime image for the final image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# Set the entry point to run the application
ENTRYPOINT ["dotnet", "YourAppName.dll"]
