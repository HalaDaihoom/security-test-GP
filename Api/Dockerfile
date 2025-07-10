    FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

    # Install required tools: git, curl, wget, unzip
    RUN apt-get update && \
        apt-get install -y git curl wget unzip && \
        rm -rf /var/lib/apt/lists/*
    
    # Install Go 1.23.11 (required by subzy)
    RUN wget https://go.dev/dl/go1.23.11.linux-amd64.tar.gz && \
        tar -C /usr/local -xzf go1.23.11.linux-amd64.tar.gz && \
        rm go1.23.11.linux-amd64.tar.gz
    
    # Set Go environment variables
    ENV GOPATH="/root/go"
    ENV GOBIN="/usr/local/bin"
    ENV PATH="${GOBIN}:/usr/local/go/bin:${PATH}"
    
    # Install assetfinder using Go
    RUN go install github.com/tomnomnom/assetfinder@latest
    
    # Manually install subzy from correct repo
    RUN git clone https://github.com/PentestPad/subzy.git /tmp/subzy && \
        cd /tmp/subzy && \
        go build -o /usr/local/bin/subzy . && \
        rm -rf /tmp/subzy
    
    # Create directory for scan outputs
    RUN mkdir -p /app/tools
    
    # Set working directory and copy source code
    WORKDIR /src
    COPY . .
    
    # Publish .NET project
    RUN dotnet publish -c Release -o /app/publish
        
    FROM mcr.microsoft.com/dotnet/aspnet:8.0
    
    # Install curl for shell commands used at runtime
    RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
    
    # Set working directory
    WORKDIR /app
    
    # Copy published app files
    COPY --from=build /app/publish .
    
    # Copy built tools and output directory
    COPY --from=build /usr/local/bin/subzy /usr/local/bin/
    COPY --from=build /usr/local/bin/assetfinder /usr/local/bin/
    COPY --from=build /app/tools /app/tools
    
    # Expose port used by ASP.NET app
    EXPOSE 80
    
    # Start the application
    ENTRYPOINT ["dotnet", "Api.dll"]
  