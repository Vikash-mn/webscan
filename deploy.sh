#!/bin/bash

# Build Rust components
echo "Building Rust scanner..."
cd rust/
cargo build --release
cp target/release/scanner ../bin/

# Build Go components
echo "Building Go modules..."
cd ../go/
go build -o ../bin/subdomain_scanner subdomains.go
go build -o ../bin/vuln_scanner vulnerabilities.go

# Setup Python environment
echo "Setting up Python AI..."
cd ../ai/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "Deployment complete. Binaries are in ./bin/"