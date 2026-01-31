#!/bin/bash

# Soul Password Manager - Extension Build Script
# This script packages the browser extension for distribution

echo "🔨 Building Soul Password Manager Extension..."

# Directory setup
EXTENSION_DIR="extension"
BUILD_DIR="extension-build"
DIST_FILE="soul-password-manager-extension.zip"

# Clean previous build
if [ -d "$BUILD_DIR" ]; then
  echo "🧹 Cleaning previous build..."
  rm -rf "$BUILD_DIR"
fi

if [ -f "$DIST_FILE" ]; then
  rm "$DIST_FILE"
fi

# Create build directory
echo "📁 Creating build directory..."
mkdir -p "$BUILD_DIR"

# Copy extension files
echo "📋 Copying extension files..."
cp -r "$EXTENSION_DIR"/* "$BUILD_DIR/"

# Remove unnecessary files
echo "🗑️  Removing unnecessary files..."
find "$BUILD_DIR" -name "*.md" -type f -delete
find "$BUILD_DIR" -name ".DS_Store" -type f -delete

# Check for icons
if [ ! -f "$BUILD_DIR/icons/icon-128.png" ]; then
  echo "⚠️  Warning: Extension icons not found!"
  echo "   Please add icon files to extension/icons/ directory"
  echo "   See extension/icons/README.md for details"
fi

# Create zip archive
echo "📦 Creating distribution package..."
cd "$BUILD_DIR"
zip -r "../$DIST_FILE" . > /dev/null
cd ..

# Cleanup
rm -rf "$BUILD_DIR"

echo "✅ Extension built successfully!"
echo "📦 Package: $DIST_FILE"
echo ""
echo "📝 Next steps:"
echo "   1. Unzip $DIST_FILE"
echo "   2. Load unpacked extension in Chrome/Edge:"
echo "      - Open chrome://extensions/"
echo "      - Enable Developer Mode"
echo "      - Click 'Load unpacked'"
echo "      - Select the unzipped folder"
echo ""
echo "   For Firefox:"
echo "      - Open about:debugging#/runtime/this-firefox"
echo "      - Click 'Load Temporary Add-on'"
echo "      - Select manifest.json from the unzipped folder"
