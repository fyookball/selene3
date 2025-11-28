 #!/bin/bash

set -e  # Exit immediately on error
 
echo "📦  Step 8: Yarn Pretty"

yarn pretty

echo "📦  Step 9: run the build on the main package"

yarn run build

echo "🔄  Step 10: Syncing Capacitor Android..."
npx cap sync android

echo "📱  Step 11: Running on Android emulator..."
# Auto-confirm emulator selection by simulating Enter key
# `yes ''` sends a newline to the prompt that appears
yes '' | npx cap run android

