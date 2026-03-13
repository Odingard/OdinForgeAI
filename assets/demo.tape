# OdinForge AI — Demo Recording (VHS tape)
#
# Install vhs: brew install charmbracelet/tap/vhs
# Run: vhs assets/demo.tape
#
# This produces assets/odinforge-demo.gif

Output assets/odinforge-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1100
Set Height 650
Set Theme "Monokai"
Set Padding 20
Set TypingSpeed 35ms
Set CursorBlink false

# Show prompt context
Type "# OdinForge AI — Breach Chain Benchmark"
Enter
Sleep 500ms

Type "npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts http://localhost:3000 live --target broken-crystals --output /tmp/breach-chain-demo.json"
Enter

# Wait for benchmark to complete (adjust if needed)
Sleep 120s

# Hold final output
Sleep 5s
