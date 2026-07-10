# Generate the README demo GIF with vhs (https://github.com/charmbracelet/vhs):
#   vhs docs/demo.tape
# or without installing vhs (from the repo root):
#   docker run --rm -v "$PWD:/vhs" --entrypoint sh ghcr.io/charmbracelet/vhs \
#     -c "python3 -m ensurepip -q && python3 -m pip install -q --break-system-packages . && vhs docs/demo.tape"
Output docs/demo.gif
Set FontSize 15
Set Width 1100
Set Height 660
Set Theme "Catppuccin Latte"
Set TypingSpeed 40ms
Type "patchtriage demo   # offline: no network, no API keys"
Enter
Sleep 9s
Type "# ^ the CVSS 10.0 (xz backdoor) ranks BELOW the CVSS 7.8 in active ransomware use"
Sleep 4s
