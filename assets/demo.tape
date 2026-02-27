# epack demo - core workflow with signing
Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 900
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 30
Set TypingSpeed 40ms
Set CursorBlink false

# Setup
Hide
Type "export PS1='$ '"
Enter
Type "export PATH=$HOME/bin:$PATH"
Enter
Type "cd /private/tmp && rm -rf epack-demo && mkdir epack-demo && cd epack-demo"
Enter

# Create GitHub posture data
Type "cat > github.json << 'EOF'"
Enter
Type '{"branch_protection": "94%", "code_review_required": "91%", "secret_scanning": "100%", "dependabot": "88%"}'
Enter
Type "EOF"
Enter

# Create Okta posture data
Type "cat > okta.json << 'EOF'"
Enter
Type '{"mfa_enrolled": "99%", "admin_mfa": "100%", "inactive_disabled": "96%", "password_compliance": "92%"}'
Enter
Type "EOF"
Enter
Sleep 200ms
Ctrl+L
Show

# Build
Sleep 600ms
Type "epack build february.epack *.json --stream acme/security"
Sleep 300ms
Enter
Sleep 2s

# Sign (opens browser for OIDC auth - VHS waits for completion)
Sleep 500ms
Type "epack sign february.epack --yes"
Sleep 300ms
Enter
Sleep 5s

# Verify signed pack
Sleep 500ms
Type "epack verify february.epack --subject michael.nipper@locktivity.com --issuer https://accounts.google.com"
Sleep 300ms
Enter
Sleep 2.5s

# Inspect to show attestation
Sleep 500ms
Type "epack inspect february.epack"
Sleep 300ms
Enter
Sleep 3s

# Update data for March
Hide
Type "cat > github.json << 'EOF'"
Enter
Type '{"branch_protection": "97%", "code_review_required": "94%", "secret_scanning": "100%", "dependabot": "92%"}'
Enter
Type "EOF"
Enter
Sleep 100ms
Ctrl+L
Show

# Build March
Sleep 500ms
Type "epack build march.epack *.json --stream acme/security"
Sleep 300ms
Enter
Sleep 2s

# Diff
Sleep 500ms
Type "epack diff february.epack march.epack"
Sleep 300ms
Enter
Sleep 2.5s

# Content diff
Sleep 500ms
Type "epack diff february.epack march.epack --artifact artifacts/github.json"
Sleep 300ms
Enter
Sleep 3s

Sleep 1s
