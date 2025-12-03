#!/bin/bash
echo "Creating missing filter files..."

mkdir -p ../config/filters

# f2b-exploit-critical.conf
cat > ../config/filters/f2b-exploit-critical.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*(\.\.\/|etc\/passwd|bin\/bash|\/bin\/sh|cmd\.exe|phpinfo|eval\(|base64_decode)"
ignoreregex =
EOF

# f2b-web-medium.conf
cat > ../config/filters/f2b-web-medium.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*(union.*select|script>|<iframe|javascript:|onerror=)"
ignoreregex =
EOF

# nginx-recon-optimized.conf
cat > ../config/filters/nginx-recon-optimized.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) /(admin|phpmyadmin|wp-admin|wp-login|\.git|\.env|backup|config|\.well-known|xmlrpc\.php|\.sql|\.zip|\.tar\.gz|\.bak|web\.config|cgi-bin)"
ignoreregex =
EOF

# f2b-fuzzing-payloads.conf
cat > ../config/filters/f2b-fuzzing-payloads.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*(AAAA|%00|%0d%0a|\.\.\.\.)"
ignoreregex =
EOF

# f2b-botnet-signatures.conf
cat > ../config/filters/f2b-botnet-signatures.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "(bot|crawler|spider|scan)" - HTTP/
ignoreregex = googlebot|bingbot|yandex
EOF

# f2b-anomaly-detection.conf
cat > ../config/filters/f2b-anomaly-detection.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "HTTP/[0-9\.]+" (400|401|403|404|405|406|408|418|429|444|500|502|503)
ignoreregex =
EOF

echo "✅ All filters created"
ls -lh ../config/filters/*.conf
