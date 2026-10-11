# Response headers for the app shell, shared by the exact-match and the fallback location.
#
# `always` is required on each one: without it nginx drops the header on any non-2xx response, which
# is exactly where it still matters. The dashboard loads no third-party script, embeds no frame, and
# calls only same-origin paths, so the policy can be strict.
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy no-referrer always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" always;
