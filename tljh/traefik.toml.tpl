# traefik.toml file template
{% if https['enabled'] %}
defaultEntryPoints = ["http", "https"]
{% else %}
defaultEntryPoints = ["http"]
{% endif %}

logLevel = "INFO"
# log errors, which could be proxy errors
[accessLog]
format = "json"
[accessLog.filters]
statusCodes = ["500-999"]

[accessLog.fields.headers]
[accessLog.fields.headers.names]
Authorization = "redact"
Cookie = "redact"
Set-Cookie = "redact"
X-Xsrftoken = "redact"

[respondingTimeouts]
idleTimeout = "10m0s"

[entryPoints]
  [entryPoints.http]
  address = ":{{http['port']}}"
  {% if https['enabled'] %}
    [entryPoints.http.redirect]
    entryPoint = "https"
  {% endif %}

  {% if https['enabled'] %}
  [entryPoints.https]
  address = ":{{https['port']}}"
  backend = "jupyterhub"
  [entryPoints.https.tls]
  minVersion = "VersionTLS12"
  cipherSuites = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"]
  {% if https['tls']['cert'] %}
    [[entryPoints.https.tls.certificates]]
      certFile = "{{https['tls']['cert']}}"
      keyFile = "{{https['tls']['key']}}"
  {% endif %}
  {% endif %}

{% if https['enabled'] and https['letsencrypt']['email'] %}
[acme]
email = "{{https['letsencrypt']['email']}}"
storage = "acme.json"
entryPoint = "https"
  [acme.httpChallenge]
  entryPoint = "http"

{% for domain in https['letsencrypt']['domains'] %}
[[acme.domains]]
  main = "{{domain}}"
{% endfor %}
{% endif %}

[file]

[frontends]
  [frontends.jupyterhub]
  backend = "jupyterhub"
  passHostHeader = true
[backends]
  [backends.jupyterhub]
    [backends.jupyterhub.servers.chp]
    url = "http://127.0.0.1:15003"

