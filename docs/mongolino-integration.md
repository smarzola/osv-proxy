# Mongolino Integration

mongolino is a single-binary MongoDB wire-protocol server backed by one SQLite file. `osv-proxy` should use it through the same MongoDB-compatible store implementation used for MongoDB.

Do not add a separate `mongolino` backend or config shape inside `osv-proxy`.

## Run mongolino

When the `mongolino` binary is available:

```sh
mongolino --addr 127.0.0.1:27018 --db ./data/osv-proxy-malicious.db
```

From a local checkout:

```sh
cd /Users/smarzola/projects/mongolino
cargo run -- --addr 127.0.0.1:27018 --db /Users/smarzola/projects/osv-proxy/data/osv-proxy-malicious.db
```

## Configure osv-proxy

Point the local malicious store at mongolino with the normal MongoDB URI config:

```yaml
policy:
  malicious:
    mode: "local"
    only_mal_ids: true
    on_osv_error: "block"
malicious_store:
  mongodb:
    uri: "mongodb://127.0.0.1:27018"
    database: "osv_proxy"
    collection: "malicious_packages"
  sync:
    enabled: true
    interval: "15m"
    ecosystems: ["npm", "PyPI"]
```

The same shape works with MongoDB by changing only `malicious_store.mongodb.uri`.

## Compose Pattern

For containerized deployment, run mongolino as a MongoDB-compatible service and point `osv-proxy` at that service name:

```yaml
services:
  mongolino:
    image: ghcr.io/smarzola/mongolino:latest
    command:
      - "--addr"
      - "0.0.0.0:27017"
      - "--db"
      - "/data/osv-proxy-malicious.db"
    volumes:
      - mongolino-data:/data
    ports:
      - "27018:27017"

  osv-proxy:
    image: ghcr.io/smarzola/osv-proxy:latest
    depends_on:
      - mongolino
    volumes:
      - ./osv-proxy.yaml:/etc/osv-proxy.yaml:ro
    command:
      - "serve"
      - "--config"
      - "/etc/osv-proxy.yaml"
    ports:
      - "8080:8080"

volumes:
  mongolino-data:
```

Matching `osv-proxy.yaml` fragment:

```yaml
malicious_store:
  mongodb:
    uri: "mongodb://mongolino:27017"
    database: "osv_proxy"
    collection: "malicious_packages"
```

On this machine, use `container-compose up -d` for compose workflows.

## Integration Contract

- `osv-proxy` depends on MongoDB driver behavior, not mongolino-specific APIs.
- The malicious store implementation creates and uses MongoDB indexes.
- mongolino should be used in examples, local development, and cheap single-node deployments.
- Managed MongoDB can replace mongolino without changing application code.
