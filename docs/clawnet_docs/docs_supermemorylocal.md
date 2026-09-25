> ## Documentation Index
> Fetch the complete documentation index at: https://supermemory.ai/docs/llms.txt
> Use this file to discover all available pages before exploring further.

# Self-Hosting Supermemory

> State-of-the-art memory, running on your machine. One binary, zero config.

Supermemory runs on your own hardware. It's the same memory engine behind the [hosted platform](https://console.supermemory.ai) — ingestion, memory extraction, hybrid semantic search, and the full API — as a single self-contained binary.

<CodeGroup>
  ```bash curl theme={null}
  curl -fsSL https://supermemory.ai/install | bash
  ```

  ```bash npx theme={null}
  npx supermemory local
  ```
</CodeGroup>

No Docker. No database to provision. No config files. It boots in seconds with everything built in, and it's [open source](https://git.new/memory).

## Zero config, actually

Run the binary with nothing set and you get a complete memory system:

* **The Supermemory graph engine, embedded** — created automatically on first boot. No database to stand up, no connection strings.
* **Built-in local embeddings** — default `Xenova/bge-base-en-v1.5` (768d) on your machine, no API key. Same provider stack as cloud if you opt into OpenAI, Gemini, or Ollama — see [Embeddings](/self-hosting/embeddings).
* **An API key, generated for you** — printed on first boot, ready to paste into any SDK.
* **The full Memory API** — `/v3/documents`, `/v4/search`, `/v4/profile`, spaces, the works.

The only thing you bring is a model. In production, Supermemory runs its own proprietary models, purpose-tuned for long-horizon data understanding and memory extraction. Self-hosted, the same pipeline runs on whatever model you point it at — OpenAI, Anthropic, Gemini, Groq, or any OpenAI-compatible endpoint. Bring a key and go. Or don't bring one at all:

## Runs fully offline

Supermemory works with any OpenAI-compatible endpoint, which means it runs end-to-end on your machine with a local model — Ollama, LM Studio, vLLM, llama.cpp. `gpt-oss-20b` is a great fit:

```bash theme={null}
OPENAI_BASE_URL=http://localhost:11434/v1 \
OPENAI_API_KEY=ollama \
OPENAI_MODEL=gpt-oss:20b \
supermemory-server
```

Local graph engine, local embeddings, local LLM. Your data never leaves the building.

## Drop-in with your existing code

The self-hosted server speaks the same API as the hosted platform. Point any Supermemory SDK at it with a one-line change:

```typescript theme={null}
const client = new Supermemory({
  apiKey: "sm_...", // printed on first boot
  baseURL: "http://localhost:6767",
})
```

Everything in the [Memory API docs](/quickstart) works the same way. The coding plugins do too — [Claude Code](/integrations/claude-code), [Codex](/integrations/codex), and [OpenCode](/integrations/opencode) all target your local server with `SUPERMEMORY_API_URL=http://localhost:6767`.

## Self-hosted vs. the platform

Self-hosted is free, open source, and great for local development, air-gapped environments, and privacy-sensitive workloads. The hosted platform is where the full product lives:

|                                                                            | Self-hosted                                 | Platform                                                           |
| -------------------------------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------ |
| Full Memory API                                                            | ✅                                           | ✅                                                                  |
| Hybrid semantic search                                                     | ✅                                           | ✅                                                                  |
| Embeddings                                                                 | Local default (or OpenAI / Gemini / Ollama) | Same provider stack, managed                                       |
| File ingestion (PDFs, images)                                              | ✅                                           | ✅                                                                  |
| [Connectors](/connectors/overview) (Google Drive, Notion, Gmail, OneDrive) | —                                           | ✅                                                                  |
| [Supermemory MCP](/supermemory-mcp/mcp)                                    | —                                           | ✅                                                                  |
| Memory extraction                                                          | Your model, your key                        | Proprietary long-horizon models — higher quality, cheaper at scale |
| Infrastructure                                                             | Your machine                                | Globally distributed, scales with you                              |

If you outgrow a single machine — or want connectors, MCP, and the best-tuned extraction pipeline — [the platform](https://console.supermemory.ai) is one `baseURL` change away. Running this for a team or organization? See [Local vs. Enterprise](/self-hosting/local-vs-enterprise).

## Next steps

<CardGroup cols={3}>
  <Card title="Quickstart" icon="play" href="/self-hosting/quickstart">
    Install, run, and store your first memory in under two minutes
  </Card>

  <Card title="Configuration" icon="settings" href="/self-hosting/configuration">
    Every environment variable: LLM providers, storage, auth, tuning
  </Card>

  <Card title="Embeddings" icon="waypoints" href="/self-hosting/embeddings">
    Local default, remote providers, multilingual, dimension lock
  </Card>
</CardGroup>


> ## Documentation Index
> Fetch the complete documentation index at: https://supermemory.ai/docs/llms.txt
> Use this file to discover all available pages before exploring further.

# Self-Hosting Quickstart

> From zero to your first memory in under two minutes.

## Install

<Tabs>
  <Tab title="curl">
    ```bash theme={null}
    curl -fsSL https://supermemory.ai/install | bash
    ```
  </Tab>

  <Tab title="npx">
    ```bash theme={null}
    npx supermemory local
    ```
  </Tab>

  <Tab title="bunx">
    ```bash theme={null}
    bunx supermemory local
    ```
  </Tab>
</Tabs>

The installer detects your OS and architecture, downloads the right binary, verifies it, and (when run interactively) prompts you for an LLM API key. Supported platforms: macOS (Apple Silicon & Intel), Linux (x64 & arm64).

## Run

```bash theme={null}
supermemory-server
```

First boot sets everything up — the embedded Supermemory graph engine, local embeddings, and your credentials:

```
  ┌──────────────────────────────────────────────────┐
  │  url       http://localhost:6767                 │
  │  database  ./.supermemory                        │
  │  api key   sm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx     │
  │  org id    xxxxxxxxxxxxxxxxxxxxxx                │
  └──────────────────────────────────────────────────┘
```

Save that API key — it's your bearer token for every request.

<Note>
  In production, Supermemory runs proprietary models tuned for long-horizon data understanding. Self-hosted, you bring any model: if no provider key is set, first boot launches an interactive setup wizard — pick a provider (OpenAI, Anthropic, Gemini, Groq, or any OpenAI-compatible endpoint like Ollama), paste your key, and it's saved encrypted for every future launch. After the LLM key, you can optionally pick an embedding model (press Enter to keep local `Xenova/bge-base-en-v1.5`). See [all providers](/self-hosting/configuration#llm-providers), [embeddings](/self-hosting/embeddings), and [fully-offline local models](/self-hosting/configuration#fully-offline-with-local-models).
</Note>

<Tip>
  **Docker / non-interactive:** set an LLM key via env and, if you don’t want local embeddings, set `SUPERMEMORY_EMBEDDING_PROVIDER` / `MODEL` / `DIMENSIONS`. There is no wizard without a TTY.
</Tip>

## Add your first memory

<Tabs>
  <Tab title="TypeScript">
    ```typescript theme={null}
    import Supermemory from "supermemory"

    const client = new Supermemory({
      apiKey: "sm_...",
      baseURL: "http://localhost:6767",
    })

    await client.memories.add({
      content: "I'm Dhravya. I love building dev tools and I'm allergic to peanuts.",
      containerTag: "user_dhravya",
    })
    ```
  </Tab>

  <Tab title="Python">
    ```python theme={null}
    from supermemory import Supermemory

    client = Supermemory(
        api_key="sm_...",
        base_url="http://localhost:6767",
    )

    client.memories.add(
        content="I'm Dhravya. I love building dev tools and I'm allergic to peanuts.",
        container_tag="user_dhravya",
    )
    ```
  </Tab>

  <Tab title="curl">
    ```bash theme={null}
    curl http://localhost:6767/v3/documents \
      -H "Authorization: Bearer sm_..." \
      -H "Content-Type: application/json" \
      -d '{
        "content": "I am Dhravya. I love building dev tools and I am allergic to peanuts.",
        "containerTag": "user_dhravya"
      }'
    ```
  </Tab>
</Tabs>

## Search it

<Tabs>
  <Tab title="TypeScript">
    ```typescript theme={null}
    const results = await client.search.memories({
      q: "what food should I avoid?",
      containerTag: "user_dhravya",
    })
    ```
  </Tab>

  <Tab title="Python">
    ```python theme={null}
    results = client.search.memories(
        q="what food should I avoid?",
        container_tag="user_dhravya",
    )
    ```
  </Tab>

  <Tab title="curl">
    ```bash theme={null}
    curl http://localhost:6767/v3/search \
      -H "Authorization: Bearer sm_..." \
      -H "Content-Type: application/json" \
      -d '{
        "q": "what food should I avoid?",
        "containerTag": "user_dhravya"
      }'
    ```
  </Tab>
</Tabs>

That's it. Everything in the [Memory API](/quickstart) — documents, memories, user profiles, spaces, filtering — works identically against your local server.

## Where things live

By default, all state lives in a single directory you can back up or move:

| Path                                           | Contents                                                                |
| ---------------------------------------------- | ----------------------------------------------------------------------- |
| `./.supermemory/` (or `$SUPERMEMORY_DATA_DIR`) | The Supermemory graph engine's data, auth secret, embedding model cache |
| `~/.supermemory/env`                           | API keys saved by the installer, loaded on every launch                 |

## Next steps

<CardGroup cols={3}>
  <Card title="Configuration" icon="settings" href="/self-hosting/configuration">
    LLM providers, local models, performance tuning
  </Card>

  <Card title="Embeddings" icon="waypoints" href="/self-hosting/embeddings">
    Local default, OpenAI / Gemini / Ollama, multilingual
  </Card>

  <Card title="Memory API" icon="book-open" href="/quickstart">
    The full API — it all works against your local server
  </Card>
</CardGroup>


> ## Documentation Index
> Fetch the complete documentation index at: https://supermemory.ai/docs/llms.txt
> Use this file to discover all available pages before exploring further.

# Self-Hosting Configuration

> Every environment variable the self-hosted server understands.

The self-hosted server aims for **zero configuration** — the only required input is one LLM provider key, which the first-boot wizard collects interactively (or set via env var for non-interactive deployments). Embeddings default to local English; you can pick another provider in the optional wizard step or via env. Everything else below is opt-in.

The installer writes API keys to `~/.supermemory/env`, which is loaded on every launch. You can also set variables in your shell or a process manager.

## Core

| Variable                       | Purpose                                                          | Default          |
| ------------------------------ | ---------------------------------------------------------------- | ---------------- |
| `PORT` (or `SUPERMEMORY_PORT`) | HTTP listen port                                                 | `6767`           |
| `SUPERMEMORY_DATA_DIR`         | Where the graph engine's data, auth secret, and model cache live | `./.supermemory` |

## LLM providers

In production, Supermemory uses its own proprietary models tuned for long-horizon data understanding. Self-hosted, you bring your own LLM for the intelligent steps — summaries, contextual chunking, and memory extraction. Embeddings default to a local model (no API key) and can optionally use OpenAI, Gemini, or Ollama — see [Embeddings](/self-hosting/embeddings). Configure **at least one** LLM provider:

| Variable                                              | Provider                                              |
| ----------------------------------------------------- | ----------------------------------------------------- |
| `OPENAI_API_KEY`                                      | OpenAI — or any OpenAI-compatible endpoint, see below |
| `ANTHROPIC_API_KEY`                                   | Anthropic                                             |
| `GEMINI_API_KEY`                                      | Google AI Studio (Gemini)                             |
| `GROQ_API_KEY`                                        | Groq                                                  |
| `WORKERS_AI_API_KEY` + `CLOUDFLARE_ACCOUNT_ID`        | Cloudflare Workers AI                                 |
| `GOOGLE_VERTEX_PROJECT_ID` + `GOOGLE_VERTEX_LOCATION` | GCP Vertex AI                                         |

<Tip>
  No key set? The server walks you through it. On first boot, an interactive setup wizard asks which provider you want, securely prompts for the key, and saves it encrypted — including a custom base URL and model name if you pick an OpenAI-compatible endpoint.
</Tip>

With multiple providers configured, the first one in the order above is used.

<Note>
  Image, video, and high-fidelity PDF understanding require a Gemini or Vertex AI key. Text ingestion, memory extraction, and search work with any provider.
</Note>

### Fully offline with local models

`OPENAI_API_KEY` + `OPENAI_BASE_URL` covers any OpenAI-compatible endpoint: Ollama, LM Studio, vLLM, llama.cpp server, Together, Fireworks, and more.

```bash theme={null}
# Ollama example — gpt-oss-20b works great
OPENAI_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama        # any non-empty string for local runners
OPENAI_MODEL=gpt-oss:20b
```

| Variable            | Purpose                         | Default        |
| ------------------- | ------------------------------- | -------------- |
| `OPENAI_BASE_URL`   | OpenAI-compatible endpoint URL  | OpenAI         |
| `OPENAI_MODEL`      | Model ID sent to that endpoint  | `gpt-5.1`      |
| `OPENAI_FAST_MODEL` | Override for fast/light tasks   | `OPENAI_MODEL` |
| `OPENAI_TEXT_MODEL` | Override for heavier text tasks | `OPENAI_MODEL` |

## File storage

Nothing to configure. Uploaded files (PDFs, images) are stored on local disk inside `$SUPERMEMORY_DATA_DIR` and served by the server at `/files/:key`.

## Embeddings

By default, vectors are computed locally with `Xenova/bge-base-en-v1.5` (768d) — no embedding API key. On interactive first boot you can pick a different provider after the LLM key step; for Docker/CI set env vars instead.

Full provider table, multilingual guidance, remote examples (OpenAI / Gemini / Ollama), and the re-ingestion / dimension-lock warning: **[Embeddings (self-hosted)](/self-hosting/embeddings)**.

| Variable                           | Purpose                                                  | Default                   |
| ---------------------------------- | -------------------------------------------------------- | ------------------------- |
| `SUPERMEMORY_EMBEDDING_PROVIDER`   | `local`, `openai`, `gemini`, or OpenAI-compatible remote | `local`                   |
| `SUPERMEMORY_EMBEDDING_MODEL`      | Model id for the chosen provider                         | `Xenova/bge-base-en-v1.5` |
| `SUPERMEMORY_EMBEDDING_DIMENSIONS` | Vector size; must match model and stored data            | `768`                     |
| `SUPERMEMORY_EMBEDDING_BASE_URL`   | Base URL for OpenAI-compatible embedding APIs            | unset                     |

### Embedding performance

Local embeddings are prewarmed at startup with conservative defaults — one worker, minimal CPU footprint. Turn these up if you're ingesting heavily and prefer throughput over headroom:

| Variable                                      | Purpose                                 | Default  |
| --------------------------------------------- | --------------------------------------- | -------- |
| `SUPERMEMORY_LOCAL_EMBEDDING_POOL_SIZE`       | Number of embedding workers             | `1`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_WASM_THREADS`    | Compute threads per worker              | `1`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_BATCH_SIZE`      | Texts per worker dispatch               | `8`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_IDLE_TIMEOUT_MS` | Idle time before workers shut down      | `120000` |
| `SUPERMEMORY_SKIP_EMBEDDING_PREWARM`          | Skip startup prewarm, load on first use | unset    |

## Memory limits & ingestion queue

The server manages memory for you and separates the two kinds of work you send it:

* **Searches are always served immediately.** They never wait behind ingestion, regardless of how much is queued.
* **Adds are accepted instantly but processed through a queue.** A `POST /v3/documents` call returns in milliseconds with status `queued`; extraction, embedding, and indexing happen in the background at a controlled pace.

Ingestion may grow the server's memory usage by at most `SUPERMEMORY_EMBEDDING_RAM_LIMIT` (default **1 GB**) above its post-boot baseline. Past that, new documents simply wait in the queue until memory drops back under the limit — nothing is dropped, ingestion just slows down. The limit is measured above the boot baseline because the built-in local embeddings and storage engine have a fixed footprint that exists before any document is processed.

The limit is printed at boot, and whenever adds are waiting the binary shows a live status line in the terminal:

```
[ingest] memory limit 1.0 GB above baseline (1.6 GB) · 2 concurrent — set SUPERMEMORY_EMBEDDING_RAM_LIMIT=ngb to change
[ingest] 2 running · 193 queued · 0.4 GB / 1.0 GB ingest memory
[ingest] 2 running · 193 queued · paused — 1.1 GB / 1.0 GB ingest memory, waiting for it to drop
[ingest] resumed — memory back under the 1.0 GB ingest limit
```

| Variable                          | Purpose                                                                                                   | Default |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- | ------- |
| `SUPERMEMORY_EMBEDDING_RAM_LIMIT` | Memory ingestion may use above the boot baseline. Accepts `1gb`, `1.5gb`, `512mb`, or a bare number (GB). | `1gb`   |
| `SUPERMEMORY_INGEST_CONCURRENCY`  | Documents processed concurrently                                                                          | `2`     |

```bash theme={null}
# Give ingestion 4 GB of headroom on a larger machine
SUPERMEMORY_EMBEDDING_RAM_LIMIT=4gb ./supermemory-server
```

Raise the limit and concurrency on machines with spare RAM for faster bulk imports; lower them on small VPSes where you want the server to stay lean and don't mind adds draining slowly.

## Telemetry

The self-hosted binary sends no analytics — there is nothing to opt out of. The only related switch:

| Variable                        | Purpose                                                              | Default |
| ------------------------------- | -------------------------------------------------------------------- | ------- |
| `SUPERMEMORY_DISABLE_TELEMETRY` | Set to `1` to also disable internal AI SDK telemetry instrumentation | unset   |

## Platform-only features

These exist in the codebase but are exclusive to the [hosted platform](https://console.supermemory.ai) — the self-hosted binary doesn't include them:

* **Connectors** — Google Drive, Notion, Gmail, OneDrive background sync
* **Supermemory MCP** — managed MCP server endpoints
* **Optimized memory extraction** — the platform's extraction pipeline is tuned for higher quality at lower cost than bring-your-own-key
* **Managed scale** — globally distributed infrastructure, no capacity planning

Any other environment variables you may find referenced in the codebase are platform-only: the self-hosted binary ignores them even when set.

## Example: production-ish `.env`

```dotenv theme={null}
# Persistent data location
SUPERMEMORY_DATA_DIR=/var/lib/supermemory

# One LLM provider (required for extraction)
OPENAI_API_KEY=sk-...

# Optional — omit to keep local Xenova/bge-base-en-v1.5 (768d)
# SUPERMEMORY_EMBEDDING_PROVIDER=openai
# SUPERMEMORY_EMBEDDING_MODEL=text-embedding-3-small
# SUPERMEMORY_EMBEDDING_DIMENSIONS=1536
```

That's enough for full ingestion, memory extraction, and hybrid search with the default local embeddings.


> ## Documentation Index
> Fetch the complete documentation index at: https://supermemory.ai/docs/llms.txt
> Use this file to discover all available pages before exploring further.

# Embeddings (self-hosted)

> Local and remote embedding providers for Supermemory local — defaults, env vars, multilingual options, and dimension lock.

Self-hosted Supermemory uses the **same embedding provider stack** as the hosted platform: local ONNX models, OpenAI, Gemini, or any OpenAI-compatible embeddings endpoint (including Ollama). LLM keys power extraction and summarization; embeddings are configured separately.

## Defaults

|            |                             |
| ---------- | --------------------------- |
| Provider   | `local`                     |
| Model      | `Xenova/bge-base-en-v1.5`   |
| Dimensions | `768`                       |
| API key    | None — runs on your machine |

Press Enter at the optional first-boot picker to keep this default. Nothing is sent off-box to embed.

<Warning>
  The default local model is **English-only**. Non-English content can ingest successfully while dense semantic recall stays weak. See [Multilingual](#multilingual).
</Warning>

## First-time setup (interactive)

On first boot with a TTY, Supermemory asks for an LLM API key (required), then optionally which embedding model to use.

1. Choose or paste an LLM provider key (OpenAI, Anthropic, Gemini, Groq, or OpenAI-compatible).
2. Optionally pick an embedding provider/model. **Press Enter to keep the local English model.**
3. Choices are saved encrypted under your data directory (`$SUPERMEMORY_DATA_DIR`, typically `./.supermemory` / `~/.supermemory`).

Boot order is intentional: LLM keys load first so remote embedding options can reuse them (for example OpenAI or Gemini embeddings with the same key).

<Tip>
  **First boot (terminal):** Supermemory asks for an LLM API key (required), then optionally which embedding model to use. Press Enter to keep the local English model. Choices are saved encrypted under your data directory.
</Tip>

## Configuration (env)

For Docker, CI, or any non-interactive deploy, set env vars — there is **no interactive prompt without a TTY**.

| Variable                           | Purpose                                                                                                     | Default                           |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `SUPERMEMORY_EMBEDDING_PROVIDER`   | Embedding backend: `local`, `openai`, `gemini`, or an OpenAI-compatible remote (`ollama` / custom base URL) | `local`                           |
| `SUPERMEMORY_EMBEDDING_MODEL`      | Model id for the chosen provider                                                                            | `Xenova/bge-base-en-v1.5` (local) |
| `SUPERMEMORY_EMBEDDING_DIMENSIONS` | Vector size; must match the model and any already-stored data                                               | `768` (local default)             |
| `SUPERMEMORY_EMBEDDING_BASE_URL`   | Base URL for OpenAI-compatible embedding APIs (Ollama, vLLM, etc.)                                          | unset                             |
| `OPENAI_API_KEY`                   | Used when provider is `openai` (or compatible) if not otherwise supplied                                    | unset                             |
| `GEMINI_API_KEY`                   | Used when provider is `gemini`                                                                              | unset                             |

Local worker tuning (throughput only — does not change model or dimensions):

| Variable                                      | Purpose                                 | Default  |
| --------------------------------------------- | --------------------------------------- | -------- |
| `SUPERMEMORY_LOCAL_EMBEDDING_POOL_SIZE`       | Number of embedding workers             | `1`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_WASM_THREADS`    | Compute threads per worker              | `1`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_BATCH_SIZE`      | Texts per worker dispatch               | `8`      |
| `SUPERMEMORY_LOCAL_EMBEDDING_IDLE_TIMEOUT_MS` | Idle time before workers shut down      | `120000` |
| `SUPERMEMORY_SKIP_EMBEDDING_PREWARM`          | Skip startup prewarm, load on first use | unset    |

Ingestion memory headroom is controlled by `SUPERMEMORY_EMBEDDING_RAM_LIMIT` — see [Memory limits & ingestion queue](/self-hosting/configuration#memory-limits--ingestion-queue).

<Tip>
  **Docker / production:** Set at least one LLM key and, if you don’t want local embeddings, set `SUPERMEMORY_EMBEDDING_PROVIDER` / `SUPERMEMORY_EMBEDDING_MODEL` / `SUPERMEMORY_EMBEDDING_DIMENSIONS` (and base URL or API key as needed). There is no interactive prompt without a TTY.
</Tip>

## Multilingual

The default `Xenova/bge-base-en-v1.5` model is trained for English. For German, Dutch, and other non-English corpora, dense recall can fail even when hybrid keyword search still finds rare tokens.

For multilingual or non-English deployments, switch **before** large backfills:

```bash theme={null}
# Example: local multilingual (set dimensions to match the model)
SUPERMEMORY_EMBEDDING_PROVIDER=local
SUPERMEMORY_EMBEDDING_MODEL=Xenova/bge-m3
SUPERMEMORY_EMBEDDING_DIMENSIONS=1024
```

Or use a remote multilingual embedding API (OpenAI, Gemini, or Ollama with a multilingual embed model). Set provider, model, and dimensions together. Changing them later requires a fresh data directory or full re-ingestion — see below.

## Remote providers

### Local (default)

```bash theme={null}
# Explicit local default — no embedding API key
SUPERMEMORY_EMBEDDING_PROVIDER=local
SUPERMEMORY_EMBEDDING_MODEL=Xenova/bge-base-en-v1.5
SUPERMEMORY_EMBEDDING_DIMENSIONS=768
```

### OpenAI

```bash theme={null}
OPENAI_API_KEY=sk-...
SUPERMEMORY_EMBEDDING_PROVIDER=openai
SUPERMEMORY_EMBEDDING_MODEL=text-embedding-3-small
SUPERMEMORY_EMBEDDING_DIMENSIONS=1536
```

### Gemini

```bash theme={null}
GEMINI_API_KEY=...
SUPERMEMORY_EMBEDDING_PROVIDER=gemini
SUPERMEMORY_EMBEDDING_MODEL=text-embedding-004
SUPERMEMORY_EMBEDDING_DIMENSIONS=768
```

### Ollama (OpenAI-compatible)

```bash theme={null}
SUPERMEMORY_EMBEDDING_PROVIDER=openai
SUPERMEMORY_EMBEDDING_BASE_URL=http://localhost:11434/v1
OPENAI_API_KEY=ollama
SUPERMEMORY_EMBEDDING_MODEL=nomic-embed-text
SUPERMEMORY_EMBEDDING_DIMENSIONS=768
```

Use the dimension published for your chosen model. A mismatch with vectors already in the store fails boot.

## Changing models later

<Warning>
  **Not supported in place.** Embeddings from different models (or different dimensions) are not comparable. Start from a fresh data directory or re-ingest all content so vectors stay in one space. If configured dimensions disagree with stored data, the server **refuses to boot**.
</Warning>

**Changing embeddings later:** Not supported in place. Start from a fresh data directory or re-ingest all content so vectors stay comparable.

## Related

* [Configuration](/self-hosting/configuration) — LLM providers, storage, ingestion limits
* [Quickstart](/self-hosting/quickstart) — install and first memory


> ## Documentation Index
> Fetch the complete documentation index at: https://supermemory.ai/docs/llms.txt
> Use this file to discover all available pages before exploring further.

# Local vs. Enterprise

> Supermemory local is for builders. Supermemory Enterprise is for organizations.

Supermemory local — the self-hosted binary — is free, open source, and built for individual developers: local-first workflows, prototyping, air-gapped experiments, privacy-sensitive side projects.

**Supermemory Enterprise** is the full platform, run for your organization: the same memory engine with proprietary models, organizational controls, and infrastructure that scales with you — without you operating any of it.

## At a glance

|                    | Supermemory local                                      | Enterprise                                                             |
| ------------------ | ------------------------------------------------------ | ---------------------------------------------------------------------- |
| **Memory engine**  | Full graph engine, embedded                            | Full graph engine, managed                                             |
| **Models**         | Bring your own key (any provider, incl. fully offline) | Proprietary models tuned for long-horizon data understanding           |
| **Authentication** | Single auto-generated API key                          | Organization-wide authentication and access controls                   |
| **Team access**    | Single org on one machine                              | Multi-member organizations, roles, and scoped API keys                 |
| **Observability**  | Server logs                                            | Control dashboard: usage analytics, ingestion monitoring, request logs |
| **Control**        | Env vars on your box                                   | Org-wide settings, key management, and governance from the console     |
| **Connectors**     | —                                                      | Google Drive, Notion, Gmail, OneDrive with continuous background sync  |
| **Scalability**    | One machine, one process                               | Globally distributed, scales elastically with your workload            |
| **Hosting**        | You run it                                             | Fully managed — or dedicated deployments for compliance needs          |
| **Support**        | Community ([GitHub](https://git.new/memory))           | Dedicated support, onboarding, and SLAs                                |

## What Enterprise adds

### Auth and team access

Local runs as a single-tenant server with one API key. Enterprise gives your whole organization structured access: member roles, and API keys scoped per environment, per team, or per app — all revocable from one place.

### Observability and the control dashboard

Local gives you logs. Enterprise gives you the console: live usage analytics, ingestion pipeline visibility, search and request logs, and per-key attribution — so you always know what your agents are remembering, and what it costs.

### Memory quality

Local runs the extraction pipeline on whatever model you bring. Enterprise runs it on Supermemory's proprietary models, purpose-tuned for long-horizon data understanding — higher-quality memories at a lower effective cost than any bring-your-own-key setup.

### Scale and hosting

Local is bounded by one machine — which is the point. Enterprise runs on globally distributed infrastructure that scales with your ingestion volume and query load, with no capacity planning on your side. For strict data residency or compliance requirements, dedicated deployment options are available.

## Moving between them

The two speak the same API. Code written against your local server moves to Enterprise by changing the `baseURL` — and vice versa. Prototype locally, ship on Enterprise.

<CardGroup cols={2}>
  <Card title="Talk to us" icon="mail" href="mailto:dhravya@supermemory.com">
    Get a walkthrough of Supermemory Enterprise for your team
  </Card>

  <Card title="Start locally" icon="terminal" href="/self-hosting/quickstart">
    Install the binary and build against the same API today
  </Card>
</CardGroup>
