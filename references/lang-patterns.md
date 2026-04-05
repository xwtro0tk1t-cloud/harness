# Tech Stack Coding Patterns Quick Reference

Language/framework-specific coding conventions. During Harness initialization, applicable sections are extracted based on the detected project tech stack and written to `docs/conventions/coding-patterns.md`.

> **Note**: This is a reference template — tailor it to your project's actual needs. If your project uses a language/framework not listed here, add a custom section following the existing format.

---

## Python

### Security
- SQL queries MUST use parameterization (`db.execute("... WHERE id = :id", {"id": v})`), never f-string/format concatenation — CWE-89
- `subprocess` must not use `shell=True`, use argument lists instead — CWE-78
- Secrets via environment variables or Secret Manager, never hardcoded — CWE-798
- `pickle.loads` / `yaml.load` must not process untrusted input, use `json.loads` / `yaml.safe_load` — CWE-502
- User input must never be passed to `eval()` / `exec()` — CWE-95

### Idiomatic Patterns
- Add type hints to function signatures and return values (`def foo(x: int) -> str:`)
- Prefer `dataclass` / `pydantic.BaseModel` over raw dicts for data structures
- Use `pathlib.Path` for path operations instead of `os.path` string concatenation
- Use `with` for resource management (files, connections, locks)
- Async code uses `async/await`, don't mix `threading` + `asyncio`

### Common Pitfalls
- **Mutable default args**: `def foo(items=[])` → multiple calls share the same list. Use `items: list | None = None`
- **Circular imports**: A imports B, B imports A → use lazy imports or restructure modules
- **GIL**: CPU-bound tasks use `multiprocessing` or C extensions; `threading` only for IO-bound work
- **Float comparison**: `0.1 + 0.2 != 0.3`, use `math.isclose()` or `decimal.Decimal`

---

## JavaScript / TypeScript

### Security
- Sanitize HTML rendering with DOMPurify, never inject user content via raw `innerHTML` — CWE-79
- Database queries use parameterization (Prisma / Knex / pg parameterized), never template literal SQL — CWE-89
- Never use `eval()` / `new Function()` with user input — CWE-95
- Configure CSP (Content-Security-Policy) response headers
- Cookies: set `HttpOnly` + `Secure` + `SameSite=Strict`

### Idiomatic Patterns
- Enable strict mode (TypeScript: `"strict": true`)
- Variable declaration priority: `const` > `let`, never `var`
- Async uses `async/await`, not nested callbacks or bare `.then()` chains
- TypeScript: use `interface` for object shapes, `type` for unions, avoid `any`
- Error handling: custom Error classes, explicit types in `catch`

### Common Pitfalls
- **Prototype pollution**: When deep-merging user input, check for `__proto__` / `constructor` / `prototype` keys
- **== vs ===**: Always use `===` to avoid implicit type coercion
- **this binding**: Arrow functions don't bind `this`; use arrow functions or `.bind()` for class method callbacks
- **Closure trap**: `for (var i ...)` + async → use `let` or `for...of`
- **Float precision**: Use integers (cents) or `decimal.js` for monetary calculations

---

## Go

### Security
- SQL uses `?` or `$1` placeholders (`db.Query("... WHERE id = ?", id)`), never `fmt.Sprintf` for SQL — CWE-89
- Random numbers use `crypto/rand`, not `math/rand` (predictable)
- TLS connections must verify certificates, never set `InsecureSkipVerify: true` (except in tests)
- HTTP clients must set timeouts (`http.Client{Timeout: 10 * time.Second}`) to prevent resource exhaustion

### Idiomatic Patterns
- Error wrapping: `fmt.Errorf("xxx: %w", err)` to preserve error chains
- Context propagation: first parameter is `ctx context.Context` for timeout/cancellation
- Use `defer` for resource cleanup (files, locks, connections); note: defer executes on function return
- Minimize exported API: use lowercase for unexported identifiers
- Small interfaces: `io.Reader` (1 method) is better than large interfaces

### Common Pitfalls
- **Goroutine leak**: Channel send with no receiver blocks forever → use `context.WithCancel` + `select` for exit
- **nil interface vs nil pointer**: `var err *MyError = nil; var i error = err; i != nil` → true (interface is non-nil)
- **Range variable capture**: `for _, v := range items { go func() { use(v) }() }` → v is shared. Pass as param or use Go 1.22+ semantics
- **Slice append trap**: append may modify the underlying array → `copy` or `slices.Clone` when isolation is needed

---

## Java

### Security
- SQL uses `PreparedStatement`, never string concatenation — CWE-89
- Never pass user input to `Runtime.getRuntime().exec()` — CWE-78
- Jackson deserialization: enable `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`, disable default typing
- XML parsing must disable external entities (`XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false`) — CWE-611
- Spring Security: keep CSRF protection enabled, mind custom filter ordering

### Idiomatic Patterns
- Use `Optional<T>` for nullable values instead of returning null
- Resource management with try-with-resources (`try (var conn = ...)`)
- DTOs use records (Java 16+): `record UserDTO(String name, int age) {}`
- Collection operations use Stream API, but split into variables when exceeding 3 steps for readability
- Logging uses SLF4J + parameterization: `log.info("user {} logged in", userId)`, never string concatenation

### Common Pitfalls
- **equals/hashCode contract**: Override `equals` → must also override `hashCode`, otherwise HashMap/HashSet misbehave
- **ConcurrentModificationException**: Don't modify collections during iteration → use `ConcurrentHashMap` or `Iterator.remove()`
- **Checked exception abuse**: Don't let checked exceptions propagate through multiple layers → wrap as unchecked or use Result pattern
- **Spring Bean thread safety**: Default singleton → don't store mutable state, or use `@Scope("prototype")`

---

## Rust

### Security
- `unsafe` blocks require justification and comments — every `unsafe` must have a `// SAFETY:` comment
- SQL uses sqlx compile-time checks or parameterized queries, never `format!` for SQL
- Error types use `thiserror`, avoid `.unwrap()` / `.expect()` (only when panic is impossible)
- Cryptography uses `ring` / `rustls`, never roll your own crypto
- Dependency audit: `cargo audit` to check for known vulnerabilities

### Idiomatic Patterns
- Error handling: `Result<T, E>` over `panic!`, propagate with `?` operator
- Maintain zero `cargo clippy` warnings
- Leverage derive macros: `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]`
- Strings: function parameters take `&str` (borrowed), use `String` when ownership is needed
- Iterator chains over manual loops (`.iter().filter().map().collect()`)

### Common Pitfalls
- **Lifetime elision confusion**: When the compiler reports lifetime errors, annotate explicitly first, then simplify
- **Async runtime mixing**: Never call `std::thread::sleep` inside a tokio runtime (blocks thread pool), use `tokio::time::sleep`
- **Cargo feature flags**: Features are additive → don't use features for mutually exclusive choices
- **Send + Sync**: Cross-thread data transfer requires `Send`, shared references require `Sync` → `Rc` won't work, use `Arc`

---

## Docker / IaC

### Security
- Containers MUST run as non-root user (`USER appuser`) — principle of least privilege
- Never embed secrets in `ENV` / `COPY` → inject at runtime via Secret Manager / environment variables
- Use multi-stage builds; production images must not contain build toolchains
- Enable read-only root filesystem (`--read-only`), write temporary data to tmpfs
- Scan base images for vulnerabilities (Trivy / Grype), update regularly

### Idiomatic Patterns
- `.dockerignore` excludes .git / node_modules / __pycache__ / .env
- Base images use pinned version tags (`python:3.12-slim`), never `latest`
- Configure `HEALTHCHECK` directive (or K8s liveness/readiness probes)
- Order Dockerfile instructions by change frequency: rarely-changed on top (OS deps), frequently-changed on bottom (code COPY)
- K8s/Terraform: sensitive values use Sealed Secrets / External Secrets / Vault

### Common Pitfalls
- **Layer cache invalidation**: Put `COPY . .` after `RUN pip install`, otherwise every code change reinstalls dependencies
- **Signal handling (PID 1)**: Container main process must handle SIGTERM properly → use `exec` or `tini` as init process
- **Timezone issues**: Alpine lacks timezone data → install `tzdata` or set `TZ` environment variable
- **Docker socket mount**: `-v /var/run/docker.sock` grants the container root-equivalent access → forbidden unless absolutely necessary
- **Large images**: Clean cache after `apt-get install` (`rm -rf /var/lib/apt/lists/*`), use alpine/distroless base images
