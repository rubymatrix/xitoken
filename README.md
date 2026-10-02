# xitoken

Short-lived, single-use, signed tokens that let a POL provider (auth + lobby) admit a player to an FFXI world it
does not share a database with. The format is in [SPEC.md](SPEC.md): PASETO v4.public (Ed25519), server ids
derived from identity keys, signed key sets, and the `xi.world-entry/1` token.

```
provider (e.g. Project Crystal)                          world (e.g. PhoenixPS2 / any LSB server)
  player picks a character
  TokenIssuer.Issue("xi.world-entry/1", aud=<world id>)  ──►  POST /xi/v1/world-entry
        signed with a key from its signed key set           Verifier: checks the key against the provider's key set
                                                            checks the character belongs to <provider id>:<player>
                                                            writes its own accounts_sessions row
  client → map server (unchanged 0x00A / Blowfish)       ──►  finds the row, as today
```

## Ids and keys

* Every server has an **identity key**. Its **server id** is `xi1.` plus 22 characters derived from the key, so ids
  are globally unique, need no registry, and can't be claimed without the key.
* A player's **global id** is `<provider server id>:<account id at the provider>`.
* The identity key signs only the server's **key set**: the list of signing keys it currently uses. Signing keys
  rotate without changing the server id.
* A world trusts a provider by its server id alone. The key set proves itself, so it can be copied from anywhere.

## Layout

| path | what |
|---|---|
| `SPEC.md` | the format and the world gateway API. Read this first if you are writing another implementation |
| `vectors/paseto-v4-public.json` | upstream PASETO v4.public vectors |
| `vectors/xitoken.json` | cross-implementation vectors: server ids, key sets, tokens. Same key and payload give the same token and the same verdict |
| `dotnet/XiToken` | C# library (net8.0, BouncyCastle) — for Crystal and other .NET servers |
| `dotnet/XiToken.Cli` | `xitoken-cli`: keygen, keyset, show-keyset, issue, verify, gen-vectors |
| `cpp/` | C++17 library, one header and one source file (OpenSSL 3 libcrypto, nlohmann/json) — for LSB-based servers |

The libraries know nothing about databases, sockets or FFXI servers. To plug them in, you supply:

* **which servers you trust:** `KeySetResolver.Trust(keySetToken, serverId)`, or your own `IKeyResolver`
* **a replay guard:** `MemoryReplayGuard` for a single process, or your own `IReplayGuard` over a shared table
* **what to do with a verified token:** for LSB, check the character's owner and insert the `accounts_sessions` row

## Use

Operators:

```
xitoken-cli keygen --out identity.key                    # prints the server id
xitoken-cli keygen --kid 2026-10 --out signing-2026-10.key
xitoken-cli keyset --identity identity.key --name "Crystal" 2026-10=signing-2026-10.key > crystal.keyset
xitoken-cli show-keyset crystal.keyset
xitoken-cli verify --trust <crystal id>=crystal.keyset --aud <world id> --type xi.world-entry/1 <token>
```

Keep `identity.key` offline if you can. It is only needed to publish a new key set.

C# (provider):

```csharp
var signing = SigningKey.FromPaserk("2026-10", File.ReadAllText("signing-2026-10.key").Trim());
var issuer = new TokenIssuer(crystalServerId, signing);
string token = issuer.Issue(WorldEntry.Type, audience: worldServerId, subject: polId,
                            WorldEntry.DefaultLifetime, entry.ToClaims());
```

C++ (world):

```cpp
xitoken::KeySetResolver keys;
keys.trustFile("trust/crystal.keyset", "xi1.…", -1, &error);
xitoken::MemoryReplayGuard replay;
xitoken::VerifierOptions options;
options.audience    = myServerId;
options.replayGuard = &replay;
xitoken::Verifier verifier(keys, options);

auto result = verifier.verify(token, xitoken::WorldEntry::type);
if (!result) { /* reject: xitoken::toString(result.error) */ }
auto entry = xitoken::WorldEntry::fromClaims(result.token->claims); // nullopt → reject
// result.token->playerId() is "<provider id>:<sub>"
```

CMake: `add_subdirectory(xitoken/cpp)` and link `xitoken`. If the parent project names its OpenSSL or json targets
differently, set `XITOKEN_CRYPTO_TARGET` / `XITOKEN_JSON_TARGET` first. In LandSandBoat those are `libcrypto` and
`nlohmann_json::nlohmann_json`.

## Tests

```
dotnet test dotnet/XiToken.slnx
cmake -S cpp -B build && cmake --build build && build/xitoken_tests
```

If you change the vector generator (`Vectors` in `XiToken.Cli/Program.cs`), regenerate the vectors with
`dotnet run --project dotnet/XiToken.Cli -- gen-vectors --out vectors/xitoken.json`. Both test suites must still
pass afterwards.
