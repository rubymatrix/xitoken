# xitoken

Federation for FFXI private servers: a PlayOnline provider (auth + lobby, such as Project Crystal) lets its players
use worlds run by other operators, without sharing a database or a secret with them. The format is in
[SPEC.md](SPEC.md):

* PASETO v4.public (Ed25519) tokens;
* server ids derived from identity keys, and signed key sets;
* a world gateway API for entering the world and for listing, creating, renaming and deleting characters;
* signed registries for a shared world list.

```
provider (e.g. Project Crystal)                    world (e.g. PhoenixPS2 / any LSB server)
  lobby: list / create / rename / delete      ──►  GET|POST|DELETE /xi/v1/characters   (xi.account/1 token)
  lobby: player picks a character             ──►  POST /xi/v1/world-entry             (xi.world-entry/1 token)
                                                     checks the token against the provider's key set and the
                                                     character against <provider id>:<player>; writes the session
  client → map server (unchanged 0x00A / Blowfish)
```

Reference implementations:

* PhoenixPS2 (`src/world/federation_gateway.cpp`) is the world side.
* The Project Crystal lobby (`Federation.cs`) is the provider side.

## Ids and keys

* Every server has an **identity key**. Its **server id** is `xi1.` plus 22 characters derived from the key, so ids
  are globally unique, need no registry, and can't be claimed without the key.
* A player's **global id** is `<provider server id>:<account id at the provider>`.
* The identity key signs only the server's **key set**: the list of signing keys it currently uses. A world's key set
  also names its gateway, its expansions and, optionally, its search server. Signing keys rotate without changing the
  server id.
* Trust is a server id. Key sets and registries are signed documents, so they can be copied from anywhere.

## Layout

| path | what |
|---|---|
| `SPEC.md` | the format, the gateway API and registries. Read this first if you are writing another implementation |
| `vectors/paseto-v4-public.json` | upstream PASETO v4.public vectors |
| `vectors/xitoken.json` | cross-implementation vectors: server ids, key sets, registries, tokens. Same key and payload give the same token and the same verdict |
| `dotnet/XiToken` | C# library (net8.0, BouncyCastle): tokens, key sets, registries, and `GatewayClient` for providers |
| `dotnet/XiToken.Cli` | `xitoken-cli`: keygen, keyset, registry, show-keyset, show-registry, issue, verify, gen-vectors |
| `cpp/` | C++17 library, one header and one source file (OpenSSL 3 libcrypto, nlohmann/json), for LSB-based servers |

The token code knows nothing about databases or FFXI servers. To plug it in, you supply:

* **which servers you trust:** `KeySetResolver.Trust(keySetToken, serverId)`, or your own `IKeyResolver`;
* **a replay guard:** `MemoryReplayGuard` for a single process, or your own `IReplayGuard` over a shared table;
* **what a verified token does:** for an LSB world, the gateway in PhoenixPS2 is a complete example.

## Use

Operators:

```
xitoken-cli keygen --out identity.key                    # prints the server id
xitoken-cli keygen --kid 2026-10 --out signing-2026-10.key
xitoken-cli keyset --identity identity.key --name "Crystal" 2026-10=signing-2026-10.key > crystal.keyset
xitoken-cli show-keyset crystal.keyset
xitoken-cli registry --identity registry.key --name "PS2 Federation" \
    xi1.<world>=world=https://ps2.example.net:8088/xi/v1/keyset=sha256:<pin> > federation.registry
xitoken-cli verify --trust <crystal id>=crystal.keyset --aud <world id> --type xi.world-entry/1 <token>
```

Keep identity keys offline if you can. They are only needed to publish a new key set or registry.

C# (provider):

```csharp
var issuer = new TokenIssuer(crystalServerId, SigningKey.FromPaserk("2026-10", File.ReadAllText("signing.key").Trim()));
KeySet world = await GatewayClient.FetchKeySetAsync(keySetUrl, worldServerId, pin);
using var gateway = new GatewayClient(world.World!.Gateway, worldServerId, issuer, pin);

var characters = await gateway.ListCharactersAsync(polId);
var created    = await gateway.CreateCharacterAsync(polId, new NewCharacter("Ayame", 2, 4, 1, 1, 0));
var map        = await gateway.EnterAsync(polId, new WorldEntry(charId, null, clientIp, version, expansions, sessionKey));
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

## License

MIT; see [LICENSE](LICENSE).
