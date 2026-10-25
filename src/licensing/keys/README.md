# Licence trust anchors

Each `<kid>.pub` file here is an Ed25519 public key (SPKI PEM) that manar-api trusts to sign
licences. The file name without `.pub` is the `kid` a licence names in its JWS header. `nest
build` copies these files to `dist/licensing/keys/`, so they ship in the image.

No production key is here yet. Until one is added, every licence reports `unverifiable` (unknown
`kid`) and nothing is blocked.

To add one (founder only; see `docs/licensing.md`):

1. Generate the keypair offline and keep the private key out of every repository.
2. Commit only the public key as `src/licensing/keys/<kid>.pub` in a merge request.
3. To rotate, add the new `<kid>.pub` next to the old one, issue licences with the new `kid`, and
   remove the old file once no deployed licence uses it.

Never put a private key in this directory. Tests generate their own keypair at run time.
