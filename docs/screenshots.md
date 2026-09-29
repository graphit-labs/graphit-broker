# Screenshot maintenance

The public administration screenshots use **Aster Delivery**, a fictional English organization.
They were captured from the running Broker with an isolated SQLite database and no enabled external
services. People, teams and projects are invented. Generated credentials and the temporary environment
were deleted after capture; no example accounts are installed with the product.

| Asset | Purpose | References |
|---|---|---|
| `assets/broker-resource-grants.jpg` | Historical four-step grant UI; retained for the shared Graphit website until its capture is replaced | Shared Graphit website |
| `assets/broker-identities.jpg` | Historical identities UI with former navigation labels; retained until a current capture replaces it | Historical reference only |

Use the [shared capture workflow](https://github.com/graphit-labs/graphit-code/blob/main/docs/guides/product_screenshots.md)
when replacing these images. Build the current binary because administration HTML is embedded.
Use a new database and loopback port; never seed a real Broker. Create state through the supported
bootstrap and administration APIs, preserving CSRF and revision checks. Do not place passwords,
service credentials, tokens or deployment secrets in a capture.

The grants image is no longer used by this repository's README or administration guide. Replace
it from the current Project access UI and update Code's `docs/site/assets/broker-resource-grants.jpg`
in the same capture workflow before using it as a current product image again.
The identities image is also no longer embedded in the administration guide because its sidebar
labels predate the current navigation. Replace it from the current Local users UI before using it
as a current product image again.
Review captions against actual state: these demo accounts have pending onboarding steps, and a
configured grant is not evidence that an embedding, rerank or storage service is enabled.
