# Screenshot maintenance

The public administration screenshots use **Aster Delivery**, a fictional English organization.
They were captured from the running Broker with an isolated SQLite database and no enabled external
services. People, teams and projects are invented. Generated credentials and the temporary environment
were deleted after capture; no example accounts are installed with the product.

| Asset | Purpose | References |
|---|---|---|
| `assets/broker-resource-grants.jpg` | Compare audiences, capabilities and exact project scopes | README, administration guide and the shared Graphit website |
| `assets/broker-identities.jpg` | Distinguish people and service identities, membership, roles and onboarding state | Administration guide |

Use the [shared capture workflow](https://github.com/graphit-labs/graphit-code/blob/main/docs/guides/product_screenshots.md)
when replacing these images. Build the current binary because administration HTML is embedded.
Use a new database and loopback port; never seed a real Broker. Create state through the supported
bootstrap and administration APIs, preserving CSRF and revision checks. Do not place passwords,
service credentials, tokens or deployment secrets in a capture.

Keep the grants image byte-identical in Code's `docs/site/assets/broker-resource-grants.jpg`.
Review captions against actual state: these demo accounts have pending onboarding steps, and a
configured grant is not evidence that an embedding, rerank or storage service is enabled.
