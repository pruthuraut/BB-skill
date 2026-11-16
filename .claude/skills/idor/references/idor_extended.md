# IDOR and Access-Control Extension (extension)

Use two self-owned accounts (A and B). Every check is `bounded`: read or harmless-change on B's objects using A's session, then compare. Writes only on objects you created.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| IDOR-X-001 | Path IDs | Sequential ID swap on profile, order, invoice endpoints | bounded | Account A requests B's ID, compare body |
| IDOR-X-002 | UUID | UUID v1 time-based predictability | bounded | Two own UUIDs, compare timestamps |
| IDOR-X-003 | ObjectId | MongoDB ObjectId predictability | bounded | Two own IDs, compare counter bytes |
| IDOR-X-004 | Encoded IDs | Base64 or hex encoded IDs decode to sequence | passive | Decode own IDs |
| IDOR-X-005 | Query IDs | IDOR via query string parameter | bounded | Swap own ID for B's ID |
| IDOR-X-006 | JSON body | IDOR via nested object ID | bounded | Swap nested ID |
| IDOR-X-007 | Methods | GET allowed but PUT or DELETE not checked (or reverse) | bounded | Same ID across methods, own objects |
| IDOR-X-008 | Versions | Older API version lacks authorization | bounded | Same request on /v1 and /v2 |
| IDOR-X-009 | Files | Downloadable file by ID without ownership | bounded | Swap file ID |
| IDOR-X-010 | Bulk | Bulk export includes other users' objects | bounded | Own bulk request with B's IDs |
| IDOR-X-011 | Search | Search and filter return other users' objects | bounded | Search as A for B's known unique value |
| IDOR-X-012 | Pagination | Page offset returns objects across tenants | bounded | Pages 1 to 3 as A, check for B's records |
| IDOR-X-013 | Notifications | Notification or message IDs readable across users | bounded | Swap message ID |
| IDOR-X-014 | WebSockets | Object ID in socket messages not checked | bounded | See client-side-js-security WS-001 |
| IDOR-X-015 | GraphQL | Object argument not checked | bounded | See api-security API-X-005 |
| IDOR-X-016 | Object reassignment | Set owner to another user's ID on update | bounded | Own object, set owner field to B's ID, expect rejection |
| IDOR-X-017 | Cross-application | Object accessible from another app on same account | bounded | Swap IDs across apps you own |
| IDOR-X-018 | Second order | Reference stored earlier then used in later step | bounded | Multi-step flow with own objects |
| IDOR-X-019 | Harvesting | IDs leaked in responses, archives, or JS | passive | Grep responses and archives for other users' IDs (do not use real data) |
