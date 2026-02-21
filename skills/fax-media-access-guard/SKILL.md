---
name: fax-media-access-guard
description: Replace public upload exposure with signed expiring media URLs and secure file serving.
---

# Fax Media Access Guard

## Scope
- Move upload storage out of static public path.
- Generate signed expiring URLs for outbound media access.
- Serve files via signed `/media/:filename` route.
- Add periodic cleanup for stale files.

## Steps
1. Relocate upload directory under `DATA_DIR`.
2. Add URL signing and verification helpers.
3. Add secure media route.
4. Update upload endpoints to return signed URLs.
5. Add cleanup interval for old uploads.

## Done Criteria
- Unsigned/expired media requests return `403`.
- Signed media requests return files successfully.
