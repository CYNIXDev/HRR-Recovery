# HARR Footer

Current validated footer layout is 49 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `HARR` magic |
| 4 | 1 | Version (`21` observed) |
| 5 | 24 | Per-file field (semantics currently unknown) |
| 29 | 4 | Reserved |
| 33 | 4 | Footer offset, big-endian uint32 |
| 37 | 4 | Constant (`0x00001000` observed) |
| 41 | 4 | Reserved |
| 45 | 4 | `HARR` magic |

The parser requires the stored footer offset to equal the actual footer start. Unknown and reserved bytes are preserved without assigning speculative meaning.

This documents the current research model, not a vendor specification.
