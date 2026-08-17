# HRR-Recovery

Open-source research toolkit for forensic analysis, format detection, and recovery of `.HRR` files.

## Project status

This project is preliminary forensic and recovery research. The goal is to understand the `.HRR` file structure and recover original media where possible.

The project does **not** assume that `.HRR` files are simply encrypted originals. High-entropy regions may represent compression, proprietary transformations, containers, or encrypted data; conclusions should be based on structural evidence.

## Current focus

- Parse the `HARR` footer and per-file metadata.
- Detect embedded JPEG, MPO, TIFF, RAW-like, RIFF, ISO-BMFF, ZIP, and PDF structures.
- Recover valid JPEG previews and full-resolution images where possible.
- Perform conservative JPEG reconstruction when structural evidence supports it.
- Preserve metadata such as EXIF, XMP, ICC profiles, and Photoshop metadata.
- Investigate RAW formats including NEF, CR2, CR3, ARW, DNG, RAF, ORF, RW2, PEF, and SRW.
- Investigate cryptographic decryption only when evidence demonstrates that encryption is involved.

## Forensic safety

Original `.HRR` files must never be overwritten or modified by recovery operations.

Real-world samples and potentially sensitive recovered media should not be committed to this public repository. Use synthetic or sanitized test data instead.

## Current known observations

- Sample files contain a 49-byte `HARR` footer.
- The footer includes version `21`, a 24-byte per-file field, a footer offset, `0x00001000`, reserved bytes, and a trailing `HARR` marker.
- The recorded footer offset matches the actual footer position at the end of the file.
- Some samples contain multiple valid JPEG representations, including thumbnails/previews and larger images.
- At least one sample can be reconstructed into a valid JPEG by restoring a missing JPEG SOI marker (`FF D8`), without using a cryptographic key.
- Preserved metadata includes EXIF/TIFF structures, Photoshop metadata, XMP, ICC/sRGB profiles, camera metadata, and original filename information.

## Repository structure

```text
HRR-Recovery/
├── src/
├── tests/
├── docs/
├── tools/
├── samples/
├── reports/
├── README.md
├── .gitignore
└── requirements.txt
```

## Disclaimer

This repository documents ongoing research and recovery tooling. Findings are experimental and should be independently validated against additional `.HRR` samples.
