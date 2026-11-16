#!/usr/bin/env python3
"""
Build-time codegen: randomizes the field order and padding of `sessionSlot`
so every image build has a distinct in-memory struct layout. Runs inside the
Docker builder stage, before `go build`. Only the compiled binary is
served to solvers.
"""
import os
import random
import sys

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "daemon", "layout_template.go.tmpl")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "daemon", "layout_generated.go")

REAL_FIELDS = [
    ("Key", "[32]byte"),
    ("Nonce", "[16]byte"),
    ("EpochID", "uint64"),
    ("Created", "int64"),
]


def main():
    seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)

    fields = list(REAL_FIELDS)
    rng.shuffle(fields)

    num_pad = rng.randint(3, 6)
    pad_fields = []
    for i in range(num_pad):
        size = rng.randint(1, 96)
        pad_fields.append((f"Pad{i}", f"[{size}]byte"))

    # interleave real fields and padding fields in a random order
    all_fields = fields + pad_fields
    rng.shuffle(all_fields)

    lines = "\n".join(f"\t{name} {gotype}" for name, gotype in all_fields)

    with open(TEMPLATE_PATH, "r") as f:
        template = f.read()

    rendered = template.replace("__FIELDS__", lines)

    with open(OUTPUT_PATH, "w") as f:
        f.write(rendered)

    sys.stderr.write(f"[gen_layout] seed={seed:016x} num_pad={num_pad} fields={[n for n,_ in all_fields]}\n")


if __name__ == "__main__":
    main()
