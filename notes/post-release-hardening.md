# Post-release hardening — reliable.cs

The 2026-08-07 review recorded no surviving findings at that time. The port
has since added construction-time checks for sequence-buffer sizes and
smoothing factors; `Endpoint` accepts finite smoothing factors in [0,1].

## Remaining large-size arithmetic review

Fragment reassembly computes `packetBufferSize` as an `int` from the fragment
count and configured fragment size. The constructor checks the product using
`long`, but its bound allows the product up to `int.MaxValue` minus the maximum
packet-header size. The allocation expression also adds eight bytes. Review
that final addition with checked or wider arithmetic and a focused extreme
configuration test before claiming every accepted configuration is safe from
integer overflow. This is a configuration boundary, not a wire-input claim.

## Ongoing gates

The CI workflow runs the C wire and behavior compatibility gate against the
v1.4.5 C reference, plus the C# test matrix. Consult the run for the commit
being evaluated; an older green run does not establish the current head.
