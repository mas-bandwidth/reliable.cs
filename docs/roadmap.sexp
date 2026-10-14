; The reliable.cs roadmap: the data ROADMAP.md is generated from.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment):
; data, never evaluated. Edit this file, then regenerate ROADMAP.md with nova-sprint's
; generator, from a nova-sprint checkout:
;   go build -o /tmp/roadmap ./tools/roadmap && (cd <this repo> && /tmp/roadmap --file docs/roadmap.sexp --out ROADMAP.md)
; Never edit ROADMAP.md by hand. Created 2026-10-14 when the open sprint cards of this
; repository were moved out of the stopped sprint.
(roadmap "v1"
 :title "reliable.cs roadmap"
 :text "Planned work for reliable.cs. Each item below was an open sprint card, moved out of the stopped sprint on 2026-10-14; it names its card, its tier, its base branch and any pushed work to resume from. Landed work is in git."

 :groups
 (
  (group "export-reliable-cs-port" :title "Moved out of the sprint on 2026-10-14: reliable-cs-port"
   :text "The open cards of sprint stream reliable-cs-port, moved out of the stopped sprint on 2026-10-14, one item per card. Landed cards of the stream are in git and are not listed. Each item names its card, its tier, its base branch and any pushed work to resume from.")
 )

 :items
 (
  (item "cs-reliable-an-empty-packet-is-counted-not-thrown" :group "export-reliable-cs-port" :area "reliable.cs"
   :title "Cs reliable an empty packet is counted not thrown"
   :text "Replace the throw with a debug log, `NumPacketsInvalid++; return;`; update the XML doc at :1038-1039 and README.md:138; flip the assertion at tests/Hostile.cs:346 to the counted refusal."
   :exists "Work was pushed: head 3b0be5fb6eb3951b49f33d1412e67fa3567f7951 on branch sprint/cs-reliable-an-empty-packet-is-counted-not-thrown.w5.g1.e20 (attempt 5). Resume from it; do not start over."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-reliable-an-empty-packet-is-counted-not-thrown (stream reliable-cs-port, column review, tier pro, base sprint/reliable-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-reliable-an-empty-packet-is-counted-not-thrown" :sprint-stream "reliable-cs-port" :sprint-column "review" :tier "pro" :sprint-base "sprint/reliable-cs-port" :needs "cs-reliable-a-fragment-does-not-advance-the-received-window" :pushed-head "3b0be5fb6eb3951b49f33d1412e67fa3567f7951" :pushed-branch "sprint/cs-reliable-an-empty-packet-is-counted-not-thrown.w5.g1.e20"))
  (item "cs-reliable-config-refuses-what-c-refuses" :group "export-reliable-cs-port" :area "reliable.cs"
   :title "Cs reliable config refuses what c refuses"
   :text "In the constructor: require `n > 0 && n <= 16384 && (n & (n-1)) == 0` for the three fields (ArgumentException, as the neighbouring checks), leave AckBufferSize and RttHistorySize; add the five missing C bounds with C's order and the long arithmetic for header + max + 9 + 5 > int.MaxValue; make :1049 use long; put every check before the allocations at :887-901 (a huge MaxPacketSize otherwise OOMs at new byte[...] first)."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-reliable-config-refuses-what-c-refuses (stream reliable-cs-port, column waiting, tier pro, base sprint/reliable-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-reliable-config-refuses-what-c-refuses" :sprint-stream "reliable-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/reliable-cs-port" :needs "cs-reliable-an-empty-packet-is-counted-not-thrown" :pushed-head "" :pushed-branch ""))
  (item "cs-reliable-hardening-from-the-c-1-4-releases-is-carried" :group "export-reliable-cs-port" :area "reliable.cs"
   :title "Cs reliable hardening from the c 1 4 releases is carried"
   :text "(a) Zero the same fields in Reset and fill the rtt history with -1; update README.md and notes/port-map.md."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-reliable-hardening-from-the-c-1-4-releases-is-carried (stream reliable-cs-port, column waiting, tier pro, base sprint/reliable-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-reliable-hardening-from-the-c-1-4-releases-is-carried" :sprint-stream "reliable-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/reliable-cs-port" :needs "cs-reliable-config-refuses-what-c-refuses" :pushed-head "" :pushed-branch ""))
  (item "cs-reliable-unfinished-reassembly-has-a-byte-budget" :group "export-reliable-cs-port" :area "reliable.cs"
   :title "Cs reliable unfinished reassembly has a byte budget"
   :text "Endpoint.ReceivePacket, fragment branch, src/Reliable.cs:1210 and :1215: `int packetBufferSize = Wire.MaxPacketHeaderBytes + numFragments * _fragmentSize;` and `newReassembly.PacketData = ArrayPool<byte>.Shared.Rent(packetBufferSize);`; there is no budget and no age eviction and Update never touches reassembly."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-reliable-unfinished-reassembly-has-a-byte-budget (stream reliable-cs-port, column waiting, tier pro, base sprint/reliable-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-reliable-unfinished-reassembly-has-a-byte-budget" :sprint-stream "reliable-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/reliable-cs-port" :needs "cs-reliable-hardening-from-the-c-1-4-releases-is-carried,relfix-unfinished-reassembly-has-a-byte-budget" :pushed-head "" :pushed-branch ""))
  (item "cs-reliable-interop-gate-and-spec-follow-c" :group "export-reliable-cs-port" :area "reliable.cs"
   :title "Cs reliable interop gate and spec follow c"
   :text "Cs reliable interop gate and spec follow c. Done when: STANDARD.md equals the upstream STANDARD.md of the C release named in the card byte for byte;"
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card cs-reliable-interop-gate-and-spec-follow-c (stream reliable-cs-port, column waiting, tier pro, base sprint/reliable-cs-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "cs-reliable-interop-gate-and-spec-follow-c" :sprint-stream "reliable-cs-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/reliable-cs-port" :needs "cs-reliable-unfinished-reassembly-has-a-byte-budget" :pushed-head "" :pushed-branch ""))
))
