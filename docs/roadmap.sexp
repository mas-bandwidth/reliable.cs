; The reliable.cs roadmap: the data ROADMAP.md is generated from.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment):
; data, never evaluated. Edit this file, then regenerate ROADMAP.md with nova-sprint's
; generator, from a nova-sprint checkout:
;   go build -o /tmp/roadmap ./tools/roadmap && (cd <this repo> && /tmp/roadmap --file docs/roadmap.sexp --out ROADMAP.md)
; Never edit ROADMAP.md by hand. Created 2026-10-14 when the open sprint cards of this
; repository were moved out of the stopped sprint; those five cards landed with the
; reliable-cs-port reconcile (2026-11-10). What remains is pinning the bounds that are
; ahead of the C release once the C library releases them.
(roadmap "v1"
 :title "reliable.cs roadmap"
 :text "Planned work for reliable.cs. The open sprint cards moved out of the stopped sprint on 2026-10-14 have landed. Landed work is in git."

 :groups
 (
  (group "interop" :title "Interop gate"
   :text "The head-to-head gate against the pinned C release (scripts/interop.sh, the c-interop CI job).")
 )

 :items
 (
  (item "interop-pins-the-bounds-ahead-of-c" :group "interop" :area "reliable.cs"
   :title "Differential pins for the bounds ahead of the C release"
   :text "The power-of-two and 16384 sequence-buffer bound, FragmentReassemblyByteBudget, and counting an empty receive invalid are ahead of the pinned C release v1.4.5, so the interop gate feeds only inputs both implementations agree on and the unit tests pin the rest. When a C release carries these bounds, bump the pin in .github/workflows/ci.yml and README.md, add a byte_budget mode to both compat harnesses, feed the zero-length receive in malformed and receive_bounds, and widen the config_refusal value list to every power-of-two boundary."
   :why "Waits on a C release of mas-bandwidth/reliable that carries the three bounds."
   :date "2026-11-10"
   :origin "the reliable-cs-port reconcile onto main")
 ))
