; reliable.cs roadmap: the data ROADMAP.md is generated from (nova-roadmap, a nova-tools release binary;
; make roadmap renders, make roadmap-check fails on drift). Read as data, never evaluated.
; A cell is done only when its task is :done with :evidence, a test or a commit;
; :tested-revision is the main commit whose CI passed with that evidence.
(:schema 1
 :root "goal"
 :page (:title "reliable.cs roadmap"
        :roadmaps ("acks" "fragments" "stats" "robustness" "compat"))
 :nodes
 ((:id "goal" :type :work-set :children ("acks" "fragments" "stats" "robustness" "compat"))
  (:id "acks" :type :roadmap :title "Acknowledgement"
   :text "Sequence numbers, packet headers and acks: which of your packets the other side received."
   :rows (("header" "packet header with sequence, ack and ack bits")
          ("sequence-buffer" "sequence buffers, including the 16-bit wrap")
          ("acks" "acks for every packet received")
          ("acks-loss" "acks under packet loss")
          ("duplicates" "duplicate packets ignored")
          ("stale" "stale packets dropped")
          ("ack-overflow" "ack buffer overflow handled")
          ("reject-redelivery" "a packet the process callback rejects is not acked"))
   :columns (("done" "done"))
   :cells (("header" "done" "acks/header")
           ("sequence-buffer" "done" "acks/sequence-buffer")
           ("acks" "done" "acks/acks")
           ("acks-loss" "done" "acks/acks-loss")
           ("duplicates" "done" "acks/duplicates")
           ("stale" "done" "acks/stale")
           ("ack-overflow" "done" "acks/ack-overflow")
           ("reject-redelivery" "done" "acks/reject-redelivery")))
  (:id "acks/header" :type :task :title "packet header with sequence, ack and ack bits" :state :done :evidence ("tests/Tests.cs: TestPacketHeader" "tests/Tests.cs: TestGenerateAckBits") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/sequence-buffer" :type :task :title "sequence buffers, including the 16-bit wrap" :state :done :evidence ("tests/Tests.cs: TestSequenceBuffer" "tests/Tests.cs: TestSequenceBufferRollover") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/acks" :type :task :title "acks for every packet received" :state :done :evidence ("tests/Tests.cs: TestAcks") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/acks-loss" :type :task :title "acks under packet loss" :state :done :evidence ("tests/Tests.cs: TestAcksPacketLoss") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/duplicates" :type :task :title "duplicate packets ignored" :state :done :evidence ("tests/Tests.cs: TestDuplicatePackets") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/stale" :type :task :title "stale packets dropped" :state :done :evidence ("tests/Tests.cs: TestStalePackets") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/ack-overflow" :type :task :title "ack buffer overflow handled" :state :done :evidence ("tests/Tests.cs: TestAckBufferOverflow") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "acks/reject-redelivery" :type :task :title "a packet the process callback rejects is not acked" :state :done :evidence ("tests/Hostile.cs: TestProcessRejectRedelivery") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "fragments" :type :roadmap :title "Fragmentation"
   :text "Packets larger than a fragment are split on send and reassembled on receive."
   :rows (("packets" "send and receive packets")
          ("large" "large packets fragmented and reassembled")
          ("cleanup" "abandoned reassemblies cleaned up")
          ("reassembly-budget" "unfinished reassembly has a byte budget"))
   :columns (("done" "done"))
   :cells (("packets" "done" "fragments/packets")
           ("large" "done" "fragments/large")
           ("cleanup" "done" "fragments/cleanup")
           ("reassembly-budget" "done" "fragments/reassembly-budget")))
  (:id "fragments/packets" :type :task :title "send and receive packets" :state :done :evidence ("tests/Tests.cs: TestPackets") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "fragments/large" :type :task :title "large packets fragmented and reassembled" :state :done :evidence ("tests/Tests.cs: TestLargePackets" "tests/Tests.cs: TestGoldenFragments") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "fragments/cleanup" :type :task :title "abandoned reassemblies cleaned up" :state :done :evidence ("tests/Tests.cs: TestFragmentCleanup") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "fragments/reassembly-budget" :type :task :title "unfinished reassembly has a byte budget" :state :todo
   :note "Endpoint.ReceivePacket rents each new reassembly buffer from ArrayPool with no budget and no age eviction; Update never touches reassembly (src/Reliable.cs:1210, :1215). Carry the C library budget."
   :sprint-card "cs-reliable-unfinished-reassembly-has-a-byte-budget"
   :sprint-needs "relfix-unfinished-reassembly-has-a-byte-budget")
  (:id "stats" :type :roadmap :title "Network stats"
   :text "Round-trip time, jitter, packet loss and bandwidth estimates, and endpoint reset."
   :rows (("rtt" "rtt with min, max and average")
          ("jitter-loss-bandwidth" "jitter, packet loss and bandwidth, bit-identical to C")
          ("reset" "endpoint reset")
          ("reset-hardening" "reset hardening from the C 1.4 releases"))
   :columns (("done" "done"))
   :cells (("rtt" "done" "stats/rtt")
           ("jitter-loss-bandwidth" "done" "stats/jitter-loss-bandwidth")
           ("reset" "done" "stats/reset")
           ("reset-hardening" "done" "stats/reset-hardening")))
  (:id "stats/rtt" :type :task :title "rtt with min, max and average" :state :done :evidence ("tests/Tests.cs: TestRtt" ".github/workflows/ci.yml: c-interop job (scripts/interop.sh, bit-exact vs reliable.c v1.4.0 on ubuntu-latest and macos-latest), green on afcefe3") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "stats/jitter-loss-bandwidth" :type :task :title "jitter, packet loss and bandwidth, bit-identical to C" :state :done :evidence (".github/workflows/ci.yml: c-interop job (scripts/interop.sh, bit-exact vs reliable.c v1.4.0 on ubuntu-latest and macos-latest), green on afcefe3") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "stats/reset" :type :task :title "endpoint reset" :state :done :evidence ("tests/Tests.cs: TestEndpointReset") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "stats/reset-hardening" :type :task :title "reset hardening from the C 1.4 releases" :state :todo
   :note "Reset should zero the same fields as the C 1.4 releases and fill the rtt history with -1; update README.md and notes/port-map.md."
   :sprint-card "cs-reliable-hardening-from-the-c-1-4-releases-is-carried")
  (:id "robustness" :type :roadmap :title "Robustness"
   :text "Hostile wire data never throws: malformed, stale, duplicate and truncated packets are counted and dropped; no allocation at steady state."
   :rows (("truncated" "truncated headers refused and counted")
          ("hostile-fragments" "hostile fragments refused and counted")
          ("fuzz" "parser fuzz and the C fuzz_target.c script harness")
          ("soak" "seeded adversarial soak")
          ("zero-alloc" "zero allocation at steady state")
          ("config-validation" "invalid configuration refused at construction")
          ("config-like-c" "configuration refuses exactly what C refuses")
          ("empty-packet" "an empty received packet is counted, not thrown"))
   :columns (("done" "done"))
   :cells (("truncated" "done" "robustness/truncated")
           ("hostile-fragments" "done" "robustness/hostile-fragments")
           ("fuzz" "done" "robustness/fuzz")
           ("soak" "done" "robustness/soak")
           ("zero-alloc" "done" "robustness/zero-alloc")
           ("config-validation" "done" "robustness/config-validation")
           ("config-like-c" "done" "robustness/config-like-c")
           ("empty-packet" "done" "robustness/empty-packet")))
  (:id "robustness/truncated" :type :task :title "truncated headers refused and counted" :state :done :evidence ("tests/Hostile.cs: TestHostileTruncatedHeaders") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/hostile-fragments" :type :task :title "hostile fragments refused and counted" :state :done :evidence ("tests/Hostile.cs: TestHostileFragments") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/fuzz" :type :task :title "parser fuzz and the C fuzz_target.c script harness" :state :done :evidence ("tests/Hostile.cs: TestHostileParserFuzz" "tests/Hostile.cs: TestFuzzScript") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/soak" :type :task :title "seeded adversarial soak" :state :done :evidence ("tests/Soak.cs: TestSoak") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/zero-alloc" :type :task :title "zero allocation at steady state" :state :done :evidence ("tests/Hostile.cs: TestZeroAllocation") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/config-validation" :type :task :title "invalid configuration refused at construction" :state :done :evidence ("tests/Hostile.cs: TestConfigValidation") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "robustness/config-like-c" :type :task :title "configuration refuses exactly what C refuses" :state :todo
   :note "Require power-of-two sizes up to 16384 for the three buffer sizes, add the five missing C bounds in C order with long arithmetic, and check everything before allocating."
   :sprint-card "cs-reliable-config-refuses-what-c-refuses")
  (:id "robustness/empty-packet" :type :task :title "an empty received packet is counted, not thrown" :state :todo
   :note "ReceivePacket(empty) still throws ArgumentException (src/Reliable.cs:1044; asserted in tests/Hostile.cs TestConfigValidation). Count it in NumPacketsInvalid and return."
   :sprint-card "cs-reliable-an-empty-packet-is-counted-not-thrown"
   :pushed-head "3b0be5fb6eb3951b49f33d1412e67fa3567f7951"
   :pushed-branch "sprint/cs-reliable-an-empty-packet-is-counted-not-thrown.w5.g1.e20")
  (:id "compat" :type :roadmap :title "Compatibility"
   :text "Byte-identical wire format and observable behaviour with the C reliable library, on the platforms CI runs."
   :rows (("golden" "golden wire vectors from the C library")
          ("interop" "head-to-head interop with reliable.c: bytes, deliveries, acks, counters, stats")
          ("strict-float" "strict float rounding pinned on x86-64 and arm64")
          ("standard" "STANDARD.md vendored verbatim, drift checked")
          ("follow-c" "interop gate and spec follow the current C release")
          ("dotnet" ".NET 8 (LTS) and .NET 10")
          ("platforms" "Linux and macOS"))
   :columns (("done" "done"))
   :cells (("golden" "done" "compat/golden")
           ("interop" "done" "compat/interop")
           ("strict-float" "done" "compat/strict-float")
           ("standard" "done" "compat/standard")
           ("follow-c" "done" "compat/follow-c")
           ("dotnet" "done" "compat/dotnet")
           ("platforms" "done" "compat/platforms")))
  (:id "compat/golden" :type :task :title "golden wire vectors from the C library" :state :done :evidence ("tests/Tests.cs: TestGoldenPacketHeaders" "tests/Tests.cs: TestGoldenFragments") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "compat/interop" :type :task :title "head-to-head interop with reliable.c: bytes, deliveries, acks, counters, stats" :state :done :evidence (".github/workflows/ci.yml: c-interop job (scripts/interop.sh, bit-exact vs reliable.c v1.4.0 on ubuntu-latest and macos-latest), green on afcefe3") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "compat/strict-float" :type :task :title "strict float rounding pinned on x86-64 and arm64" :state :done :evidence ("tests/Tests.cs: FloatMultiplyAddRoundsTwice" "commit 038ee97 (c-interop: run on arm64 where contraction bites; pin C# strict rounding)") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "compat/standard" :type :task :title "STANDARD.md vendored verbatim, drift checked" :state :done :evidence (".github/workflows/ci.yml: spec-sync job (STANDARD.md matches upstream)" "commit 913317a (STANDARD.md: re-vendor verbatim from reliable main)") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "compat/follow-c" :type :task :title "interop gate and spec follow the current C release" :state :todo
   :note "The interop gate and golden pins are at reliable v1.4.0; the latest C release is v1.4.5. Move the pinned tag and STANDARD.md to the named C release, byte for byte."
   :sprint-card "cs-reliable-interop-gate-and-spec-follow-c")
  (:id "compat/dotnet" :type :task :title ".NET 8 (LTS) and .NET 10" :state :done :evidence (".github/workflows/ci.yml: test job, Tests (net10.0) and Tests (net8.0, the LTS leg), green on afcefe3") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")
  (:id "compat/platforms" :type :task :title "Linux and macOS" :state :done :evidence (".github/workflows/ci.yml: test job, matrix ubuntu-latest, macos-latest, green on afcefe3") :tested-revision "afcefe3d61528bab4c0cc1332f8637eae30cd851")))
