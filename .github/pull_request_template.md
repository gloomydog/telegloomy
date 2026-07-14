## What this changes

<!-- One or two sentences. -->

## Checklist

- [ ] `make` and `make telegloomy-voice` build with no warnings
- [ ] `make test` passes (all 5 suites)
- [ ] If a parser or the wire format changed: `make fuzz N=500000` is clean
- [ ] If threading changed: `make tsan` is clean, cross-thread flags are `_Atomic`
- [ ] If crypto/key-schedule changed: explained against SECURITY.md's threat
      model below

## Notes for the reviewer

<!-- Anything that needs context: why this approach, what was tried and
     rejected, what's still rough. -->
