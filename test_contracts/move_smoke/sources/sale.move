// Dependency-free Aptos Move module used by the sandbox smoke test.
// The package intentionally declares no framework dependencies so the
// smoke stays fast; production Move repos ship their own Move.toml with
// the framework deps they need and that manifest is preserved verbatim.
module move_smoke::sale {
    /// Quote the price of `amount` units at `price_bps` (basis points per
    /// unit). Integer division truncates, so fractional results round
    /// DOWN — a dust-loss the PoC exploits.
    public fun quote(amount: u64, price_bps: u64, units: u64): u64 {
        if (amount == 0u64 || units == 0u64) {
            abort 1
        };
        (amount * price_bps) / units
    }

    #[test]
    fun test_smoke_quote_works() {
        assert!(quote(1000, 10000, 1000) == 10000, 1);
    }
}
