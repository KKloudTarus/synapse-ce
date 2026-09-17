using System;

static class Program
{
    static void Main()
    {
        ControlPositive();
        OpaqueDispatch(Environment.GetEnvironmentVariable("REACHBENCH_CONTROL"));
    }

    static void ControlPositive() { }
    static void ControlUnreachable() { }

    static void OpaqueDispatch(string? name)
    {
        if (name == "opaque") ControlOpaque();
    }

    static void ControlOpaque() { }
    // Tier-two metadata capability is intentionally unavailable in this fixture.
    static void ControlNoCoverage() { }
}
