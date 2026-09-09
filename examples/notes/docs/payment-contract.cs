using Cryptide.Models;
using Cryptide.Tools;
using Ork.Forseti.Sdk;
using Ork.Shared.Models.Contracts;

/// <summary>
/// Signs a payment instruction, and refuses one over the limit.
///
/// This is the thing encryption cannot do. A custom request always has its data validated before
/// the cohort will sign, so the contract sees the bytes first and can decline. The refusal is not
/// advice the application may ignore: without the network's signature there is no instruction, only
/// a string that failed to become one.
///
/// The payload is plain text, "amount=250;to=alice". Read directly rather than deserialised, since a
/// contract that cannot allocate is easier to reason about than one that can.
///
/// No fields, no statics, and no array literals: each compiles to a static constructor, which the
/// Forseti VM refuses to load.
/// </summary>
public class Contract : IAccessPolicy
{
    public PolicyDecision ValidateData(DataContext context)
    {
        byte[] data = context.Data;
        if (data == null || data.Length == 0)
        {
            return PolicyDecision.Deny("Nothing to sign");
        }

        int limit;
        try
        {
            limit = context.Policy.Params.GetParameter<int>("limit");
        }
        catch
        {
            // A policy with no limit cannot express what it will sign, so it signs nothing.
            return PolicyDecision.Deny("Policy does not name a limit");
        }

        // Find "amount=" and read the digits after it.
        int at = -1;
        for (int i = 0; i + 6 < data.Length; i++)
        {
            if (data[i] != 0x61) continue;      // a
            if (data[i + 1] != 0x6D) continue;  // m
            if (data[i + 2] != 0x6F) continue;  // o
            if (data[i + 3] != 0x75) continue;  // u
            if (data[i + 4] != 0x6E) continue;  // n
            if (data[i + 5] != 0x74) continue;  // t
            if (data[i + 6] != 0x3D) continue;  // =
            at = i + 7;
            break;
        }
        if (at < 0)
        {
            return PolicyDecision.Deny("This policy signs payment instructions, and saw none");
        }

        int amount = 0;
        int digits = 0;
        for (int i = at; i < data.Length; i++)
        {
            byte c = data[i];
            if (c < 0x30 || c > 0x39) break;
            // Refuse rather than wrap. A number this long is not a payment, it is an attempt.
            if (digits > 9) return PolicyDecision.Deny("The amount is not a number this will sign");
            amount = (amount * 10) + (c - 0x30);
            digits++;
        }
        if (digits == 0)
        {
            return PolicyDecision.Deny("The amount is missing");
        }

        if (amount > limit)
        {
            return PolicyDecision.Deny("Over the limit this policy will sign");
        }

        return PolicyDecision.Allow();
    }
}
