using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthorizationServer;

// RFC 7636 (PKCE) helpers shared by /authorize (which stores the challenge) and /token (which
// checks the verifier against it). Only S256 is supported — "plain" sends the verifier itself
// through the front channel, which defeats the point, so this server refuses it.
internal static partial class Pkce
{
    public const string S256 = "S256";

    // A S256 challenge is BASE64URL(SHA256(verifier)) without padding — always exactly 43 chars.
    public static bool IsValidChallenge(string challenge) => ChallengeRegex().IsMatch(challenge);

    public static bool VerifierMatches(string verifier, string challenge)
    {
        // RFC 7636 §4.1: 43–128 chars from the unreserved set. A malformed verifier can't match.
        if (!VerifierRegex().IsMatch(verifier))
        {
            return false;
        }

        var computed = Encoding.ASCII.GetBytes(ComputeS256Challenge(verifier));
        return CryptographicOperations.FixedTimeEquals(computed, Encoding.ASCII.GetBytes(challenge));
    }

    private static string ComputeS256Challenge(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$")]
    private static partial Regex ChallengeRegex();

    [GeneratedRegex("^[A-Za-z0-9._~-]{43,128}$")]
    private static partial Regex VerifierRegex();
}
