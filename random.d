import std.bigint;
import std.stdio : File, writeln;

/*
    Tools:
    get-cryptobytes {number of bytes}
*/

void main()
{
    immutable uint bufferSize = 1000;
    File random = File("/dev/random", "r");
    ubyte[bufferSize] bytes;
    // bytes = cast(ubyte[]) read("/dev/random", 100000u);
    writeln(random.rawRead(bytes));
}

// RSA Steps
/*
    Generating the RSA Keys:
        Select 2 prime numbers, P and Q.
            Select random 512-bit
        N = PQ
        Phi(N) = (P-1)(Q-1)
        Pick E, where E > 1 and E < Phi(N)
        Compute D, where (d * e) % Phi(N) = 1
        Public Key is (e, N) (e = exponent, N = modulus)
        Private Key is (d, N)
    Source: http://www.c-sharpcorner.com/UploadFile/75a48f/rsa-algorithm-with-C-Sharp2/

    https://crypto.stackexchange.com/questions/1970/how-are-primes-generated-for-rsa
    Generating the primes, P and Q:
        Fermat's Little Theorem:
            a^(p-1) = 1 (mod p)
            If the equality does not hold for a value of a,
            then p is composite.
            Choose a number a, where 1 < a < p-1.
    Source: https://crypto.stackexchange.com/questions/71/how-can-i-generate-large-prime-numbers-for-rsa#79
*/
/* NOTE:
    https://security.stackexchange.com/questions/90169/rsa-public-key-and-private-key-lengths
    "Traditionally, the "length" of a RSA key is the length, in bits, of the
    modulus. When a RSA key is said to have length "2048", it really means
    that the modulus value lies between 22047 and 22048. Since the public and
    private key of a given pair share the same modulus, they also have, by
    definition, the same "length"."
*/
public
size_t phi (size_t p, size_t q)
{
    return ((p-1)*(q-1));
}

///
public alias RSAPrivateKeyVersion = RivestShamirAdlemanPrivateKeyVersion;
/// INTEGER { two-prime(0), multi(1) }
public
enum RivestShamirAdlemanPrivateKeyVersion : ubyte
{
    twoPrime = 0u,
    multiPrime = 1u
}

///
public alias RSAPrivateKey = RivestShamirAdlemanPrivateKey;
/**
    From $(LINK https://tools.ietf.org/html/rfc3447, RFC3447):

    $(PRE
        RSAPrivateKey ::= SEQUENCE {
            version           Version,
            modulus           INTEGER,  -- n
            publicExponent    INTEGER,  -- e
            privateExponent   INTEGER,  -- d
            prime1            INTEGER,  -- p
            prime2            INTEGER,  -- q
            exponent1         INTEGER,  -- d mod (p-1)
            exponent2         INTEGER,  -- d mod (q-1)
            coefficient       INTEGER,  -- (inverse of q) mod p
            otherPrimeInfos   OtherPrimeInfos OPTIONAL }

        OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
    )
*/
public
class RivestShamirAdlemanPrivateKey
{
    public RSAPrivateKeyVersion vers;
    public BigInt modulus;
    public ulong publicExponent;
    public ulong privateExponent;
    public BigInt prime1;
    public BigInt prime2;
    public ulong exponent1;
    public ulong exponent2;
    public ulong coefficient;
    public RSAPrivateKeyOtherPrimeInfo[] otherPrimeInfo;

    // this(ushort bits = 2048u)
    // {
    //     this.vers = RSAPrivateKeyVersion.twoPrime;
    //     // How long must P and Q be to generate N of length (bits/8)?
    //     // Answer: https://stackoverflow.com/questions/12192116/rsa-bitlength-of-p-and-q#12195783
    //     // len(P),len(Q) = len(N) / 2;
    //     prime1 = cryptorandom()
    // }
}

///
public alias RSAPrivateKeyOtherPrimeInfo = RivestShamirAdlemanPrivateKeyOtherPrimeInfo;
/**
    OtherPrimeInfo ::= SEQUENCE {
        prime             INTEGER,  -- ri
        exponent          INTEGER,  -- di
        coefficient       INTEGER } -- ti
*/
public
struct RivestShamirAdlemanPrivateKeyOtherPrimeInfo
{
    public BigInt prime;
    public ulong exponent;
    public ulong coefficient;
}


/* NOTE:
    I am pretty sure the register supplied as an argument to RDRAND
    determines the width of the random number returned.
*/
/*
In order for the hardware design to meet its security goal
s, the random number generator continuously tests itself
and the random data it is generating. Runtime failures in the random number generator circuitry or statistically
anomalous data occurring by chance will be detected by the self test hardware and flag the resulting data as being bad.
In such extremely rare cases, the RDRAND instruction will return no data instead of bad data. Under heavy load, with multiple cores executing RDRAND in parallel, it is possible, though unlikely, for the demand
of random numbers by software processes/threads to 
exceed the rate at which the random number generator 
hardware can supply them. This will 
lead to the RDRAND instruction return
ing no data transitorily. The RDRAND 
instruction indicates the occurrence of this rare situation by clearing the CF flag.
The RDRAND instruction returns with the carry flag set (CF 
= 1) to indicate valid data is returned. It is recom-
mended that software using the RDRAND instruction to 
get random numbers retry for a limited number of itera-
tions while RDRAND returns CF=0 and complete when valid 
data is returned, indicated with CF=1. This will deal 
with transitory underflows. A retry limit should be employ
ed to prevent a hard failure in the RNG (expected to be 
extremely rare) leading to a busy loop in software.
The intrinsic primitive for RDRAND is 
defined to address software’s need for the common cases (CF = 1) and the 
rare situations (CF = 0). The intrinsic primitive returns a va
lue that reflects the value of the carry flag returned by 
the underlying RDRAND instruction. The example below illu
strates the recommended usage of an RDRAND intrinsic 
in a utility function, a loop to fetch a 64 bit random value with a retry count limit of 10. A C implementation might 
be written as follows:
*/