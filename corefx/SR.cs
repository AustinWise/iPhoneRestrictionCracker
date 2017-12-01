namespace System.Security.Cryptography
{
    class SR
    {
        public const string Cryptography_PasswordDerivedBytes_FewBytesSalt = "Salt is not enough bytes.";
        public const string ArgumentOutOfRange_NeedPosNum = "Positive number required.";
        public const string Cryptography_HashAlgorithmNameNullOrEmpty = "The hash algorithm name cannot be null or empty.";
        public const string Cryptography_UnknownHashAlgorithm = "'{0}' is not a known hash algorithm.";

        public static string Format(string resourceFormat, object p1) => string.Format(resourceFormat, p1);
    }
}
