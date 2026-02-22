<?php

/**
 * PKCE (Proof Key for Code Exchange) Implementation for RFC 7636
 * 
 * This script provides functions to generate code_verifier and code_challenge
 * as specified in RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients
 * 
 * @author MiniMax Agent
 * @version 1.0
 */

class PKCE
{
    /**
     * Minimum length for code_verifier (RFC 7636 Section 4.1)
     */
    const MIN_CODE_VERIFIER_LENGTH = 43;

    /**
     * Maximum length for code_verifier (RFC 7636 Section 4.1)
     */
    const MAX_CODE_VERIFIER_LENGTH = 128;

    /**
     * Default length for code_verifier generation
     */
    const DEFAULT_CODE_VERIFIER_LENGTH = 64;

    /**
     * Characters allowed in code_verifier (RFC 7636 Section 4.1)
     * A-Z, a-z, 0-9, "-", ".", "_", "~"
     */
    const CODE_VERIFIER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

    /**
     * Generate a cryptographically secure code_verifier
     * 
     * @param int $length Length of the code_verifier (43-128)
     * @return string The generated code_verifier
     * @throws InvalidArgumentException If length is out of bounds
     */
    public static function generateCodeVerifier(int $length = self::DEFAULT_CODE_VERIFIER_LENGTH): string
    {
        if ($length < self::MIN_CODE_VERIFIER_LENGTH || $length > self::MAX_CODE_VERIFIER_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Code verifier length must be between %d and %d characters',
                self::MIN_CODE_VERIFIER_LENGTH,
                self::MAX_CODE_VERIFIER_LENGTH
            ));
        }

        $charactersLength = strlen(self::CODE_VERIFIER_CHARS);
        $codeVerifier = '';

        // Use random_bytes for cryptographically secure random generation
        $randomBytes = random_bytes($length);
        
        for ($i = 0; $i < $length; $i++) {
            $codeVerifier .= self::CODE_VERIFIER_CHARS[ord($randomBytes[$i]) % $charactersLength];
        }

        return $codeVerifier;
    }

    /**
     * Generate code_challenge from code_verifier using S256 method
     * 
     * RFC 7636 Section 4.2:
     * code_challenge = BASE64URL(SHA256(code_verifier))
     * 
     * @param string $codeVerifier The code_verifier string
     * @return string The generated code_challenge
     * @throws InvalidArgumentException If code_verifier is invalid
     */
    public static function generateCodeChallenge(string $codeVerifier): string
    {
        return self::generateS256CodeChallenge($codeVerifier);
    }

    /**
     * Generate code_challenge using S256 method (SHA256 + Base64URL)
     * 
     * @param string $codeVerifier The code_verifier string
     * @return string The generated code_challenge
     */
    public static function generateS256CodeChallenge(string $codeVerifier): string
    {
        // Validate code_verifier length
        $length = strlen($codeVerifier);
        if ($length < self::MIN_CODE_VERIFIER_LENGTH || $length > self::MAX_CODE_VERIFIER_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'Code verifier must be between %d and %d characters',
                self::MIN_CODE_VERIFIER_LENGTH,
                self::MAX_CODE_VERIFIER_LENGTH
            ));
        }

        // Calculate SHA256 hash
        $hash = hash('sha256', $codeVerifier, true);

        // Encode with Base64URL (URL-safe base64 without padding)
        return self::base64UrlEncode($hash);
    }

    /**
     * Generate code_challenge using plain method
     * 
     * RFC 7636 Section 4.2:
     * If the method is "plain", the code_challenge IS the code_verifier
     * 
     * @param string $codeVerifier The code_verifier string
     * @return string The code_challenge (same as code_verifier)
     */
    public static function generatePlainCodeChallenge(string $codeVerifier): string
    {
        return $codeVerifier;
    }

    /**
     * Base64URL encoding (RFC 4648 Section 5)
     * 
     * Base64URL is Base64 encoding with:
     * - '+' replaced with '-'
     * - '/' replaced with '_'
     * - padding ('=') removed
     * 
     * @param string $data The data to encode
     * @return string The Base64URL encoded string
     */
    public static function base64UrlEncode(string $data): string
    {
        // Standard Base64 encoding
        $base64 = base64_encode($data);

        // Convert to Base64URL
        $base64Url = strtr($base64, '+/', '-_');

        // Remove padding
        return rtrim($base64Url, '=');
    }

    /**
     * Base64URL decoding
     * 
     * @param string $data The Base64URL encoded string
     * @return string The decoded data
     */
    public static function base64UrlDecode(string $data): string
    {
        // Add padding if necessary
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }

        // Convert from Base64URL to standard Base64
        $base64 = strtr($data, '-_', '+/');

        return base64_decode($base64);
    }

    /**
     * Verify that a code_verifier matches a code_challenge
     * 
     * @param string $codeVerifier The code_verifier to verify
     * @param string $codeChallenge The code_challenge to verify against
     * @param string $method The method used ('plain' or 'S256')
     * @return bool True if verification succeeds
     */
    public static function verifyCodeChallenge(
        string $codeVerifier, 
        string $codeChallenge, 
        string $method = 'S256'
    ): bool {
        if ($method === 'plain') {
            return $codeVerifier === $codeChallenge;
        }

        // Default to S256
        $calculatedChallenge = self::generateS256CodeChallenge($codeVerifier);
        return hash_equals($calculatedChallenge, $codeChallenge);
    }

    /**
     * Generate PKCE parameters for OAuth authorization request
     * 
     * @param string $method The code challenge method ('plain' or 'S256')
     * @param int $verifierLength Length of the code_verifier
     * @return array Array containing code_verifier and code_challenge
     */
    public static function generatePkceParameters(
        string $method = 'S256', 
        int $verifierLength = self::DEFAULT_CODE_VERIFIER_LENGTH
    ): array {
        $codeVerifier = self::generateCodeVerifier($verifierLength);
        
        if ($method === 'plain') {
            $codeChallenge = self::generatePlainCodeChallenge($codeVerifier);
        } else {
            $codeChallenge = self::generateS256CodeChallenge($codeVerifier);
        }

        return [
            'code_verifier' => $codeVerifier,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => $method
        ];
    }
}

/**
 * Helper function for simple usage
 * 
 * @param string $method Code challenge method ('plain' or 'S256')
 * @return array PKCE parameters
 */
function generatePkce(string $method = 'S256'): array
{
    return PKCE::generatePkceParameters($method);
}

// Example usage and demonstration
if (php_sapi_name() === 'cli' || !isset($_SERVER['HTTP_HOST'])) {
    echo "=== PKCE (RFC 7636) Implementation Demo ===\n\n";
    
    // Example 1: Generate PKCE with S256 method
    echo "1. Generating PKCE with S256 method:\n";
    $pkce = PKCE::generatePkceParameters('S256');
    echo "   Code Verifier: " . $pkce['code_verifier'] . "\n";
    echo "   Code Challenge: " . $pkce['code_challenge'] . "\n";
    echo "   Method: " . $pkce['code_challenge_method'] . "\n\n";
    
    // Example 2: Generate PKCE with plain method
    echo "2. Generating PKCE with plain method:\n";
    $pkcePlain = PKCE::generatePkceParameters('plain');
    echo "   Code Verifier: " . $pkcePlain['code_verifier'] . "\n";
    echo "   Code Challenge: " . $pkcePlain['code_challenge'] . "\n";
    echo "   Method: " . $pkcePlain['code_challenge_method'] . "\n\n";
    
    // Example 3: Verify code challenge
    echo "3. Verifying code challenge:\n";
    $isValid = PKCE::verifyCodeChallenge(
        $pkce['code_verifier'], 
        $pkce['code_challenge'], 
        'S256'
    );
    echo "   Verification result: " . ($isValid ? "VALID" : "INVALID") . "\n\n";
    
    // Example 4: Custom verifier length
    echo "4. Generating with custom length (100 chars):\n";
    $pkceCustom = PKCE::generatePkceParameters('S256', 100);
    echo "   Code Verifier length: " . strlen($pkceCustom['code_verifier']) . "\n";
    echo "   Code Challenge: " . $pkceCustom['code_challenge'] . "\n\n";
    
    // Example 5: Base64URL encoding demo
    echo "5. Base64URL encoding demo:\n";
    $testData = "Hello, World!";
    $encoded = PKCE::base64UrlEncode($testData);
    $decoded = PKCE::base64UrlDecode($encoded);
    echo "   Original: $testData\n";
    echo "   Base64URL encoded: $encoded\n";
    echo "   Decoded: $decoded\n";
}
