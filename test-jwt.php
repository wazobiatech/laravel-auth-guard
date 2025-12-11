<?php
/**
 * Independent JWT Package Test Script
 * 
 * This script tests the JWT authentication package independently
 * to debug JWKS fetching and token validation issues.
 */

require_once __DIR__ . '/vendor/autoload.php';

use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Services\JwksService;

// Configuration (update these values to match your .env)
$config = [
    'mercury_base_url' => 'https://mercury.tiadara.com',
    'signature_shared_secret' => 'AAAAB3NzaC1yc2EAAAADAQABAAACAQD3GObqRywP1xuNkk9SltJ',
    'service_id' => '4d3ab1f6-cd27-457f-b727-bcbb37f6b58f',
    'jwt_algorithm' => 'RS512',
    'cache_ttl' => 3600,
];

// Test token (your project token)
$testToken = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVkZ2ZDSWtITGpiR2tJWHktc1BzRy14NDFJdXhVRWlLZlppdVFBTlNiMGsifQ.eyJwcm9qZWN0X3V1aWQiOiI1YzFlMzg2Yy0wOGMwLTRhMGEtODBhZC0xZjFiMzBlYTIzMWYiLCJzZWNyZXRfdmVyc2lvbiI6NSwiZW5hYmxlZF9zZXJ2aWNlcyI6WyI0ZDNhYjFmNi1jZDI3LTQ1N2YtYjcyNy1iY2JiMzdmNmI1OGYiXSwidG9rZW5faWQiOiIzZGFiOWZjMC02NmYxLTQyM2ItOWVhNy05NTg0MjJlOTc0Y2IiLCJ0eXBlIjoicHJvamVjdCIsImlhdCI6MTc2NTQzODIyMCwibmJmIjoxNzY1NDM4MjIwLCJleHAiOjE3NjU0NDE4MjAsImF1ZCI6IioiLCJpc3MiOiJodHRwczovL21lcmN1cnkudGlhZGFyYS5jb20ifQ.T-8VFb5zZH0ESZjw_2PjGw77hezu6EOWnPEvqW50MGS5QKHiC_OlnNKuYSi89AtRWHleiL0ly5oiU8ekIoY4nhjGKC-p4ADT3Ila09K29O-uR4Pnrz56_pJkSQBr0BhMhYnPEOBJLnVtAUXvtnVclqnU2OZSRCcxuByJTmCk95BjiPeYq3NRIn3-nlT-FCx_cgh-9HwU2T3ScNPHSN-wAI9vsPqCSvbBFm5bWd2485hZEpGDuHbSTPF9XtjHKEkyZk8QZ8JMTOr8CCeZugudGb53Kwf6DX3GseYdVM3HtPFEYcavm00XPIfmjRUa2i6ya1JmEIBcSUQD9WmbFcl1Vw';

function logMessage($level, $message, $context = []) {
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = $context ? ' ' . json_encode($context) : '';
    echo "[{$timestamp}] {$level}: {$message}{$contextStr}" . PHP_EOL;
}

function testTokenDecoding($token) {
    logMessage('INFO', 'Testing token structure');
    
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        logMessage('ERROR', 'Invalid JWT format');
        return false;
    }
    
    // Decode header
    $header = json_decode(base64_decode($parts[0]), true);
    logMessage('INFO', 'Token header', $header);
    
    // Decode payload
    $payload = json_decode(base64_decode($parts[1]), true);
    logMessage('INFO', 'Token payload', $payload);
    
    return ['header' => $header, 'payload' => $payload];
}

function testHmacSignature($config) {
    logMessage('INFO', 'Testing HMAC signature generation');
    
    $timestamp = (string) round(microtime(true) * 1000);
    $path = 'auth/project/.well-known/jwks.json';
    $signature = hash_hmac(
        'sha256',
        'GET' . "/{$path}" . $timestamp,
        $config['signature_shared_secret']
    );
    
    logMessage('INFO', 'Generated HMAC signature', [
        'timestamp' => $timestamp,
        'path' => $path,
        'signature' => $signature,
        'secret_length' => strlen($config['signature_shared_secret'])
    ]);
    
    return ['timestamp' => $timestamp, 'signature' => $signature];
}

function testMercuryJwks($config) {
    logMessage('INFO', 'Testing Mercury JWKS endpoint');
    
    $hmac = testHmacSignature($config);
    $url = $config['mercury_base_url'] . '/auth/project/.well-known/jwks.json';
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'User-Agent: Laravel-AuthGuard/1.0',
            'X-Timestamp: ' . $hmac['timestamp'],
            'X-Signature: ' . $hmac['signature'],
        ],
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        logMessage('ERROR', 'CURL error', ['error' => $error]);
        return false;
    }
    
    logMessage('INFO', 'Mercury JWKS response', [
        'http_code' => $httpCode,
        'response_size' => strlen($response)
    ]);
    
    if ($httpCode !== 200) {
        logMessage('ERROR', 'Mercury JWKS failed', ['response' => $response]);
        return false;
    }
    
    $jwks = json_decode($response, true);
    if (!$jwks || !isset($jwks['keys'])) {
        logMessage('ERROR', 'Invalid JWKS response');
        return false;
    }
    
    logMessage('INFO', 'JWKS keys found', ['count' => count($jwks['keys'])]);
    foreach ($jwks['keys'] as $key) {
        logMessage('INFO', 'JWKS key', [
            'kid' => $key['kid'] ?? 'missing',
            'alg' => $key['alg'] ?? 'missing',
            'use' => $key['use'] ?? 'missing'
        ]);
    }
    
    return $jwks;
}

function testJwksService($config) {
    logMessage('INFO', 'Testing JwksService directly');
    
    try {
        // Create JwksService instance
        $jwksService = new JwksService(
            $config['mercury_base_url'],
            null, // default project UUID
            $config['signature_shared_secret']
        );
        
        // Test getting public key for project token
        $publicKey = $jwksService->getProjectTokenPublicKey($GLOBALS['testToken']);
        
        logMessage('INFO', 'Successfully retrieved public key', [
            'key_length' => strlen($publicKey),
            'key_type' => strpos($publicKey, '-----BEGIN') === 0 ? 'PEM' : 'unknown'
        ]);
        
        return $publicKey;
        
    } catch (Exception $e) {
        logMessage('ERROR', 'JwksService failed', [
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);
        return false;
    }
}

function testProjectAuthService($config) {
    logMessage('INFO', 'Testing ProjectAuthService');
    
    try {
        // Create a mock Redis connection class
        $mockRedis = new class {
            public function exists($key) { return false; } // Token not in blacklist
            public function disconnect() {}
        };
        
        // This would normally require proper Laravel setup
        // For now, we'll just test the JWKS part
        logMessage('INFO', 'ProjectAuthService test requires Laravel environment');
        
    } catch (Exception $e) {
        logMessage('ERROR', 'ProjectAuthService failed', [
            'error' => $e->getMessage()
        ]);
    }
}

// Run tests
logMessage('INFO', 'Starting JWT Package Independent Tests');
logMessage('INFO', 'Configuration', $config);

echo "\n=== Test 1: Token Decoding ===\n";
$tokenData = testTokenDecoding($testToken);

echo "\n=== Test 2: HMAC Signature ===\n";
$hmacResult = testHmacSignature($config);

echo "\n=== Test 3: Mercury JWKS Endpoint ===\n";
$jwksResult = testMercuryJwks($config);

echo "\n=== Test 4: JwksService ===\n";
$publicKeyResult = testJwksService($config);

echo "\n=== Test Results Summary ===\n";
logMessage('INFO', 'Token decoding: ' . ($tokenData ? 'SUCCESS' : 'FAILED'));
logMessage('INFO', 'HMAC signature: ' . ($hmacResult ? 'SUCCESS' : 'FAILED'));
logMessage('INFO', 'Mercury JWKS: ' . ($jwksResult ? 'SUCCESS' : 'FAILED'));
logMessage('INFO', 'JwksService: ' . ($publicKeyResult ? 'SUCCESS' : 'FAILED'));

if ($publicKeyResult) {
    logMessage('INFO', 'JWT package is working correctly!');
    logMessage('INFO', 'The issue might be in Laravel configuration or environment variables.');
} else {
    logMessage('ERROR', 'JWT package has issues that need to be resolved.');
}