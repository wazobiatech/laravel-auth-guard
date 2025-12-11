<?php
/**
 * Standalone JWT Package Test Runner
 * 
 * This script provides an isolated testing environment for the JWT package
 * without Laravel dependencies.
 */

require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Simple configuration class
class TestConfig {
    public static function get($key, $default = null) {
        $env = [
            'mercury.base_url' => $_ENV['MERCURY_BASE_URL'] ?? 'https://mercury.tiadara.com',
            'signature.shared_secret' => $_ENV['SIGNATURE_SHARED_SECRET'] ?? 'AAAAB3NzaC1yc2EAAAADAQABAAACAQD3GObqRywP1xuNkk9SltJ',
            'service_id' => $_ENV['SERVICE_ID'] ?? '4d3ab1f6-cd27-457f-b727-bcbb37f6b58f',
            'jwt.algorithm' => $_ENV['JWT_ALGORITHM'] ?? 'RS512',
            'auth.cache.ttl' => $_ENV['AUTH_CACHE_TTL'] ?? 3600,
            'auth.logging.enabled' => $_ENV['AUTH_LOGGING_ENABLED'] ?? 'true',
            'auth.jwt.header' => $_ENV['AUTH_JWT_HEADER'] ?? 'Authorization',
            'auth.project.token.header' => $_ENV['AUTH_PROJECT_TOKEN_HEADER'] ?? 'X-Project-Token',
            'redis.auth.db' => $_ENV['REDIS_AUTH_DB'] ?? '0',
        ];
        
        return $env[$key] ?? $default;
    }
}

// Simple logger class
class TestLogger {
    public static function log($level, $message, $context = []) {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = $context ? ' ' . json_encode($context, JSON_PRETTY_PRINT) : '';
        echo "[{$timestamp}] {$level}: {$message}{$contextStr}" . PHP_EOL;
    }
    
    public static function info($message, $context = []) {
        self::log('INFO', $message, $context);
    }
    
    public static function error($message, $context = []) {
        self::log('ERROR', $message, $context);
    }
    
    public static function success($message, $context = []) {
        self::log('SUCCESS', $message, $context);
    }
}

// Simple HTTP client
class TestHttpClient {
    public static function get($url, $headers = []) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => array_map(fn($k, $v) => "$k: $v", array_keys($headers), $headers),
            CURLOPT_USERAGENT => 'JWT-Package-Test/1.0',
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception("CURL error: $error");
        }
        
        return [
            'status' => $httpCode,
            'body' => $response,
            'success' => $httpCode >= 200 && $httpCode < 300
        ];
    }
}

// Simplified JWKS Service for testing
class TestJwksService {
    private $mercuryBaseUrl;
    private $sharedSecret;
    
    public function __construct($mercuryBaseUrl, $sharedSecret) {
        $this->mercuryBaseUrl = $mercuryBaseUrl;
        $this->sharedSecret = $sharedSecret;
    }
    
    public function getProjectTokenPublicKey($token) {
        TestLogger::info('Starting JWKS key retrieval');
        
        // Parse token header
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT format');
        }
        
        $header = json_decode(base64_decode($parts[0]), true);
        if (!$header || !isset($header['kid'])) {
            throw new Exception('Missing key ID in token header');
        }
        
        $kid = $header['kid'];
        TestLogger::info('Looking for key ID', ['kid' => $kid]);
        
        // Fetch JWKS
        $jwks = $this->fetchProjectJWKS();
        
        // Find matching key
        foreach ($jwks['keys'] as $key) {
            if ($key['kid'] === $kid) {
                TestLogger::success('Found matching key', ['kid' => $kid]);
                return $this->jwkToPem($key);
            }
        }
        
        throw new Exception("Key $kid not found in JWKS");
    }
    
    private function fetchProjectJWKS() {
        $path = 'auth/project/.well-known/jwks.json';
        $url = $this->mercuryBaseUrl . '/' . $path;
        
        // Generate HMAC signature
        $timestamp = (string) round(microtime(true) * 1000);
        $signature = hash_hmac('sha256', 'GET' . '/' . $path . $timestamp, $this->sharedSecret);
        
        TestLogger::info('Fetching JWKS', [
            'url' => $url,
            'timestamp' => $timestamp,
            'signature' => substr($signature, 0, 16) . '...'
        ]);
        
        $headers = [
            'Accept' => 'application/json',
            'X-Timestamp' => $timestamp,
            'X-Signature' => $signature,
        ];
        
        $response = TestHttpClient::get($url, $headers);
        
        if (!$response['success']) {
            throw new Exception("JWKS request failed: HTTP {$response['status']} - {$response['body']}");
        }
        
        $jwks = json_decode($response['body'], true);
        if (!$jwks || !isset($jwks['keys'])) {
            throw new Exception('Invalid JWKS response');
        }
        
        TestLogger::success('JWKS fetched successfully', [
            'key_count' => count($jwks['keys'])
        ]);
        
        return $jwks;
    }
    
    private function jwkToPem($jwk) {
        if ($jwk['kty'] !== 'RSA') {
            throw new Exception('Unsupported key type: ' . $jwk['kty']);
        }
        
        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);
        
        $rsa = \phpseclib3\Crypt\RSA::loadPublicKey([
            'n' => new \phpseclib3\Math\BigInteger($n, 256),
            'e' => new \phpseclib3\Math\BigInteger($e, 256),
        ]);
        
        return $rsa->toString('PKCS8');
    }
    
    private function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}

// Test runner
class JwtPackageTestRunner {
    private $token;
    private $config;
    
    public function __construct($token) {
        $this->token = $token;
        $this->config = [
            'mercury_base_url' => TestConfig::get('mercury.base_url'),
            'shared_secret' => TestConfig::get('signature.shared_secret'),
            'service_id' => TestConfig::get('service_id'),
            'jwt_algorithm' => TestConfig::get('jwt.algorithm'),
        ];
    }
    
    public function runAllTests() {
        TestLogger::info('Starting JWT Package Tests');
        TestLogger::info('Configuration', $this->config);
        
        $results = [];
        
        echo "\n=== Test 1: Token Structure ===\n";
        $results['token_structure'] = $this->testTokenStructure();
        
        echo "\n=== Test 2: JWKS Connectivity ===\n";
        $results['jwks_connectivity'] = $this->testJwksConnectivity();
        
        echo "\n=== Test 3: Key Retrieval ===\n";
        $results['key_retrieval'] = $this->testKeyRetrieval();
        
        echo "\n=== Test 4: Token Validation ===\n";
        $results['token_validation'] = $this->testTokenValidation();
        
        echo "\n=== Test Results Summary ===\n";
        $this->printSummary($results);
        
        return $results;
    }
    
    private function testTokenStructure() {
        try {
            $parts = explode('.', $this->token);
            if (count($parts) !== 3) {
                throw new Exception('Invalid JWT format');
            }
            
            $header = json_decode(base64_decode($parts[0]), true);
            $payload = json_decode(base64_decode($parts[1]), true);
            
            TestLogger::success('Token structure valid');
            TestLogger::info('Header', $header);
            TestLogger::info('Payload summary', [
                'project_uuid' => $payload['project_uuid'] ?? 'missing',
                'enabled_services' => $payload['enabled_services'] ?? 'missing',
                'token_id' => $payload['token_id'] ?? 'missing',
                'exp' => date('Y-m-d H:i:s', $payload['exp'] ?? 0),
                'iss' => $payload['iss'] ?? 'missing'
            ]);
            
            return true;
        } catch (Exception $e) {
            TestLogger::error('Token structure test failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
    
    private function testJwksConnectivity() {
        try {
            $jwksService = new TestJwksService(
                $this->config['mercury_base_url'],
                $this->config['shared_secret']
            );
            
            $jwks = $jwksService->fetchProjectJWKS();
            TestLogger::success('JWKS connectivity test passed');
            return true;
        } catch (Exception $e) {
            TestLogger::error('JWKS connectivity test failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
    
    private function testKeyRetrieval() {
        try {
            $jwksService = new TestJwksService(
                $this->config['mercury_base_url'],
                $this->config['shared_secret']
            );
            
            $publicKey = $jwksService->getProjectTokenPublicKey($this->token);
            TestLogger::success('Key retrieval test passed', [
                'key_length' => strlen($publicKey),
                'key_type' => strpos($publicKey, '-----BEGIN') === 0 ? 'PEM' : 'unknown'
            ]);
            return true;
        } catch (Exception $e) {
            TestLogger::error('Key retrieval test failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
    
    private function testTokenValidation() {
        try {
            $jwksService = new TestJwksService(
                $this->config['mercury_base_url'],
                $this->config['shared_secret']
            );
            
            $publicKey = $jwksService->getProjectTokenPublicKey($this->token);
            
            // Validate JWT signature
            JWT::$leeway = 60; // 60 seconds leeway for clock skew
            $decoded = JWT::decode($this->token, new Key($publicKey, $this->config['jwt_algorithm']));
            
            TestLogger::success('Token validation test passed');
            return true;
        } catch (Exception $e) {
            TestLogger::error('Token validation test failed', ['error' => $e->getMessage()]);
            return false;
        }
    }
    
    private function printSummary($results) {
        $passed = array_sum($results);
        $total = count($results);
        
        TestLogger::info("Tests completed: $passed/$total passed");
        
        foreach ($results as $test => $result) {
            $status = $result ? '✅ PASS' : '❌ FAIL';
            TestLogger::info("$test: $status");
        }
        
        if ($passed === $total) {
            TestLogger::success('All tests passed! JWT package is working correctly.');
        } else {
            TestLogger::error('Some tests failed. Check the logs above for details.');
        }
    }
}

// Main execution
if (php_sapi_name() === 'cli') {
    $testToken = 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVkZ2ZDSWtITGpiR2tJWHktc1BzRy14NDFJdXhVRWlLZlppdVFBTlNiMGsifQ.eyJwcm9qZWN0X3V1aWQiOiI1YzFlMzg2Yy0wOGMwLTRhMGEtODBhZC0xZjFiMzBlYTIzMWYiLCJzZWNyZXRfdmVyc2lvbiI6NSwiZW5hYmxlZF9zZXJ2aWNlcyI6WyI0ZDNhYjFmNi1jZDI3LTQ1N2YtYjcyNy1iY2JiMzdmNmI1OGYiXSwidG9rZW5faWQiOiIzZGFiOWZjMC02NmYxLTQyM2ItOWVhNy05NTg0MjJlOTc0Y2IiLCJ0eXBlIjoicHJvamVjdCIsImlhdCI6MTc2NTQzODIyMCwibmJmIjoxNzY1NDM4MjIwLCJleHAiOjE3NjU0NDE4MjAsImF1ZCI6IioiLCJpc3MiOiJodHRwczovL21lcmN1cnkudGlhZGFyYS5jb20ifQ.T-8VFb5zZH0ESZjw_2PjGw77hezu6EOWnPEvqW50MGS5QKHiC_OlnNKuYSi89AtRWHleiL0ly5oiU8ekIoY4nhjGKC-p4ADT3Ila09K29O-uR4Pnrz56_pJkSQBr0BhMhYnPEOBJLnVtAUXvtnVclqnU2OZSRCcxuByJTmCk95BjiPeYq3NRIn3-nlT-FCx_cgh-9HwU2T3ScNPHSN-wAI9vsPqCSvbBFm5bWd2485hZEpGDuHbSTPF9XtjHKEkyZk8QZ8JMTOr8CCeZugudGb53Kwf6DX3GseYdVM3HtPFEYcavm00XPIfmjRUa2i6ya1JmEIBcSUQD9WmbFcl1Vw';
    
    $testRunner = new JwtPackageTestRunner($testToken);
    $results = $testRunner->runAllTests();
    
    exit($results['token_validation'] && $results['key_retrieval'] ? 0 : 1);
}