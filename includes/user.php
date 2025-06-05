<?php
require_once 'conexion.php';
require_once 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class User {
    private $con;
    private $jwt_algo = 'HS256';

    public function __construct() {
        $this->con = conectar();
    }

    // Generar una clave privada aleatoria segura para cada usuario
    private function generatePrivateKey() {
        return bin2hex(random_bytes(32)); // 64 caracteres hex (256 bits)
    }

    public function register($username, $email, $password) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $jwt_secret = $this->generatePrivateKey();

        $stmt = $this->con->prepare("INSERT INTO usuarios (username, email, password, jwt_secret) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $username, $email, $password_hash, $jwt_secret);

        if ($stmt->execute()) {
            return true;
        }
        return false;
    }

    public function login($username, $password) {
        // Traer id, email, password, jwt_secret
        $stmt = $this->con->prepare("SELECT id, email, password, jwt_secret FROM usuarios WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($id, $email, $password_hash, $jwt_secret);

        if ($stmt->fetch()) {
            if (password_verify($password, $password_hash)) {
                // Preparar los datos sensibles cifrados en el campo 'data'
                $data = json_encode([
                    'username' => $username,
                    'email' => $email,
                ]);

                // Payload: sub y data cifrado en base64
                $payload = [
                    'iss' => 'tu_dominio.com',
                    'iat' => time(),
                    'exp' => time() + 3600,
                    'sub' => $id,
                    'data' => base64_encode(openssl_encrypt($data, 'aes-256-cbc', hex2bin($jwt_secret), OPENSSL_RAW_DATA, substr(hex2bin($jwt_secret), 0, 16)))
                ];

                // Firmar con la jwt_secret única del usuario
                $jwt = JWT::encode($payload, hex2bin($jwt_secret), $this->jwt_algo);

                return [
                    'token' => $jwt,
                    'user' => [
                        'id' => $id,
                        'username' => $username,
                        'email' => $email,
                    ]
                ];
            }
        }
        return false;
    }

    private function getPayloadFromToken($jwt) {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) return null;
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')));
        return $payload;
    }

    public function validateToken($jwt) {
        try {
            // Extraer payload sin verificar para obtener userId
            $payload = $this->getPayloadFromToken($jwt);
            if (!$payload || !isset($payload->sub)) return false;

            $userId = $payload->sub;

            // Traer la jwt_secret del usuario para verificar token
            $stmt = $this->con->prepare("SELECT jwt_secret FROM usuarios WHERE id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $stmt->bind_result($jwt_secret);
            if (!$stmt->fetch()) return false;

            // Verificar token con la jwt_secret
            $decoded = JWT::decode($jwt, new Key(hex2bin($jwt_secret), $this->jwt_algo));

            // Descifrar el campo data
            $encrypted_data = base64_decode($decoded->data);
            $decrypted_json = openssl_decrypt($encrypted_data, 'aes-256-cbc', hex2bin($jwt_secret), OPENSSL_RAW_DATA, substr(hex2bin($jwt_secret), 0, 16));
            $decoded->data = json_decode($decrypted_json);

            return $decoded;

        } catch (Exception $e) {
            return false;
        }
    }

    public function __destruct() {
        $this->con->close();
    }
}
