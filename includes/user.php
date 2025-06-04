<?php
require_once 'conexion.php'; // Tu conexión actual (puedes adaptar si usas mysqli)
require_once 'vendor/autoload.php'; // Para cargar JWT (si usas Composer)

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class User {
    private $con;
    private $jwt_key = 'PepeParaguayo'; // Cambia por una clave segura
    private $jwt_algo = 'HS256';

    public function __construct() {
        $this->con = conectar(); // Adaptar según tu función de conexión, ideal usar PDO
    }

    public function register($username, $email, $password) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->con->prepare("INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password_hash);
        if ($stmt->execute()) {
            return true;
        }
        return false;
    }

    public function login($username, $password) {
        $stmt = $this->con->prepare("SELECT id, email, password FROM usuarios WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($id, $email, $password_hash);
        if ($stmt->fetch()) {
            if (password_verify($password, $password_hash)) {
                // Generar token JWT con email incluido
                $payload = [
                    'iss' => 'tu_dominio.com',
                    'iat' => time(),
                    'exp' => time() + 3600, // 1 hora
                    'sub' => $id,
                    'username' => $username,
                    'email' => $email   // <-- agregado email
                ];
                $jwt = JWT::encode($payload, $this->jwt_key, $this->jwt_algo);
                return $jwt;
            }
        }
        return false;
    }

    public function validateToken($jwt) {
        try {
            $decoded = JWT::decode($jwt, new Key($this->jwt_key, $this->jwt_algo));
            return $decoded;
        } catch (Exception $e) {
            return false;
        }
    }

    public function __destruct() {
        $this->con->close();
    }
}
