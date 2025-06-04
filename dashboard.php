<?php
require_once 'includes/conexion.php';
require_once 'includes/user.php';

$user = new User();
$headers = getallheaders();

// Obtener token de cookie si existe
$token = $_COOKIE['token'] ?? null;

// Si no hay token en cookie, buscar en header Authorization (caso fetch)
if (!$token && isset($headers['Authorization']) && preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
    $token = $matches[1];
}

function isApiRequest() {
    // Detecta si la petición espera JSON (fetch o AJAX)
    $headers = getallheaders();
    if (isset($headers['Accept']) && strpos($headers['Accept'], 'application/json') !== false) {
        return true;
    }
    // O puede basarse en la cabecera Authorization también:
    if (isset($headers['Authorization'])) {
        return true;
    }
    return false;
}

if (!$token) {
    if (isApiRequest()) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado.']);
    } else {
        http_response_code(401);
        echo "Acceso no autorizado. Por favor, inicia sesión.";
    }
    exit;
}

$payload = $user->validateToken($token);
if (!$payload) {
    if (isApiRequest()) {
        http_response_code(401);
        echo json_encode(['error' => 'Token inválido o expirado']);
    } else {
        http_response_code(401);
        echo "Token inválido o expirado. Por favor, inicia sesión de nuevo.";
    }
    exit;
}

// Si llegamos acá, token válido. Si es fetch solo responder ok JSON:
if (isApiRequest()) {
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'username' => $payload->username ?? 'Usuario']);
    exit;
}

// Si no es fetch, mostrar dashboard HTML completo:
$username = $payload->username ?? 'Usuario';
$email = $payload->email ?? 'Sin email';
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="css/login.css"> 
</head>
<body>
    <div class="login-container">
        <h2>¡Bienvenido, <?= htmlspecialchars($username) ?>!</h2>
        <p><strong>Correo:</strong> <?= htmlspecialchars($email) ?></p>
        <p class="token-display"><strong>Token:</strong> <?= htmlspecialchars($token) ?></p>

        <p>Estás viendo contenido protegido.</p>
        
        <button id="logoutBtn">Cerrar sesión</button>
    </div>

    <script src="js/dashboard.js"></script>
</body>
</html>
