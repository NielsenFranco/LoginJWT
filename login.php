<?php 
require_once 'includes/conexion.php';
require_once 'includes/user.php';
session_start();

// Procesar login vía JSON fetch (AJAX)
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($contentType, 'application/json') !== false) {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);

    if (!isset($input['username']) || !isset($input['password'])) {
        echo json_encode(['success' => false, 'message' => 'Datos incompletos.']);
        exit;
    }

    $user = new User();
    $token = $user->login($input['username'], $input['password']);

    if ($token) {
        $_SESSION['jwt'] = $token;

        // ✅ Guardar token como cookie (1 hora)
        setcookie('token', $token, time() + 3600, "/");

        // ✅ Enviar token en el JSON
        echo json_encode([
            'success' => true,
            'message' => 'Inicio de sesión exitoso',
            'token' => $token
        ]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Usuario o contraseña incorrectos.']);
    }
    exit;  // Muy importante para no mostrar el HTML luego
}

// Procesar registro (form POST normal)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_SERVER['HTTP_CONTENT_TYPE'])) {
    // Es un form POST normal (no JSON fetch), asumimos registro
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $error = "Por favor complete todos los campos.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "El correo electrónico no es válido.";
    } elseif ($password !== $confirm_password) {
        $error = "Las contraseñas no coinciden.";
    } else {
        $con = conectar();
        if ($con) {
            // Verificar si usuario o email existen
            $stmt = $con->prepare("SELECT id FROM usuarios WHERE username = ? OR email = ?");
            $stmt->bind_param("ss", $username, $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $error = "El usuario o correo ya están registrados.";
                $stmt->close();
                desconectar($con);
            } else {
                $stmt->close();

                $passwordHasheada = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $con->prepare("INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $username, $email, $passwordHasheada);

                if ($stmt->execute()) {
                    $success = "Usuario registrado con éxito. Por favor, inicie sesión.";
                } else {
                    $error = "Error al registrar usuario: " . $stmt->error;
                }
                $stmt->close();
                desconectar($con);
            }
        } else {
            $error = "No se pudo conectar a la base de datos.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login y Registro</title>
  <link rel="stylesheet" href="css/login.css" />
</head>
<body>

<div class="login-container">
  <div class="tabs">
    <button id="tab-register" class="tab active">Crear Usuario</button>
    <button id="tab-login" class="tab">Iniciar Sesión</button>
  </div>

  <!-- Mostrar mensajes -->
  <?php if (isset($error)): ?>
    <div class="message error"><?= htmlspecialchars($error) ?></div>
  <?php elseif (isset($success)): ?>
    <div class="message success"><?= htmlspecialchars($success) ?></div>
  <?php endif; ?>

  <!-- Registro -->
  <form id="register-form" class="form active" action="login.php" method="POST">
    <input type="text" name="username" placeholder="Usuario" required />
    <input type="email" name="email" placeholder="Correo" required />

    <div class="password-wrapper">
      <input type="password" name="password" placeholder="Contraseña" required />
      <img src="img/ojo_cerrado.png" class="toggle-password" />
    </div>

    <div class="password-wrapper">
      <input type="password" name="confirm_password" placeholder="Repita la contraseña" required />
      <img src="img/ojo_cerrado.png" class="toggle-password" />
    </div>

    <button type="submit">Crear Usuario</button>
  </form>

  <!-- Login -->
  <form id="login-form" class="form">
    <input type="text" id="username" name="username" placeholder="Usuario" required />

    <div class="password-wrapper">
      <input type="password" id="password" name="password" placeholder="Contraseña" required />
      <img src="img/ojo_cerrado.png" id="togglePassword" class="toggle-password" />
    </div>

    <button type="submit">Ingresar</button>
  </form>

  <div class="message" id="message"></div>
</div>

<script src="js/login.js"></script>
</body>
</html>
