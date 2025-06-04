// Función para limpiar mensajes
function clearMessage() {
  const messageBox = document.getElementById('message');
  messageBox.textContent = '';
  messageBox.style.color = '';
}

// Pestañas
document.getElementById('tab-login').addEventListener('click', () => {
  document.getElementById('login-form').classList.add('active');
  document.getElementById('register-form').classList.remove('active');
  document.getElementById('tab-login').classList.add('active');
  document.getElementById('tab-register').classList.remove('active');
  clearMessage();
});

document.getElementById('tab-register').addEventListener('click', () => {
  document.getElementById('register-form').classList.add('active');
  document.getElementById('login-form').classList.remove('active');
  document.getElementById('tab-register').classList.add('active');
  document.getElementById('tab-login').classList.remove('active');
  clearMessage();
});

// Mostrar/ocultar contraseña
document.querySelectorAll('.toggle-password').forEach(icon => {
  icon.addEventListener('click', () => {
    const input = icon.previousElementSibling;
    if (input.type === 'password') {
      input.type = 'text';
      icon.src = 'img/ojo_abierto.png';
    } else {
      input.type = 'password';
      icon.src = 'img/ojo_cerrado.png';
    }
  });
});

// Envío de formulario de login con fetch (POST JSON)
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  const messageBox = document.getElementById('message');

  try {
    const res = await fetch('login.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) throw new Error('Error en la respuesta del servidor');

    const data = await res.json();
    messageBox.textContent = data.message || '';

    if (data.success) {
      messageBox.style.color = 'green';

      // Guardar token manualmente (opcional, ya se guarda como cookie desde PHP)
      // document.cookie = `token=${data.token}; path=/; max-age=3600; secure; samesite=strict`;
      localStorage.setItem('token', data.token);
      
      setTimeout(() => {
        window.location.href = 'dashboard.php';
      }, 1000);
    } else {
      messageBox.style.color = 'red';
    }
  } catch (error) {
    messageBox.textContent = 'Error al conectar con el servidor.';
    messageBox.style.color = 'red';
  }
});

// Validación de registro (coincidencia de contraseñas)
document.getElementById('register-form').addEventListener('submit', function (e) {
  const password = this.querySelector('input[name="password"]').value;
  const confirmPassword = this.querySelector('input[name="confirm_password"]').value;
  const messageBox = document.getElementById('message');

  if (password !== confirmPassword) {
    e.preventDefault();
    messageBox.textContent = 'Las contraseñas no coinciden.';
    messageBox.style.color = 'red';
  } else {
    messageBox.textContent = '';
    messageBox.style.color = '';
  }
});
