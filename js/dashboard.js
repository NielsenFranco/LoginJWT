document.addEventListener("DOMContentLoaded", () => {
    const token = localStorage.getItem('token');

    if (!token) {
        alert("No has iniciado sesión.");
        window.location.href = 'login.php';
        return;
    }

    // Verificar sesión activa enviando token a esta misma página
    fetch(window.location.href, {
        headers: {
            'Authorization': 'Bearer ' + token
        }
    }).then(res => {
        if (res.status === 401) {
            alert("Sesión expirada o inválida.");
            localStorage.removeItem('token');
            window.location.href = 'login.php';
        }
    });

    // Botón de logout
    document.getElementById('logoutBtn')?.addEventListener('click', () => {
        localStorage.removeItem('token');
        window.location.href = 'login.php';
    });
});
