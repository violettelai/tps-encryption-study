// window.onload = function() {
//   alert("This is a message from script.js!");
// };

document.addEventListener("DOMContentLoaded", function() {
  const loginForm = document.getElementById("loginForm");
  // const registerForm = document.getElementById("registerForm");

  if (loginForm) {
      loginForm.addEventListener("submit", function(event) {
          event.preventDefault();

          const formData = new FormData(loginForm);
          const data = {};
          formData.forEach((value, key) => {
              data[key] = value;
          });

          fetch('/login', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json',
              },
              body: JSON.stringify(data),
          })
          .then(response => response.text())
          .then(result => {
              document.getElementById('loginResponse').textContent = result;
          })
          .catch(error => {
              console.error('Error:', error);
          });
      });
  }

  if (registerForm) {
      registerForm.addEventListener("submit", function(event) {
          event.preventDefault(); // Prevent the form from submitting the traditional way

          const formData = new FormData(registerForm);
          const data = {};
          formData.forEach((value, key) => {
              data[key] = value;
          });

          fetch('/register', {
              method: 'POST',
              headers: {
                  'Content-Type': 'application/json',
              },
              body: JSON.stringify(data),
          })
          .then(response => response.text())
          .then(result => {
              document.getElementById('registerResponse').textContent = result; // Display the response
          })
          .catch(error => {
              console.error('Error:', error);
          });
      });
  }
});
